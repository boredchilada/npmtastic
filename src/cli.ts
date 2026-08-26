// SPDX-License-Identifier: AGPL-3.0-or-later
import { parseArgs } from "node:util";
import { existsSync, writeFileSync, appendFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { discoverOne, discoverTree } from "./discovery.js";
import { auditProject } from "./analysis.js";
import { RegistryClient } from "./registry.js";
import { VulnClient } from "./vulns.js";
import { renderAuditJson } from "./render/json.js";
import { renderSarif } from "./render/sarif.js";
import { renderTerminal, type View } from "./render/terminal.js";
import { renderReport } from "./render/report.js";
import { renderMarkdown } from "./render/markdown.js";
import { renderAgent, renderAgentError, renderNdjson } from "./render/agent.js";
import { renderCycloneDx } from "./render/cyclonedx.js";
import { setQuiet, warn, error, setLogFile, info } from "./logging.js";
import { SemverDrift, makeProjectAudit, type DepAudit, type ProjectAudit } from "./models.js";
import { updateProject } from "./update.js";
import { bootstrapProject } from "./bootstrap.js";
import { backupManifest } from "./backup.js";
import { readText } from "./fsutil.js";
import type { UpdateResult } from "./models.js";
import * as baseline from "./baseline.js";
import { loadConfig, emptyConfig, resolve as resolveOpt, ConfigError, type Config } from "./config.js";
import { isRemote, acquire } from "./sources.js";

import { buildStats, renderStats } from "./stats.js";

export const EXIT_OK = 0;
export const EXIT_ERROR = 1;
export const EXIT_ROLLBACK = 2;
export const EXIT_GATE = 3;

const VERSION = "0.1.1"; // keep in sync with package.json

const DRIFT_RANK: Record<string, number> = {
  [SemverDrift.NONE]: 0,
  [SemverDrift.PRERELEASE]: 1,
  [SemverDrift.PATCH]: 2,
  [SemverDrift.MINOR]: 3,
  [SemverDrift.MAJOR]: 4,
};

export interface GateOptions {
  failOnDrift?: string | undefined;
  failOnVuln?: string | undefined;
  failOnAge?: number | undefined;
  failOnDaysBehind?: number | undefined;
  failOnDeprecated?: boolean | undefined;
  failOnLicense?: readonly string[] | undefined;
  allowLicense?: readonly string[] | undefined;
  failOnIntegrity?: boolean | undefined;
  strictVulnGate?: boolean | undefined;

  gateScope?: "direct" | "all" | undefined;
}

const SPDX_OPERATORS = new Set(["AND", "OR", "WITH"]);

function licenseIds(expression: string): Set<string> {
  const out = new Set<string>();
  for (const token of expression.match(/[A-Za-z0-9][A-Za-z0-9.+-]*/g) ?? []) {
    if (!SPDX_OPERATORS.has(token.toUpperCase())) out.add(token.toUpperCase());
  }
  return out;
}

function spdxAllowed(expression: string | null | undefined, allowed: ReadonlySet<string>): boolean {
  if (!expression || expression.trim() === "") return false;
  const tokens = expression.match(/\(|\)|[A-Za-z0-9][A-Za-z0-9.+-]*/g);
  if (!tokens || tokens.length === 0) return false;
  let position = 0;

  const peek = (): string | undefined => tokens[position];

  const parseTerm = (): boolean | null => {
    const token = peek();
    if (token === undefined) return null;
    if (token === "(") {
      position += 1;
      const inner = parseOr();
      if (inner === null || peek() !== ")") return null;
      position += 1;
      return inner;
    }
    if (token === ")" || SPDX_OPERATORS.has(token.toUpperCase())) return null;
    position += 1;
    const base = token.toUpperCase();
    if ((peek() ?? "").toUpperCase() === "WITH") {
      position += 1;
      const exception = peek();
      if (exception === undefined) return null;
      position += 1;
      return allowed.has(`${base} WITH ${exception.toUpperCase()}`) || allowed.has(base);
    }
    return allowed.has(base);
  };

  const parseAnd = (): boolean | null => {
    let value = parseTerm();
    while (value !== null && (peek() ?? "").toUpperCase() === "AND") {
      position += 1;
      const right = parseTerm();
      if (right === null) return null;
      value = value && right;
    }
    return value;
  };

  const parseOr = (): boolean | null => {
    let value = parseAnd();
    while (value !== null && (peek() ?? "").toUpperCase() === "OR") {
      position += 1;
      const right = parseAnd();
      if (right === null) return null;
      value = value || right;
    }
    return value;
  };

  const result = parseOr();
  if (result === null || position !== tokens.length) return false;
  return result;
}

function gatedDeps(audits: readonly ProjectAudit[], scope: "direct" | "all"): DepAudit[] {
  const out: DepAudit[] = [];
  for (const project of audits) {
    for (const dep of project.deps) {
      if (scope === "direct" && !dep.dep.direct) continue;
      out.push(dep);
    }
  }
  return out;
}

export function gatesTripped(audits: readonly ProjectAudit[], gates: GateOptions): boolean {
  const scope = gates.gateScope === "direct" ? "direct" : "all";
  if (gates.failOnDrift) {
    const threshold = DRIFT_RANK[gates.failOnDrift];
    if (threshold !== undefined) {
      for (const d of gatedDeps(audits, scope)) {
        const r = DRIFT_RANK[d.drift];
        if (r !== undefined && r >= threshold) return true;
      }
    }
  }
  if (gates.failOnVuln) {
    const unreachablePkgs = [
      ...new Set(
        audits.flatMap((a) => a.deps.filter((d) => d.vulnUnreachable).map((d) => d.dep.name)),
      ),
    ].sort();
    const unreachable =
      unreachablePkgs.length > 0
        ? unreachablePkgs.length
        : audits.reduce((n, p) => n + p.vulnUnreachable, 0);
    if (unreachable > 0) {
      if (gates.strictVulnGate) {
        const shown =
          unreachablePkgs.slice(0, 5).join(", ") + (unreachablePkgs.length > 5 ? "..." : "");
        warn(
          `--strict-vuln-gate: ${unreachable} package(s) vuln_unreachable -> gate trips` +
            (shown ? `: ${shown}` : ""),
        );
        return true;
      }
      warn(
        `vuln_unreachable for ${unreachable} package(s); not tripping gate (pass --strict-vuln-gate to flip)`,
      );
    }
    const total = audits.reduce((n, p) => n + p.vulnCount, 0);
    const need = gates.failOnVuln === "any" ? 1 : Number.parseInt(gates.failOnVuln, 10);
    if (!Number.isNaN(need) && total >= need) return true;
  }
  if (gates.failOnAge !== undefined) {
    for (const d of gatedDeps(audits, scope)) {
      if (d.latestReleaseAgeDays !== null && d.latestReleaseAgeDays > gates.failOnAge) return true;
    }
  }
  if (gates.failOnDaysBehind !== undefined) {
    for (const d of gatedDeps(audits, scope)) {
      if (d.daysBehind !== null && d.daysBehind !== undefined && d.daysBehind > gates.failOnDaysBehind) return true;
    }
  }
  if (gates.failOnDeprecated && audits.some((p) => p.deprecatedCount > 0)) return true;
  if (gates.failOnLicense && gates.failOnLicense.length > 0) {
    const denied = new Set(gates.failOnLicense.map((id) => id.toUpperCase()));
    for (const dep of gatedDeps(audits, scope)) {
      for (const id of licenseIds(dep.license ?? "")) {
        if (denied.has(id)) return true;
      }
    }
  }
  if (gates.allowLicense && gates.allowLicense.length > 0) {
    const allowed = new Set(gates.allowLicense.map((id) => id.toUpperCase()));
    for (const dep of gatedDeps(audits, scope)) {
      if (!spdxAllowed(dep.license, allowed)) return true;
    }
  }
  if (gates.failOnIntegrity) {
    for (const p of audits) {
      if ((p.integrityFindings ?? []).length > 0 || !p.integrityChecked) return true;
    }
  }

  return false;
}

export interface FilterOptions {
  vulnerableOnly?: boolean | undefined;
  driftMin?: string | undefined;
}

export function filterAudits(audits: readonly ProjectAudit[], filters: FilterOptions): ProjectAudit[] {
  const driftThreshold = filters.driftMin ? DRIFT_RANK[filters.driftMin] : undefined;
  const active = Boolean(filters.vulnerableOnly) || driftThreshold !== undefined;
  const out: ProjectAudit[] = [];
  for (const p of audits) {
    let deps = p.deps;
    if (filters.vulnerableOnly) deps = deps.filter((d) => d.vulnerabilities.length > 0);
    if (driftThreshold !== undefined) deps = deps.filter((d) => {
      const r = DRIFT_RANK[d.drift];
      return r !== undefined && r >= driftThreshold;
    });
    if (active && deps.length === 0) continue;
    out.push(makeProjectAudit({ ...p, deps }));
  }
  return out;
}

function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

function offlineIncompleteMessage(registry: RegistryClient, vuln: VulnClient): string | null {
  const packages = registry.offlineMisses;
  const advisories = vuln.offlineMisses;
  if (packages.length === 0 && advisories.length === 0) return null;
  const parts: string[] = [];
  if (packages.length > 0) {
    const shown = packages.slice(0, 5).join(", ");
    parts.push(
      `${packages.length} package(s) missing registry data (${shown}${packages.length > 5 ? ", ..." : ""})`,
    );
  }
  if (advisories.length > 0) {
    const shown = advisories.slice(0, 5).join(", ");
    parts.push(
      `${advisories.length} advisory lookup(s) missing (${shown}${advisories.length > 5 ? ", ..." : ""})`,
    );
  }
  return (
    "offline audit is incomplete: " +
    parts.join("; ") +
    ". Run once with network access to warm the cache, or drop --offline."
  );
}

function configStartDir(path: string): string {
  try {
    return statSync(path).isDirectory() ? path : dirname(path);
  } catch {
    return path;
  }
}

function csvList(raw: string | undefined): string[] {
  return raw === undefined ? [] : raw.split(",").map((s) => s.trim()).filter(Boolean);
}

function gatesFromCli(
  v: {
    "fail-on-drift"?: string | undefined;
    "fail-on-vuln"?: string | undefined;
    "strict-vuln-gate"?: boolean | undefined;
    "fail-on-age"?: string | undefined;
    "fail-on-days-behind"?: string | undefined;
    "fail-on-deprecated"?: boolean | undefined;
    "fail-on-license"?: string | undefined;
    "allow-license"?: string | undefined;
    "fail-on-integrity"?: boolean | undefined;

    "gate-scope"?: string | undefined;
  },
  policy: Config["policy"],
): GateOptions {
  return {
    failOnDrift: resolveOpt(v["fail-on-drift"], policy.fail_on_drift, undefined),
    failOnVuln: resolveOpt(v["fail-on-vuln"], policy.fail_on_vuln, undefined),
    strictVulnGate: Boolean(v["strict-vuln-gate"]),
    failOnAge: resolveOpt(
      v["fail-on-age"] !== undefined ? Number.parseInt(v["fail-on-age"], 10) : undefined,
      policy.fail_on_age,
      undefined,
    ),
    failOnDaysBehind: resolveOpt(
      v["fail-on-days-behind"] !== undefined ? Number.parseInt(v["fail-on-days-behind"], 10) : undefined,
      policy.fail_on_days_behind,
      undefined,
    ),
    failOnDeprecated: resolveOpt(Boolean(v["fail-on-deprecated"]), policy.fail_on_deprecated, false),
    failOnLicense: resolveOpt(csvList(v["fail-on-license"]), policy.fail_on_license, []),
    allowLicense: resolveOpt(csvList(v["allow-license"]), policy.allow_license, []),
    failOnIntegrity: resolveOpt(Boolean(v["fail-on-integrity"]), policy.fail_on_integrity, false),

    gateScope: resolveOpt(
      (v["gate-scope"] as "direct" | "all" | undefined) ?? "all",
      policy.gate_scope,
      "all",
    ),
  };
}


const HELP = `npmtastic — a Node.js dependency auditor

Usage: npmtastic audit <path> [options]

Output:
  --json                 machine-readable JSON (schemaVersion=1)
  --sarif                SARIF 2.1.0 (GitHub Code Scanning)
  --markdown             shareable Markdown report
  --ndjson               one ECS-shaped event per line, for a SIEM
  --sbom                 CycloneDX 1.5 SBOM with vulnerabilities
  --output-format agent  one versioned machine envelope
  --view report|tree|table|summary   (default: report)
  --all                  list dependencies with no finding
  --full                 with --markdown/--ndjson, include the full inventory
  --no-color             strip ANSI color (also honors NO_COLOR)
  -o, --output PATH      write the report to a file instead of stdout

Filters (display only):
  --vulnerable-only      show only deps with known CVEs
  --drift-min LEVEL      show only deps drifted >= LEVEL (patch|minor|major)

Gates (exit 3 on trip; evaluated on unfiltered results):
  --fail-on-drift LEVEL  patch|minor|major
  --fail-on-vuln any|N
  --strict-vuln-gate     trip --fail-on-vuln if any package is vuln_unreachable (default: fail-open)
  --fail-on-age DAYS
  --fail-on-days-behind DAYS   trip when the resolved version has been superseded for > DAYS
  --fail-on-deprecated         trip when any resolved package is deprecated
  --fail-on-license SPDX,...   trip when a license token is on this denylist
  --allow-license SPDX,...     trip unless the license is satisfied (fails closed on unknown)
  --fail-on-integrity          trip when a lockfile integrity check fails (implies --verify)
  --gate-scope direct|all      hygiene gates (drift/age/staleness/license); security always spans all
  --baseline PATH              gate only on findings absent from this baseline
  --write-baseline PATH        record the current findings as a baseline

Discovery / cache:
  --exclude GLOB         (repeatable) prune directories by basename
  --include-prereleases
  --source osv|npm-audit|both   vuln data source (default: osv)
  --keep                 keep the temp clone of a remote source
  --verify               cross-check lockfile integrity hashes against the npm registry
  --no-cache | --refresh-cache | --cache-ttl S | --concurrency N
  --max-retries N        retries on registry/OSV 429/5xx (default: 5)
  --offline              serve only from cache; fail if anything is missing
  --log-file PATH        mirror stderr diagnostics to a file
  --no-config            skip package.json / npmtastic.toml policy and suppressions
  --quiet                suppress warnings on stderr

Usage: npmtastic stats <path> [options]   (cross-project rollup)
  --top N                most-depended-upon packages (default: 20)
  --json                 machine-readable JSON
  --exclude GLOB         (repeatable) prune directories by basename
  --include-prereleases
  --source osv|npm-audit|both
  --keep
  --no-cache | --refresh-cache | --cache-ttl S | --concurrency N
  --max-retries N
  --offline
  --log-file PATH
  --no-config
  --quiet
  (same gate flags as audit)

Usage: npmtastic update <path> [options]   (writes package.json)
  --pin                  convert direct-dep ranges to exact at the resolved version
  --to patch|minor|major bound the upgrade ceiling (default: major; security outranks)
  --allow-skipped        exit 0 even when an advisory-carrying dep could not be rewritten
  --packages a,b,c       limit to these dependencies
  --dry-run              show changes, write nothing
  --no-test              skip the isolated install check (skips the install check and rollback)
  --no-apply-cve-floor   disable the CVE-aware floor; pick latest as usual (default: floor is on)
  --refresh              alias for --refresh-cache
  --temp-test-dir        put the throwaway test install in the OS temp dir (already the default)
  --exclude GLOB         (repeatable) prune directories by basename
  --source osv|npm-audit|both   vuln data source (default: osv)
  --no-cache | --refresh-cache | --cache-ttl S | --concurrency N
  --max-retries N        retries on registry/OSV 429/5xx (default: 5)
  --offline              serve only from cache; fail if anything is missing
  --log-file PATH        mirror stderr diagnostics to a file
  --no-config            skip loading suppressions from package.json
  --quiet                suppress warnings on stderr
  (exit 2 if a test install failed and changes were rolled back)
  (exit 1 if an advisory-carrying dep could not be rewritten; --allow-skipped opts out)

Usage: npmtastic bootstrap <path> [options]   (reconstruct a package.json)
  (prints to stdout by default; reads the lockfile root, or node_modules)
  --from-node-modules    freeze installed top-level node_modules (exact pins) instead
  --write                write package.json (refuses to overwrite without --force)
  --force                overwrite an existing package.json (backs it up first)

  -h, --help    -v, --version
`;


function makeScanProgress(enabled: boolean, total: number): { tick: (name: string) => void; done: () => void } {
  if (!enabled) return { tick() {}, done() {} };
  let n = 0;
  let lastLen = 0;
  return {
    tick(name: string) {
      n += 1;
      const msg = `[${n}/${total}] scanning ${name}...`;
      process.stderr.write(`\r${msg.padEnd(lastLen, " ")}`);
      lastLen = Math.max(lastLen, msg.length);
    },
    done() {
      if (lastLen > 0) process.stderr.write(`\r${" ".repeat(lastLen)}\r`);
    },
  };
}

async function cmdAudit(args: string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args,
      allowPositionals: true,
      options: {
        json: { type: "boolean" },
        sarif: { type: "boolean" },
        markdown: { type: "boolean" },
        ndjson: { type: "boolean" },
        sbom: { type: "boolean" },
        "output-format": { type: "string" },
        all: { type: "boolean" },
        full: { type: "boolean" },
        view: { type: "string" },
        "vulnerable-only": { type: "boolean" },
        "drift-min": { type: "string" },
        "fail-on-drift": { type: "string" },
        "fail-on-vuln": { type: "string" },
        "strict-vuln-gate": { type: "boolean" },
        "fail-on-age": { type: "string" },
        "fail-on-days-behind": { type: "string" },
        "fail-on-deprecated": { type: "boolean" },
        "fail-on-license": { type: "string" },
        "allow-license": { type: "string" },
        "fail-on-integrity": { type: "boolean" },

        "gate-scope": { type: "string" },
        baseline: { type: "string" },
        "write-baseline": { type: "string" },
        "include-prereleases": { type: "boolean" },
        exclude: { type: "string", multiple: true },
        "no-cache": { type: "boolean" },
        "refresh-cache": { type: "boolean" },
        "cache-ttl": { type: "string" },
        concurrency: { type: "string" },
        source: { type: "string" },
        quiet: { type: "boolean" },
        "no-color": { type: "boolean" },
        "max-retries": { type: "string" },
        offline: { type: "boolean" },
        output: { type: "string", short: "o" },
        "log-file": { type: "string" },
        "no-config": { type: "boolean" },
        keep: { type: "boolean" },
        verify: { type: "boolean" },

      },
    });
  } catch (e) {
    error((e as Error).message);
    return EXIT_ERROR;
  }
  const v = parsed.values;
  if (v.quiet) setQuiet(true);
  if (v["log-file"]) {
    try {
      appendFileSync(v["log-file"], "");
    } catch (e) {
      error(`cannot open log file ${v["log-file"]}: ${(e as Error).message}`);
      return EXIT_ERROR;
    }
    setLogFile(v["log-file"]);
  }
  try {
    const outputFormat = v["output-format"] ?? "human";
    if (outputFormat !== "human" && outputFormat !== "agent") {
      error(`invalid --output-format: ${outputFormat} (expected: agent)`);
      return EXIT_ERROR;
    }
    const agent = outputFormat === "agent";
    const fail = (message: string): number => {
      if (agent) process.stdout.write(renderAgentError(message) + "\n");
      else error(message);
      return EXIT_ERROR;
    };

    const formats = (["json", "sarif", "markdown", "sbom", "ndjson"] as const).filter((k) => v[k]);
    if (formats.length > 1) {
      return fail("--" + formats.join(", --") + " are mutually exclusive; choose one output format");
    }

    if (v["gate-scope"] && v["gate-scope"] !== "direct" && v["gate-scope"] !== "all") {
      return fail(`invalid --gate-scope: ${v["gate-scope"]} (expected: direct|all)`);
    }
    if (v["fail-on-days-behind"] !== undefined) {
      const n = Number.parseInt(v["fail-on-days-behind"], 10);
      if (!Number.isFinite(n) || n < 0) {
        return fail(`invalid --fail-on-days-behind: ${v["fail-on-days-behind"]}`);
      }
    }

    const source = v.source as string | undefined;
    if (source && !["osv", "npm-audit", "both"].includes(source)) {
      return fail(`invalid --source: ${source} (expected: osv|npm-audit|both)`);
    }
    if (v.offline && (v["no-cache"] || v["refresh-cache"])) {
      return fail("--offline cannot be combined with --no-cache or --refresh-cache");
    }
    const maxRetries = v["max-retries"] !== undefined ? Number.parseInt(v["max-retries"], 10) : 5;
    if (!Number.isFinite(maxRetries) || maxRetries < 0) {
      return fail(`invalid --max-retries: ${v["max-retries"]}`);
    }

    const sourcePath = parsed.positionals[0] ?? ".";
    if (v.offline && isRemote(sourcePath)) {
      return fail("--offline cannot be used with a remote source");
    }
    if (!isRemote(sourcePath) && !existsSync(sourcePath)) {
      return fail(`path not found: ${sourcePath}`);
    }

    return await acquire(sourcePath, Boolean(v.keep), async (path) => {
    let cfg: Config;
    try {
      cfg = v["no-config"] ? emptyConfig() : loadConfig(configStartDir(path));
    } catch (e) {
      return fail(e instanceof ConfigError ? e.message : (e as Error).message);
    }

    const view = resolveOpt(v.view, cfg.view, undefined);
    if (view && !["report", "tree", "table", "summary"].includes(view)) {
      return fail(`invalid --view: ${view} (expected: report|tree|table|summary)`);
    }

    const ttlSeconds = v["no-cache"] || v["refresh-cache"]
      ? 0
      : v["cache-ttl"]
        ? Number.parseInt(v["cache-ttl"], 10)
        : (cfg.cacheTtl ?? 3600);
    const concurrency = v.concurrency ? Number.parseInt(v.concurrency, 10) : (cfg.concurrency ?? 8);
    const exclude = [...cfg.exclude, ...((v.exclude as string[] | undefined) ?? [])];
    const offline = Boolean(v.offline);
    const cacheEnabled = Boolean(v["refresh-cache"]) || !Boolean(v["no-cache"]);

    const isProject = existsSync(join(path, "package.json"));
    let projects;
    try {
      projects = isProject ? [discoverOne(path)] : discoverTree(path, { exclude });
    } catch (e) {
      return fail((e as Error).message);
    }
    if (projects.length === 0) {
      if (agent) {
        process.stdout.write(renderAgentError("no Node projects found", { command: "audit", exitCode: EXIT_ERROR }) + "\n");
      } else {
        error(`no Node projects found under ${path}`);
      }
      return EXIT_ERROR;
    }

    const registry = new RegistryClient({ ttlSeconds, concurrency, maxRetries, offline, enabled: cacheEnabled });
    const vuln = new VulnClient({
      ttlSeconds,
      concurrency,
      maxRetries,
      offline,
      enabled: cacheEnabled,
      ...(source ? { source: source as "osv" | "npm-audit" | "both" } : {}),
    });
    const includePrereleases = Boolean(v["include-prereleases"]);
    const noConfig = Boolean(v["no-config"]);
    const verify = Boolean(v.verify) || Boolean(v["fail-on-integrity"]);

    const audits: ProjectAudit[] = [];
    const progress = makeScanProgress(
      projects.length > 1 &&
        Boolean(process.stdout.isTTY) &&
        !v.quiet &&
        !agent &&
        formats.length === 0,
      projects.length,
    );
    try {
      for (const project of projects) {
        progress.tick(project.name);
        try {
          audits.push(await auditProject(project, registry, vuln, { includePrereleases, noConfig, verify }));
        } catch (e) {
          warn(`skipping ${project.name}: ${(e as Error).message}`);
        }
      }
    } finally {
      progress.done();
    }

    const incomplete = offlineIncompleteMessage(registry, vuln);
    if (incomplete) {
      return fail(incomplete);
    }

    if (v["write-baseline"]) {
      try {
        baseline.write(v["write-baseline"], audits);
      } catch (e) {
        return fail((e as Error).message);
      }
      process.stdout.write(`wrote baseline ${v["write-baseline"]}\n`);
    }

    const gates = gatesFromCli(v, cfg.policy);
    let tripped = gatesTripped(audits, gates);
    if (v.baseline) {
      let known;
      try {
        known = baseline.load(v.baseline);
      } catch (e) {
        return fail((e as Error).message);
      }
      const delta = baseline.diff(audits, known);
      for (const finding of delta.fixed) info(`fixed since baseline: ${finding.package} ${finding.key}`);
      if (delta.new.length > 0) {
        for (const finding of delta.new) {
          warn(`new since baseline: ${finding.package} ${finding.key} (${finding.project})`);
        }
      } else {
        info("no new findings since baseline");
        tripped = false;
      }
    }

    const shown = filterAudits(audits, { vulnerableOnly: Boolean(v["vulnerable-only"]), driftMin: v["drift-min"] });

    let outStr: string;
    if (agent) {
      outStr = renderAgent(shown, { command: "audit", exitCode: tripped ? EXIT_GATE : EXIT_OK });
    } else if (v.ndjson) {
      outStr = renderNdjson(shown, Boolean(v.full));
    } else if (v.json) {
      outStr = renderAuditJson(shown);
    } else if (v.sarif) {
      outStr = renderSarif(shown);
    } else if (v.sbom) {
      outStr = renderCycloneDx(shown);
    } else if (v.markdown) {
      outStr = renderMarkdown(shown, path, Boolean(v.full));
    } else {
      const chosenView = view ?? "report";
      outStr = chosenView === "report"
        ? renderReport(shown, { showAll: Boolean(v.all) })
        : renderTerminal(shown, chosenView as View);
    }
    if (v["no-color"] || process.env["NO_COLOR"] || v.output) outStr = stripAnsi(outStr);
    if (v.output) {
      try {
        writeFileSync(v.output, outStr + "\n");
      } catch (e) {
        error(`cannot write ${v.output}: ${(e as Error).message}`);
        return EXIT_ERROR;
      }
      process.stdout.write(`wrote ${v.output}\n`);
    } else {
      process.stdout.write(outStr + "\n");
    }

    return tripped ? EXIT_GATE : EXIT_OK;
    });

  } finally {
    setLogFile(null);
  }
}

async function cmdUpdate(args: string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args,
      allowPositionals: true,
      options: {
        pin: { type: "boolean" },
        packages: { type: "string" },
        "dry-run": { type: "boolean" },
        "no-test": { type: "boolean" },
        exclude: { type: "string", multiple: true },
        source: { type: "string" },
        "no-cache": { type: "boolean" },
        "refresh-cache": { type: "boolean" },
        refresh: { type: "boolean" },
        "no-apply-cve-floor": { type: "boolean" },
        "temp-test-dir": { type: "boolean" },
        "cache-ttl": { type: "string" },
        concurrency: { type: "string" },
        quiet: { type: "boolean" },
        "max-retries": { type: "string" },
        offline: { type: "boolean" },
        "log-file": { type: "string" },
        "no-config": { type: "boolean" },
        to: { type: "string" },
        "allow-skipped": { type: "boolean" },

      },
    });
  } catch (e) {
    error((e as Error).message);
    return EXIT_ERROR;
  }
  const v = parsed.values;
  if (v.quiet) setQuiet(true);
  if (v["log-file"]) {
    try {
      appendFileSync(v["log-file"], "");
    } catch (e) {
      error(`cannot open log file ${v["log-file"]}: ${(e as Error).message}`);
      return EXIT_ERROR;
    }
    setLogFile(v["log-file"]);
  }
  try {
    const path = parsed.positionals[0] ?? ".";
    if (isRemote(path)) {
      error("update does not support remote sources (writes to a throwaway clone)");
      return EXIT_ERROR;
    }
    if (!existsSync(path)) {
      error(`path not found: ${path}`);
      return EXIT_ERROR;
    }
    const toRaw = v.to ?? "major";
    if (toRaw !== "patch" && toRaw !== "minor" && toRaw !== "major") {
      error(`invalid --to: ${toRaw} (expected: patch|minor|major)`);
      return EXIT_ERROR;
    }

    const source = v.source as string | undefined;
    if (source && !["osv", "npm-audit", "both"].includes(source)) {
      error(`invalid --source: ${source}`);
      return EXIT_ERROR;
    }
    if (v.offline && (v["no-cache"] || v["refresh-cache"] || v.refresh)) {
      error("--offline cannot be combined with --no-cache or --refresh-cache");
      return EXIT_ERROR;
    }
    const maxRetries = v["max-retries"] !== undefined ? Number.parseInt(v["max-retries"], 10) : 5;
    if (!Number.isFinite(maxRetries) || maxRetries < 0) {
      error(`invalid --max-retries: ${v["max-retries"]}`);
      return EXIT_ERROR;
    }
    const ttlSeconds = v["no-cache"] || v["refresh-cache"] || v.refresh ? 0 : v["cache-ttl"] ? Number.parseInt(v["cache-ttl"], 10) : 3600;
    const concurrency = v.concurrency ? Number.parseInt(v.concurrency, 10) : 8;
    const packages = v.packages ? (v.packages as string).split(",").map((s) => s.trim()).filter(Boolean) : undefined;
    const exclude = (v.exclude as string[] | undefined) ?? [];
    const offline = Boolean(v.offline);
    const noConfig = Boolean(v["no-config"]);
    const cacheEnabled = Boolean(v["refresh-cache"]) || !Boolean(v["no-cache"]);

    const isProject = existsSync(join(path, "package.json"));
    let projects;
    try {
      projects = isProject ? [discoverOne(path)] : discoverTree(path, { exclude });
    } catch (e) {
      error((e as Error).message);
      return EXIT_ERROR;
    }

    const registry = new RegistryClient({ ttlSeconds, concurrency, maxRetries, offline, enabled: cacheEnabled });
    const vuln = new VulnClient({ ttlSeconds, concurrency, maxRetries, offline, enabled: cacheEnabled, ...(source ? { source: source as "osv" | "npm-audit" | "both" } : {}) });

    let rolledBack = false;
    let blocked = false;
    for (const project of projects) {
      let res: UpdateResult;
      try {
        res = await updateProject(project, registry, vuln, {
          pin: Boolean(v.pin),
          test: !v["no-test"],
          dryRun: Boolean(v["dry-run"]),
          noConfig,
          to: toRaw,
          applyCveFloor: !v["no-apply-cve-floor"],
          tempTestDir: Boolean(v["temp-test-dir"]),
          ...(packages ? { packages } : {}),
        });
      } catch (e) {
        const msg = (e as Error).message ?? String(e);
        if (msg.includes("ENOSPC") || msg.includes("EACCES") || msg.includes("rename")) {
          error(`update failed for ${project.name}: ${msg}`);
          return EXIT_ERROR;
        }
        warn(`skipping ${project.name}: ${msg}`);
        continue;
      }
      const incomplete = offlineIncompleteMessage(registry, vuln);
      if (incomplete) {
        error(incomplete);
        return EXIT_ERROR;
      }
      const tag = v["dry-run"] ? " (dry run)" : res.tested ? (res.testPassed ? " (install ok)" : " (rolled back)") : "";
      if (res.changes.length === 0) {
        process.stdout.write(`${project.name}: no changes${tag}\n`);
      } else {
        process.stdout.write(`${project.name}: ${res.changes.length} change(s)${tag}\n`);
        for (const c of res.changes) {
          process.stdout.write(`  ${c.name}  ${c.from} -> ${c.to}${c.note ? `  [${c.note}]` : ""}\n`);
        }
      }
      if (res.skipped.length > 0) {
        process.stdout.write("\nSkipped (cannot rewrite):\n");
        for (const s of res.skipped) {
          const target = s.minSafeVersion ? ` -> ${s.minSafeVersion}` : "";
          const detail = s.advisory ? `${s.advisory}, ${s.reason}` : s.reason;
          process.stdout.write(`  ${s.name} ${s.current ?? "?"}${target}  (${detail})\n`);
        }
      }
      if (res.skipped.some((s) => s.advisory)) blocked = true;
      if (res.tested && !res.testPassed) rolledBack = true;
    }
    if (rolledBack) return EXIT_ROLLBACK;
    if (blocked && !v["allow-skipped"]) return EXIT_ERROR;
    return EXIT_OK;

  } finally {
    setLogFile(null);
  }
}

async function cmdBootstrap(args: string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args,
      allowPositionals: true,
      options: {
        "from-node-modules": { type: "boolean" },
        write: { type: "boolean" },
        force: { type: "boolean" },
        quiet: { type: "boolean" },
      },
    });
  } catch (e) {
    error((e as Error).message);
    return EXIT_ERROR;
  }
  const v = parsed.values;
  if (v.quiet) setQuiet(true);
  const path = parsed.positionals[0] ?? ".";
  if (!existsSync(path)) {
    error(`path not found: ${path}`);
    return EXIT_ERROR;
  }

  const res = bootstrapProject(path, { fromNodeModules: Boolean(v["from-node-modules"]) });
  if (!res) {
    error(`bootstrap: no lockfile or node_modules found under ${path}; nothing to reconstruct`);
    return EXIT_ERROR;
  }
  for (const w of res.warnings) warn(w);
  const text = JSON.stringify(res.manifest, null, 2) + "\n";

  if (!v.write) {
    process.stdout.write(text);
    return EXIT_OK;
  }

  const manifestPath = join(path, "package.json");
  if (existsSync(manifestPath)) {
    if (!v.force) {
      error(`bootstrap: ${manifestPath} already exists; pass --force to overwrite (the existing file is backed up first)`);
      return EXIT_ERROR;
    }
    const existing = readText(manifestPath);
    const backup = backupManifest(manifestPath, path, existing);
    warn(`bootstrap: backed up existing package.json to ${backup}`);
  }
  writeFileSync(manifestPath, text);
  process.stdout.write(`bootstrap: wrote ${manifestPath} (source: ${res.source})\n`);
  return EXIT_OK;
}

async function cmdStats(args: string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args,
      allowPositionals: true,
      options: {
        json: { type: "boolean" },
        top: { type: "string" },
        "fail-on-drift": { type: "string" },
        "fail-on-vuln": { type: "string" },
        "strict-vuln-gate": { type: "boolean" },
        "fail-on-age": { type: "string" },
        "fail-on-days-behind": { type: "string" },
        "fail-on-deprecated": { type: "boolean" },
        "fail-on-license": { type: "string" },
        "allow-license": { type: "string" },
        "fail-on-integrity": { type: "boolean" },

        "gate-scope": { type: "string" },
        "include-prereleases": { type: "boolean" },
        exclude: { type: "string", multiple: true },
        "no-cache": { type: "boolean" },
        "refresh-cache": { type: "boolean" },
        "cache-ttl": { type: "string" },
        concurrency: { type: "string" },
        source: { type: "string" },
        quiet: { type: "boolean" },
        "max-retries": { type: "string" },
        offline: { type: "boolean" },
        "log-file": { type: "string" },
        "no-config": { type: "boolean" },
        keep: { type: "boolean" },

      },
    });
  } catch (e) {
    error((e as Error).message);
    return EXIT_ERROR;
  }
  const v = parsed.values;
  if (v.quiet) setQuiet(true);
  if (v["log-file"]) {
    try {
      appendFileSync(v["log-file"], "");
    } catch (e) {
      error(`cannot open log file ${v["log-file"]}: ${(e as Error).message}`);
      return EXIT_ERROR;
    }
    setLogFile(v["log-file"]);
  }
  try {
    if (v["gate-scope"] && v["gate-scope"] !== "direct" && v["gate-scope"] !== "all") {
      error(`invalid --gate-scope: ${v["gate-scope"]} (expected: direct|all)`);
      return EXIT_ERROR;
    }
    const source = v.source as string | undefined;
    if (source && !["osv", "npm-audit", "both"].includes(source)) {
      error(`invalid --source: ${source} (expected: osv|npm-audit|both)`);
      return EXIT_ERROR;
    }
    if (v.offline && (v["no-cache"] || v["refresh-cache"])) {
      error("--offline cannot be combined with --no-cache or --refresh-cache");
      return EXIT_ERROR;
    }
    const maxRetries = v["max-retries"] !== undefined ? Number.parseInt(v["max-retries"], 10) : 5;
    if (!Number.isFinite(maxRetries) || maxRetries < 0) {
      error(`invalid --max-retries: ${v["max-retries"]}`);
      return EXIT_ERROR;
    }
    const top = v.top !== undefined ? Number.parseInt(v.top, 10) : 20;
    if (!Number.isFinite(top) || top < 0) {
      error(`invalid --top: ${v.top}`);
      return EXIT_ERROR;
    }
    if (v["fail-on-days-behind"] !== undefined) {
      const n = Number.parseInt(v["fail-on-days-behind"], 10);
      if (!Number.isFinite(n) || n < 0) {
        error(`invalid --fail-on-days-behind: ${v["fail-on-days-behind"]}`);
        return EXIT_ERROR;
      }
    }

    const sourcePath = parsed.positionals[0] ?? ".";
    if (v.offline && isRemote(sourcePath)) {
      error("--offline cannot be used with a remote source");
      return EXIT_ERROR;
    }
    if (!isRemote(sourcePath) && !existsSync(sourcePath)) {
      error(`path not found: ${sourcePath}`);
      return EXIT_ERROR;
    }

    return await acquire(sourcePath, Boolean(v.keep), async (path) => {
    let cfg: Config;
    try {
      cfg = v["no-config"] ? emptyConfig() : loadConfig(configStartDir(path));
    } catch (e) {
      error(e instanceof ConfigError ? e.message : (e as Error).message);
      return EXIT_ERROR;
    }

    const ttlSeconds = v["no-cache"] || v["refresh-cache"]
      ? 0
      : v["cache-ttl"]
        ? Number.parseInt(v["cache-ttl"], 10)
        : (cfg.cacheTtl ?? 3600);
    const concurrency = v.concurrency ? Number.parseInt(v.concurrency, 10) : (cfg.concurrency ?? 8);
    const exclude = [...cfg.exclude, ...((v.exclude as string[] | undefined) ?? [])];
    const offline = Boolean(v.offline);
    const includePrereleases = Boolean(v["include-prereleases"]);
    const noConfig = Boolean(v["no-config"]);
    const verify = Boolean(v["fail-on-integrity"]);
    const cacheEnabled = Boolean(v["refresh-cache"]) || !Boolean(v["no-cache"]);

    const isProject = existsSync(join(path, "package.json"));
    let projects;
    try {
      projects = isProject ? [discoverOne(path)] : discoverTree(path, { exclude });
    } catch (e) {
      error((e as Error).message);
      return EXIT_ERROR;
    }
    if (projects.length === 0) {
      error(`no Node projects found under ${path}`);
      return EXIT_ERROR;
    }

    const registry = new RegistryClient({ ttlSeconds, concurrency, maxRetries, offline, enabled: cacheEnabled });
    const vuln = new VulnClient({
      ttlSeconds,
      concurrency,
      maxRetries,
      offline,
      enabled: cacheEnabled,
      ...(source ? { source: source as "osv" | "npm-audit" | "both" } : {}),
    });

    const audits: ProjectAudit[] = [];
    const progress = makeScanProgress(
      projects.length > 1 && Boolean(process.stdout.isTTY) && !v.quiet && !v.json,
      projects.length,
    );
    try {
      for (const project of projects) {
        progress.tick(project.name);
        try {
          audits.push(await auditProject(project, registry, vuln, { includePrereleases, noConfig, verify }));
        } catch (e) {
          warn(`skipping ${project.name}: ${(e as Error).message}`);
        }
      }
    } finally {
      progress.done();
    }

    const incomplete = offlineIncompleteMessage(registry, vuln);
    if (incomplete) {
      error(incomplete);
      return EXIT_ERROR;
    }

    const report = buildStats(audits, top);
    process.stdout.write((v.json ? JSON.stringify(report, null, 2) : renderStats(report)) + "\n");

    const gates = gatesFromCli(v, cfg.policy);
    return gatesTripped(audits, gates) ? EXIT_GATE : EXIT_OK;
    });

  } finally {
    setLogFile(null);
  }
}

export async function main(argv: string[]): Promise<number> {
  const sub = argv[0];
  if (sub === undefined || sub === "-h" || sub === "--help") {
    process.stdout.write(HELP);
    return EXIT_OK;
  }
  if (sub === "-v" || sub === "--version") {
    process.stdout.write(VERSION + "\n");
    return EXIT_OK;
  }
  if (sub === "audit") return cmdAudit(argv.slice(1));
  if (sub === "stats") return cmdStats(argv.slice(1));
  if (sub === "update") return cmdUpdate(argv.slice(1));
  if (sub === "bootstrap") return cmdBootstrap(argv.slice(1));
  error(`unknown command: ${sub} (try: npmtastic --help)`);
  return EXIT_ERROR;
}
