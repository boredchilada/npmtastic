// SPDX-License-Identifier: AGPL-3.0-or-later
import { parseArgs } from "node:util";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { discoverOne, discoverTree } from "./discovery.js";
import { auditProject } from "./analysis.js";
import { RegistryClient } from "./registry.js";
import { VulnClient } from "./vulns.js";
import { renderAuditJson } from "./render/json.js";
import { renderSarif } from "./render/sarif.js";
import { renderTerminal, type View } from "./render/terminal.js";
import { setQuiet, warn, error } from "./logging.js";
import { SemverDrift, makeProjectAudit, type ProjectAudit } from "./models.js";

export const EXIT_OK = 0;
export const EXIT_ERROR = 1;
export const EXIT_GATE = 3;

const VERSION = "0.1.0"; // keep in sync with package.json

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
}

export function gatesTripped(audits: readonly ProjectAudit[], gates: GateOptions): boolean {
  if (gates.failOnDrift) {
    const threshold = DRIFT_RANK[gates.failOnDrift];
    if (threshold !== undefined) {
      for (const p of audits) {
        for (const d of p.deps) {
          const r = DRIFT_RANK[d.drift];
          if (r !== undefined && r >= threshold) return true;
        }
      }
    }
  }
  if (gates.failOnVuln) {
    const total = audits.reduce((n, p) => n + p.vulnCount, 0);
    const need = gates.failOnVuln === "any" ? 1 : Number.parseInt(gates.failOnVuln, 10);
    if (!Number.isNaN(need) && total >= need) return true;
  }
  if (gates.failOnAge !== undefined) {
    for (const p of audits) {
      for (const d of p.deps) {
        if (d.latestReleaseAgeDays !== null && d.latestReleaseAgeDays > gates.failOnAge) return true;
      }
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

const HELP = `npmtastic — a Node.js dependency auditor

Usage: npmtastic audit <path> [options]

Output:
  --json                 machine-readable JSON (schemaVersion=1)
  --sarif                SARIF 2.1.0 (GitHub Code Scanning)
  --view tree|table|summary
  --no-color             strip ANSI color

Filters (display only):
  --vulnerable-only      show only deps with known CVEs
  --drift-min LEVEL      show only deps drifted >= LEVEL (patch|minor|major)

Gates (exit 3 on trip; evaluated on unfiltered results):
  --fail-on-drift LEVEL  patch|minor|major
  --fail-on-vuln any|N
  --fail-on-age DAYS

Discovery / cache:
  --exclude GLOB         (repeatable) prune directories by basename
  --include-prereleases
  --source osv|npm-audit|both   vuln data source (default: osv)
  --no-cache | --refresh-cache | --cache-ttl S | --concurrency N
  --quiet                suppress warnings on stderr

  -h, --help    -v, --version
`;

async function cmdAudit(args: string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args,
      allowPositionals: true,
      options: {
        json: { type: "boolean" },
        sarif: { type: "boolean" },
        view: { type: "string" },
        "vulnerable-only": { type: "boolean" },
        "drift-min": { type: "string" },
        "fail-on-drift": { type: "string" },
        "fail-on-vuln": { type: "string" },
        "fail-on-age": { type: "string" },
        "include-prereleases": { type: "boolean" },
        exclude: { type: "string", multiple: true },
        "no-cache": { type: "boolean" },
        "refresh-cache": { type: "boolean" },
        "cache-ttl": { type: "string" },
        concurrency: { type: "string" },
        source: { type: "string" },
        quiet: { type: "boolean" },
        "no-color": { type: "boolean" },
      },
    });
  } catch (e) {
    error((e as Error).message);
    return EXIT_ERROR;
  }
  const v = parsed.values;
  if (v.quiet) setQuiet(true);
  if (v.json && v.sarif) {
    error("--json and --sarif are mutually exclusive");
    return EXIT_ERROR;
  }

  const source = v.source as string | undefined;
  if (source && !["osv", "npm-audit", "both"].includes(source)) {
    error(`invalid --source: ${source} (expected: osv|npm-audit|both)`);
    return EXIT_ERROR;
  }

  const path = parsed.positionals[0] ?? ".";
  if (!existsSync(path)) {
    error(`path not found: ${path}`);
    return EXIT_ERROR;
  }

  const ttlSeconds = v["no-cache"] || v["refresh-cache"] ? 0 : v["cache-ttl"] ? Number.parseInt(v["cache-ttl"], 10) : 3600;
  const concurrency = v.concurrency ? Number.parseInt(v.concurrency, 10) : 8;
  const exclude = (v.exclude as string[] | undefined) ?? [];

  const isProject = existsSync(join(path, "package.json"));
  let projects;
  try {
    projects = isProject ? [discoverOne(path)] : discoverTree(path, { exclude });
  } catch (e) {
    error((e as Error).message);
    return EXIT_ERROR;
  }
  if (projects.length === 0) {
    warn(`no Node projects found under ${path}`);
    return EXIT_OK;
  }

  const registry = new RegistryClient({ ttlSeconds, concurrency });
  const vuln = new VulnClient({
    ttlSeconds,
    concurrency,
    ...(source ? { source: source as "osv" | "npm-audit" | "both" } : {}),
  });
  const includePrereleases = Boolean(v["include-prereleases"]);

  const audits: ProjectAudit[] = [];
  for (const project of projects) {
    try {
      audits.push(await auditProject(project, registry, vuln, { includePrereleases }));
    } catch (e) {
      warn(`skipping ${project.name}: ${(e as Error).message}`);
    }
  }

  const tripped = gatesTripped(audits, {
    failOnDrift: v["fail-on-drift"],
    failOnVuln: v["fail-on-vuln"],
    failOnAge: v["fail-on-age"] !== undefined ? Number.parseInt(v["fail-on-age"], 10) : undefined,
  });

  const shown = filterAudits(audits, { vulnerableOnly: Boolean(v["vulnerable-only"]), driftMin: v["drift-min"] });

  let outStr: string;
  if (v.json) outStr = renderAuditJson(shown);
  else if (v.sarif) outStr = renderSarif(shown);
  else {
    const view: View = (v.view as View | undefined) ?? (isProject ? "table" : "tree");
    outStr = renderTerminal(shown, view);
  }
  if (v["no-color"]) outStr = stripAnsi(outStr);
  process.stdout.write(outStr + "\n");

  return tripped ? EXIT_GATE : EXIT_OK;
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
  error(`unknown command: ${sub} (try: npmtastic --help)`);
  return EXIT_ERROR;
}
