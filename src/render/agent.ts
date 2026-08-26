// SPDX-License-Identifier: AGPL-3.0-or-later
import { join } from "node:path";
import { SemverDrift, type DepAudit, type ProjectAudit, type Vulnerability } from "../models.js";
import { severityRank } from "../vulns.js";

const VERSION = "0.1.1";
export const SCHEMA_VERSION = 1;
const DATASET = "npmtastic.audit";

const ECS_SEVERITY: Record<string, number> = {
  critical: 99,
  high: 73,
  moderate: 47,
  low: 21,
  unknown: 0,
};

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = sortKeys((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

function stableJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function now(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function npmPurl(name: string, version: string | null): string | null {
  if (!version) return null;
  if (name.startsWith("@")) {
    const slash = name.indexOf("/");
    if (slash > 0) {
      return `pkg:npm/%40${name.slice(1, slash)}/${name.slice(slash + 1)}@${version}`;
    }
  }
  return `pkg:npm/${name}@${version}`;
}

function origin(dep: DepAudit): string {
  if (dep.dep.direct) return "direct";
  if (dep.via && dep.via.length > 0) return "via " + dep.via.join(" -> ");
  return "transitive";
}


function current(dep: DepAudit): string | null {
  return dep.dep.resolved;
}

function topSeverity(dep: DepAudit): string {
  if (dep.vulnerabilities.length === 0) return "unknown";
  return dep.vulnerabilities.reduce((a, b) =>
    severityRank(b.severity) > severityRank(a.severity) ? b : a,
  ).severity;
}

function remediation(dep: DepAudit): string | null {
  if (dep.minSafeVersion) return dep.minSafeVersion;
  if (dep.deprecated && dep.latest && dep.latest !== (dep.dep.resolved ?? "")) return dep.latest;
  return null;
}

function isFinding(dep: DepAudit): boolean {
  return dep.vulnerabilities.length > 0 || dep.deprecated !== null;
}

function findingRecord(project: ProjectAudit, dep: DepAudit): Record<string, unknown> {
  const record: Record<string, unknown> = {
    package: dep.dep.name,
    version: current(dep),
    project: project.project.name,
    origin: origin(dep),
    severity: topSeverity(dep),
  };
  if (dep.vulnerabilities.length > 0) {
    record["vulnerabilities"] = dep.vulnerabilities.map((v: Vulnerability) => ({
      id: v.id,
      aliases: v.aliases,
      severity: v.severity,
      summary: v.summary,
    }));
  }
  if (dep.deprecated) record["deprecated"] = true;
  const fix = remediation(dep);
  record.fixable_here = Boolean(fix);
  if (fix) record.fix_version = fix;
  if (dep.via && dep.via.length > 0) record["via"] = [...dep.via];

  return record;
}

function unknowns(audits: readonly ProjectAudit[]): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const project of audits) {
    for (const dep of project.deps) {
      if (dep.registryUnreachable) {
        out.push({
          package: dep.dep.name,
          project: project.project.name,
          unknown: "registry",
          consequence: "drift and deprecation unknown",
        });
      }
      if (dep.vulnUnreachable) {
        out.push({
          package: dep.dep.name,
          version: current(dep),
          project: project.project.name,
          unknown: "advisories",
          consequence: "vulnerability status unknown, NOT clean",
        });
      }
      if (dep.dep.resolved === null && dep.dep.url === null) {
        out.push({
          package: dep.dep.name,
          project: project.project.name,
          unknown: "resolved_version",
          consequence: "no version proven by the lockfile; not audited",
        });
      }
    }
  }
  return out;
}

function nextActions(
  findings: Record<string, unknown>[],
  unknownItems: Record<string, unknown>[],
): string[] {
  const actions: string[] = [];
  const directFixable = findings.filter((f) => f["fixable_here"] && f["fix_version"]);
  if (directFixable.length > 0) {
    const pkgs = [...new Set(directFixable.map((f) => String(f["package"])))].sort().join(",");
    actions.push(`npmtastic update . --packages ${pkgs}`);
  }
  if (unknownItems.length > 0) {
    actions.push(
      "re-run with network access; results above are incomplete and must not be treated as clean",
    );
  }
  if (findings.length === 0 && unknownItems.length === 0) {
    actions.push("no action required");
  }
  return actions;
}

export function renderAgentError(
  message: string,
  opts: { command?: string; kind?: string; exitCode?: number } = {},
): string {
  return stableJson({
    command: opts.command ?? "audit",
    data: null,
    error: { kind: opts.kind ?? "error", message },
    exit_code: opts.exitCode ?? 1,
    ok: false,
    outcome: "error",
    schema_version: SCHEMA_VERSION,
    warnings: [],
  });
}

export function renderAgent(
  audits: readonly ProjectAudit[],
  opts: { command?: string; exitCode?: number; warnings?: readonly string[] } = {},
): string {
  const command = opts.command ?? "audit";
  const exitCode = opts.exitCode ?? 0;
  const deps = audits.flatMap((p) => p.deps.map((d) => ({ project: p, dep: d })));
  const findings = deps
    .filter(({ dep }) => isFinding(dep))
    .sort((a, b) => {
      const sev = severityRank(topSeverity(b.dep)) - severityRank(topSeverity(a.dep));
      if (sev !== 0) return sev;
      const vuln = (a.dep.vulnerabilities.length > 0 ? 0 : 1) - (b.dep.vulnerabilities.length > 0 ? 0 : 1);
      if (vuln !== 0) return vuln;
      return a.dep.dep.name.localeCompare(b.dep.dep.name);
    })
    .map(({ project, dep }) => findingRecord(project, dep));
  const unknownItems = unknowns(audits);

  const severities: Record<string, number> = {};
  for (const { dep } of deps) {
    for (const advisory of dep.vulnerabilities) {
      severities[advisory.severity] = (severities[advisory.severity] ?? 0) + 1;
    }
  }

  const warnings = [...(opts.warnings ?? [])];
  if (unknownItems.length > 0) {
    warnings.push(`${unknownItems.length} item(s) could not be established; this audit is incomplete`);
  }
  return stableJson({
    command,
    data: {
      tool: { name: "npmtastic", version: VERSION },
      generated: now(),
      summary: {
        projects: audits.length,
        dependencies: deps.length,
        direct: deps.filter(({ dep }) => dep.dep.direct).length,
        vulnerabilities: deps.reduce((n, { dep }) => n + dep.vulnerabilities.length, 0),
        vulnerabilities_by_severity: Object.fromEntries(
          Object.entries(severities).sort(([a], [b]) => a.localeCompare(b)),
        ),
        deprecated: deps.filter(({ dep }) => dep.deprecated !== null).length,
        integrity_problems: audits.reduce(
          (n, p) => n + (p.integrityFindings ?? []).filter((f) => f.kind !== "unverifiable").length,
          0,
        ),

        unknown: unknownItems.length,
        drift: {
          [SemverDrift.MAJOR]: deps.filter(({ dep }) => dep.drift === SemverDrift.MAJOR).length,
          [SemverDrift.MINOR]: deps.filter(({ dep }) => dep.drift === SemverDrift.MINOR).length,
          [SemverDrift.PATCH]: deps.filter(({ dep }) => dep.drift === SemverDrift.PATCH).length,
        },
      },
      findings,
      unknown: unknownItems,
      next_actions: nextActions(findings, unknownItems),
    },
    exit_code: exitCode,
    ok: exitCode === 0,
    outcome: exitCode === 0 ? "success" : "gate_tripped",
    schema_version: SCHEMA_VERSION,
    warnings,
  });
}

function baseEvent(project: ProjectAudit, timestamp: string): Record<string, unknown> {
  return {
    "@timestamp": timestamp,
    "event.dataset": DATASET,
    "event.module": "npmtastic",
    "event.provider": "npmtastic",
    "observer.version": VERSION,
    "service.name": project.project.name,
    "file.path": join(project.project.root, "package.json").replace(/\\/g, "/"),
  };
}

function depFields(dep: DepAudit): Record<string, unknown> {
  const fields: Record<string, unknown> = {
    "package.name": dep.dep.name,
    "package.type": "npm",
    "package.version": current(dep),
    "npmtastic.direct": dep.dep.direct,
    "npmtastic.pin_status": dep.pinStatus,
    "npmtastic.drift": dep.drift,
  };
  const purl = npmPurl(dep.dep.name, current(dep));
  if (purl) fields["package.reference"] = purl;
  if (dep.license) fields["package.license"] = dep.license;
  if (dep.via && dep.via.length > 0) fields["npmtastic.via"] = [...dep.via];

  if (dep.latestReleaseAgeDays !== null) fields["npmtastic.days_behind"] = dep.latestReleaseAgeDays;
  return fields;
}

export function* iterEvents(audits: readonly ProjectAudit[], full = false): Generator<Record<string, unknown>> {
  const timestamp = now();
  for (const project of audits) {
    const base = baseEvent(project, timestamp);
    for (const dep of project.deps) {
      for (const advisory of dep.vulnerabilities) {
        const event: Record<string, unknown> = { ...base, ...depFields(dep) };
        event["event.kind"] = "alert";
        event["event.category"] = ["vulnerability"];
        event["event.type"] = ["info"];
        event["event.action"] = "vulnerability-detected";
        event["event.severity"] = ECS_SEVERITY[advisory.severity] ?? 0;
        event["vulnerability.id"] = advisory.id;
        event["vulnerability.severity"] = advisory.severity;
        event["vulnerability.description"] = advisory.summary;
        event["vulnerability.scanner.vendor"] = "npmtastic";
        event["vulnerability.enumeration"] = "OSV";
        event["message"] = `${dep.dep.name} ${current(dep)}: ${advisory.id} (${advisory.severity})`;
        if (advisory.aliases.length > 0) event["vulnerability.classification"] = advisory.aliases;
        if (advisory.cvss) {
          event["vulnerability.score.version"] = "3.x";
          event["npmtastic.cvss_vector"] = advisory.cvss;
        }
        if (advisory.references.length > 0) event["vulnerability.reference"] = advisory.references[0];
        if (advisory.cweIds.length > 0) event["npmtastic.cwe"] = advisory.cweIds;
        const fix = remediation(dep);
        if (fix) event["npmtastic.fix_version"] = fix;
        yield event;
      }

      if (dep.deprecated) {
        yield {
          ...base,
          ...depFields(dep),
          "event.kind": "alert",
          "event.category": ["package"],
          "event.type": ["info"],
          "event.action": "deprecated-release",
          "event.severity": ECS_SEVERITY["moderate"],
          message: `${dep.dep.name} ${current(dep)}: package deprecated on the npm registry`,
        };
      }

      if (dep.registryUnreachable || dep.vulnUnreachable) {
        yield {
          ...base,
          ...depFields(dep),
          "event.kind": "event",
          "event.category": ["package"],
          "event.type": ["info"],
          "event.action": "lookup-unreachable",
          "event.outcome": "unknown",
          "event.severity": ECS_SEVERITY["low"],
          "npmtastic.unknown": [
            ...(dep.registryUnreachable ? ["registry"] : []),
            ...(dep.vulnUnreachable ? ["advisories"] : []),
          ],
          message: `${dep.dep.name}: lookup unreachable; status unknown, not clean`,
        };
      }

      if (full && !isFinding(dep) && !dep.registryUnreachable) {
        yield {
          ...base,
          ...depFields(dep),
          "event.kind": "state",
          "event.category": ["package"],
          "event.type": ["info"],
          "event.action": "dependency-observed",
          "event.outcome": "success",
          message: `${dep.dep.name} ${current(dep)}`,
        };
      }
    }

    yield {
      ...base,
      "event.kind": "state",
      "event.category": ["package"],
      "event.type": ["info"],
      "event.action": "audit-completed",
      "event.outcome": "success",
      "npmtastic.dependencies": project.deps.length,
      "npmtastic.vulnerabilities": project.vulnCount,
      "npmtastic.deprecated": project.deprecatedCount,
      "npmtastic.registry_unreachable": project.registryUnreachable,
      "npmtastic.advisories_unreachable": project.vulnUnreachable,
      "npmtastic.pinning_score": project.pinningScore,
      message: `${project.project.name}: ${project.deps.length} dependencies, ${project.vulnCount} vulnerabilities`,
    };
  }
}

export function renderNdjson(audits: readonly ProjectAudit[], full = false): string {
  const lines = [...iterEvents(audits, full)].map((event) =>
    stableJson(Object.fromEntries(Object.entries(event).filter(([, v]) => v !== null && v !== undefined))),
  );
  return lines.length > 0 ? lines.join("\n") + "\n" : "";
}
