// SPDX-License-Identifier: AGPL-3.0-or-later
import { SemverDrift, type DepAudit, type ProjectAudit } from "../models.js";
import { severityRank } from "../vulns.js";

const VERSION = "0.1.1";
const SEVERITY_ORDER = ["critical", "high", "moderate", "low", "unknown"] as const;

function cell(value: string | null | undefined): string {
  if (value === null || value === undefined || value === "") return "-";
  return String(value).replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function table(headers: readonly string[], rows: readonly (readonly string[])[]): string[] {
  const out = [
    "| " + headers.join(" | ") + " |",
    "| " + headers.map(() => "---").join(" | ") + " |",
  ];
  for (const row of rows) {
    if (row.length !== headers.length) {
      throw new Error(`row has ${row.length} cells, expected ${headers.length}`);
    }
    out.push("| " + row.join(" | ") + " |");
  }
  return out;
}

function origin(dep: DepAudit): string {
  if (dep.dep.direct) return "direct";
  if (dep.via && dep.via.length > 0) return "via " + dep.via.join(" -> ");
  return "transitive";
}


function current(dep: DepAudit): string {
  return dep.dep.resolved ?? dep.dep.range ?? "";
}

function isFinding(dep: DepAudit): boolean {
  return dep.vulnerabilities.length > 0 || dep.deprecated !== null;
}

function severity(dep: DepAudit): string {
  if (dep.vulnerabilities.length === 0) return dep.deprecated ? "deprecated" : "-";
  return dep.vulnerabilities.reduce((a, b) =>
    severityRank(b.severity) > severityRank(a.severity) ? b : a,
  ).severity;
}

function fix(dep: DepAudit): string | null {
  if (dep.minSafeVersion) return dep.minSafeVersion;
  if (dep.deprecated && dep.latest && dep.latest !== (dep.dep.resolved ?? "")) return dep.latest;
  return null;
}

function breakdown(total: number, mapping: Record<string, number>, order: readonly string[]): string {
  if (!total) return "0";
  const detail = order.filter((key) => mapping[key]).map((key) => `${mapping[key]} ${key}`).join(", ");
  return detail ? `${total} (${detail})` : String(total);
}


function integrityState(audits: readonly ProjectAudit[]): string {
  if (!audits.some((p) => p.integrityChecked || (p.integrityFindings ?? []).length > 0)) {
    return "not checked (`--verify` not requested)";
  }
  const problems = audits.reduce((n, p) => n + (p.integrityFindings ?? []).filter((f) => f.kind !== "unverifiable").length, 0);
  const unverifiable = audits.reduce((n, p) => n + (p.integrityFindings ?? []).filter((f) => f.kind === "unverifiable").length, 0);
  if (problems) return `**${problems} problem(s)**`;
  if (unverifiable) return `${unverifiable} unverifiable`;
  return "verified";
}

function summary(audits: readonly ProjectAudit[], deps: readonly { project: ProjectAudit; dep: DepAudit }[]): string[] {
  const severities: Record<string, number> = {};
  for (const { dep } of deps) {
    for (const v of dep.vulnerabilities) {
      severities[v.severity] = (severities[v.severity] ?? 0) + 1;
    }
  }
  const drift = {
    major: deps.filter(({ dep }) => dep.drift === SemverDrift.MAJOR).length,
    minor: deps.filter(({ dep }) => dep.drift === SemverDrift.MINOR).length,
    patch: deps.filter(({ dep }) => dep.drift === SemverDrift.PATCH).length,
  };
  const rows = [
    ["Projects", String(audits.length)],
    ["Dependencies", String(deps.length)],
    ["Vulnerabilities", breakdown(Object.values(severities).reduce((n, x) => n + x, 0), severities, SEVERITY_ORDER)],
    ["Deprecated", String(deps.filter(({ dep }) => dep.deprecated !== null).length)],
    ["Suppressed (accepted risk)", String(audits.reduce((n, p) => n + p.suppressedCount, 0))],
    ["Drift", `${drift.major} major, ${drift.minor} minor, ${drift.patch} patch`],
    ["Integrity", integrityState(audits)],

  ];
  return ["## Summary", "", ...table(["Metric", "Value"], rows), ""];
}

function findings(items: readonly { project: ProjectAudit; dep: DepAudit }[]): string[] {
  const rows = items.map(({ project, dep }) => [
    cell(dep.dep.name),
    cell(current(dep) || null),
    cell(severity(dep)),
    cell(dep.vulnerabilities.map((v) => v.id).join(", ") || (dep.deprecated ? "deprecated" : "-")),
    cell(project.project.name),
    cell(origin(dep)),
    cell(fix(dep)),
  ]);
  return [
    "## Findings",
    "",
    ...table(["Package", "Version", "Severity", "Advisories", "Project", "Path", "Fix"], rows),
    "",
  ];
}

function remediation(items: readonly { project: ProjectAudit; dep: DepAudit }[]): string[] {
  const lines = ["## Remediation", ""];
  let actionable = false;
  for (const { project, dep } of items) {
    const target = fix(dep);
    if (target === null) continue;
    actionable = true;
    lines.push(
      `- **${dep.dep.name}** in \`${project.project.name}\`: upgrade \`${current(dep) || "?"}\` to \`${target}\`.`,
    );
    if (dep.via && dep.via.length > 0) {
      lines.push(
        `  - Reached via \`${dep.via.join(" -> ")}\`, so it is not declared in this manifest - bump \`${dep.via[0]}\` (or run \`npm update\`).`,
      );
    } else if (!dep.dep.direct) {
      lines.push(
        "  - Transitive dependency, so it is not declared in this manifest - bump the parent (or run `npm update`).",
      );
    }

  }
  if (!actionable) {
    lines.push("No advisory in this report has a published fixed version.");
  }
  lines.push("");
  return lines;
}

function incomplete(audits: readonly ProjectAudit[], deps: readonly { project: ProjectAudit; dep: DepAudit }[]): string[] {
  const registry = deps.filter(({ dep }) => dep.registryUnreachable);
  const lookups = deps.filter(({ dep }) => dep.vulnUnreachable);
  if (registry.length === 0 && lookups.length === 0) return [];

  const lines = ["## Incomplete data", "", "These results could not be established:", ""];
  for (const { project, dep } of registry) {
    lines.push(
      `- \`${dep.dep.name}\` - npm registry unreachable; drift and deprecation unknown (${project.project.name}).`,
    );
  }
  for (const { project, dep } of lookups) {
    const ver = current(dep);
    lines.push(
      `- \`${dep.dep.name}${ver ? ` ${ver}` : ""}\` - advisory lookup unreachable; **vulnerability status unknown, not clean** (${project.project.name}).`,
    );
  }
  lines.push("");
  return lines;
}

function inventory(deps: readonly { project: ProjectAudit; dep: DepAudit }[]): string[] {
  const rows = [...deps]
    .sort((a, b) => {
      const byProject = a.project.project.name.localeCompare(b.project.project.name);
      return byProject !== 0 ? byProject : a.dep.dep.name.localeCompare(b.dep.dep.name);
    })
    .map(({ project, dep }) => [
      cell(dep.dep.name),
      cell(current(dep) || null),
      cell(dep.latest),
      cell(project.project.name),
      cell(origin(dep)),
      cell(dep.pinStatus),
      cell(dep.drift),
      cell(dep.license),
      dep.latestReleaseAgeDays === null ? "-" : `${dep.latestReleaseAgeDays}d`,
    ]);

  return [
    "## All dependencies",
    "",
    ...table(["Package", "Version", "Latest", "Project", "Path", "Pin", "Drift", "License", "Behind"], rows),

    "",
  ];
}

export function renderMarkdown(audits: readonly ProjectAudit[], source: string, full = false): string {
  const today = new Date().toISOString().slice(0, 10);
  const deps = audits.flatMap((p) => p.deps.map((d) => ({ project: p, dep: d })));
  const lines: string[] = [
    "# Dependency audit",
    "",
    `- **Source**: \`${cell(source)}\``,
    `- **Date**: ${today}`,
    `- **Tool**: npmtastic ${VERSION}`,
    "",
  ];
  lines.push(...summary(audits, deps));

  const found = [...deps.filter(({ dep }) => isFinding(dep))].sort((a, b) => {
    const topA = Math.max(-1, ...a.dep.vulnerabilities.map((v) => severityRank(v.severity)));
    const topB = Math.max(-1, ...b.dep.vulnerabilities.map((v) => severityRank(v.severity)));
    if (topB !== topA) return topB - topA;
    const vulnA = a.dep.vulnerabilities.length > 0 ? 0 : 1;
    const vulnB = b.dep.vulnerabilities.length > 0 ? 0 : 1;
    if (vulnA !== vulnB) return vulnA - vulnB;
    const byName = a.dep.dep.name.localeCompare(b.dep.dep.name);
    return byName !== 0 ? byName : a.project.project.name.localeCompare(b.project.project.name);
  });

  const integrity = audits.flatMap((p) => (p.integrityFindings ?? []).map((f) => ({ project: p, finding: f })));
  if (found.length > 0 || integrity.length > 0) {
    if (found.length > 0) {
      lines.push(...findings(found));
      lines.push(...remediation(found));
    } else {
      lines.push("## Findings", "");
    }
    for (const { project, finding } of integrity) {
      const version = finding.version ? ` ${finding.version}` : "";
      lines.push(`- \`${finding.name}${version}\` - integrity ${finding.kind}: ${finding.detail} (${project.project.name}).`);
    }
    if (integrity.length > 0) lines.push("");
  } else {
    lines.push("## Findings", "", "None. No vulnerabilities, deprecated packages, or integrity problems were found.", "");
  }


  lines.push(...incomplete(audits, deps));
  if (full) lines.push(...inventory(deps));
  return lines.join("\n").replace(/\s+$/, "") + "\n";
}
