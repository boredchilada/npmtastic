// SPDX-License-Identifier: AGPL-3.0-or-later
import pc from "picocolors";
import { PinStatus, SemverDrift, type DepAudit, type ProjectAudit } from "../models.js";
import { severityRank } from "../vulns.js";

const VERSION = "0.1.1";

const DRIFT_RANK: Record<string, number> = {
  [SemverDrift.NONE]: 0,
  [SemverDrift.PRERELEASE]: 1,
  [SemverDrift.PATCH]: 2,
  [SemverDrift.MINOR]: 3,
  [SemverDrift.MAJOR]: 4,
};

export interface ReportOptions {
  showAll?: boolean;
  directOnly?: boolean;
}

function current(dep: DepAudit): string {
  return dep.dep.resolved ?? dep.dep.range ?? "?";
}

function origin(dep: DepAudit): string {
  if (dep.dep.direct) return "direct";
  if (dep.via && dep.via.length > 0) return "via " + dep.via.join(" -> ");
  return "transitive";
}


function isFinding(dep: DepAudit): boolean {
  return dep.vulnerabilities.length > 0 || dep.deprecated !== null;
}

function keep(dep: DepAudit, opts: ReportOptions): boolean {
  return dep.dep.direct || !opts.directOnly;
}

function rank(dep: DepAudit): [number, number, number, number, string] {
  const top = Math.max(-1, ...dep.vulnerabilities.map((v) => severityRank(v.severity)));
  const drift = DRIFT_RANK[dep.drift];
  return [
    dep.vulnerabilities.length > 0 ? 0 : 1,
    -top,
    dep.deprecated ? 0 : 1,
    -(drift !== undefined ? drift : -1),
    dep.dep.name,
  ];
}

function cmpRank(a: DepAudit, b: DepAudit): number {
  const ra = rank(a);
  const rb = rank(b);
  for (let i = 0; i < ra.length; i++) {
    const av = ra[i]!;
    const bv = rb[i]!;
    if (av < bv) return -1;
    if (av > bv) return 1;
  }
  return 0;
}

function severityLabel(dep: DepAudit): string {
  if (dep.vulnerabilities.length === 0) return "";
  const best = dep.vulnerabilities.reduce((a, b) =>
    severityRank(b.severity) > severityRank(a.severity) ? b : a,
  );
  if (best.severity === "unknown") return "";
  return `${colorSeverity(best.severity)}  `;
}

function colorSeverity(severity: string): string {
  switch (severity) {
    case "critical":
      return pc.bold(pc.red(severity));
    case "high":
      return pc.red(severity);
    case "moderate":
      return pc.yellow(severity);
    case "low":
      return pc.cyan(severity);
    default:
      return pc.dim(severity);
  }
}

function advisoryIds(dep: DepAudit): string {
  return dep.vulnerabilities.map((v) => v.id).join(" / ");
}

function declared(dep: DepAudit): string {
  if (!dep.dep.direct || !dep.dep.range) return "";
  return ` | declared: ${dep.dep.rawName} = "${dep.dep.range}"`;
}

function remediation(dep: DepAudit): string | null {
  if (dep.minSafeVersion) return dep.minSafeVersion;
  if (dep.deprecated && dep.latest && dep.latest !== (dep.dep.resolved ?? "")) return dep.latest;
  return null;
}

function ordered(mapping: Record<string, number>, order: readonly string[]): string {
  const parts = order.filter((key) => mapping[key]).map((key) => `${mapping[key]} ${key}`);
  for (const [k, v] of Object.entries(mapping).sort(([a], [b]) => a.localeCompare(b))) {
    if (!order.includes(k) && v) parts.push(`${v} ${k}`);
  }
  return parts.join(", ");
}

interface Visible {
  project: ProjectAudit;
  deps: DepAudit[];
}

function counts(visible: readonly Visible[]): {
  deps: number;
  vulns: number;
  severities: Record<string, number>;
  deprecated: number;
  drift: Record<string, number>;
  vulnUnreachable: number;
  registryUnreachable: number;
  suppressed: number;
} {
  const deps = visible.flatMap((v) => v.deps);
  const severities: Record<string, number> = {};
  for (const dep of deps) {
    for (const v of dep.vulnerabilities) {
      severities[v.severity] = (severities[v.severity] ?? 0) + 1;
    }
  }
  return {
    deps: deps.length,
    vulns: Object.values(severities).reduce((n, x) => n + x, 0),
    severities,
    deprecated: deps.filter((d) => d.deprecated !== null).length,
    drift: {
      [SemverDrift.MAJOR]: deps.filter((d) => d.drift === SemverDrift.MAJOR).length,
      [SemverDrift.MINOR]: deps.filter((d) => d.drift === SemverDrift.MINOR).length,
      [SemverDrift.PATCH]: deps.filter((d) => d.drift === SemverDrift.PATCH).length,
    },
    vulnUnreachable: deps.filter((d) => d.vulnUnreachable).length,
    registryUnreachable: deps.filter((d) => d.registryUnreachable).length,
    suppressed: deps.reduce((n, d) => n + (d.suppressedVulnerabilities?.length ?? 0), 0),
  };
}

function verdict(visible: readonly Visible[]): string[] {
  const c = counts(visible);
  const projects = visible.length;
  const lines = [
    `${pc.bold(`npmtastic ${VERSION}`)} - ` +
      `${projects} project${projects !== 1 ? "s" : ""}, ` +
      `${c.deps} dependenc${c.deps !== 1 ? "ies" : "y"}`,
    "",
  ];

  if (c.vulns) {
    const detail = ordered(c.severities, ["critical", "high", "moderate", "low", "unknown"]);
    lines.push(
      `  ${pc.red(`${c.vulns} vulnerabilit${c.vulns !== 1 ? "ies" : "y"}`)}       ${detail}`,
    );
  }
  if (c.deprecated) {
    lines.push(`  ${pc.red(`${c.deprecated} deprecated package${c.deprecated !== 1 ? "s" : ""}`)}`);
  }
  if (c.suppressed) {
    lines.push(`  ${pc.dim(`${c.suppressed} suppressed (accepted risk)`)}`);
  }

  const major = c.drift[SemverDrift.MAJOR] ?? 0;
  const rest = [SemverDrift.MINOR, SemverDrift.PATCH]
    .filter((level) => c.drift[level])
    .map((level) => `${c.drift[level]} ${level}`)
    .join(", ");
  if (major || rest) {
    const lead = `  ${major} major drift`;
    lines.push(rest ? `${lead}         ${rest}` : lead);
  }

  if (c.registryUnreachable) {
    lines.push(
      `  ${pc.dim(`${c.registryUnreachable} package(s) unreachable on the npm registry - drift unknown`)}`,
    );
  }
  if (c.vulnUnreachable) {
    lines.push(
      `  ${pc.dim(`${c.vulnUnreachable} advisory lookup(s) unreachable - vulnerability status unknown, not clean`)}`,
    );
  }

  if (!c.vulns && !c.deprecated && !c.vulnUnreachable && !c.registryUnreachable) {
    lines.push(`  ${pc.green("no vulnerabilities or deprecated packages")}`);
  }
  return lines;
}

function findingLines(project: ProjectAudit, dep: DepAudit): string[] {
  const labels: string[] = [];
  if (dep.vulnerabilities.length > 0) labels.push(advisoryIds(dep));
  if (dep.deprecated) labels.push(pc.red("deprecated"));
  const licenseBit = dep.license ? ` | ${dep.license}` : "";
  const lines = [
    `  ${pc.red("!")} ${pc.bold(dep.dep.name)} ${current(dep)}   ${severityLabel(dep)}${labels.join("   ")}`,
    `      ${pc.dim(`${project.project.name} | ${origin(dep)}${declared(dep)}${licenseBit}`)}`,
  ];
  const target = remediation(dep);
  if (target) {
    lines.push(`      -> upgrade to ${target}`);
    if (dep.via && dep.via.length > 0) {
      lines.push(`      ${pc.dim(`reached through ${dep.via[0]}; the fix may need a parent bump`)}`);
    } else if (!dep.dep.direct) {
      lines.push(`      ${pc.dim("transitive; the fix may need a parent bump")}`);
    }
  }
  return lines;
}

function driftLines(visible: readonly Visible[]): string[] {
  const drifted = visible
    .flatMap((v) => v.deps.filter((d) => d.drift === SemverDrift.MAJOR && !isFinding(d)).map((d) => ({ project: v.project, dep: d })))
    .sort((a, b) => cmpRank(a.dep, b.dep));
  if (drifted.length === 0) return [];
  const lines = ["", `${pc.bold("Drift")} - ${drifted.length} major`];
  for (const { project, dep } of drifted) {
    lines.push(
      `  ${project.project.name}   ${dep.dep.name}   ${dep.dep.resolved ?? "-"} -> ${dep.latest ?? "-"}   ${pc.dim(origin(dep))}`,
    );
  }
  return lines;
}

function cleanLines(visible: readonly Visible[], opts: ReportOptions): string[] {
  const clean = visible.flatMap((v) =>
    v.deps
      .filter((d) => !isFinding(d) && d.drift !== SemverDrift.MAJOR)
      .map((d) => ({ project: v.project, dep: d })),
  );
  if (clean.length === 0) return [];
  if (!opts.showAll) {
    return ["", `${clean.length} dependencies are current (--all to list)`];
  }
  const lines = ["", `${pc.bold("Current")} - ${clean.length}`];
  for (const { project, dep } of [...clean].sort((a, b) => cmpRank(a.dep, b.dep))) {
    const posture = dep.pinStatus === PinStatus.PINNED ? "" : `   ${pc.dim(dep.pinStatus)}`;
    lines.push(
      `  ${project.project.name}   ${dep.dep.name} ${dep.dep.resolved ?? "-"}   ${pc.dim(origin(dep))}${posture}`,
    );
  }
  return lines;
}

export function renderReport(audits: readonly ProjectAudit[], opts: ReportOptions = {}): string {
  if (audits.length === 0) return "No Node projects audited.";

  const visible: Visible[] = audits.map((p) => ({
    project: p,
    deps: p.deps.filter((d) => keep(d, opts)),
  }));
  const lines = [...verdict(visible)];

  const findings = visible
    .flatMap((v) => v.deps.filter(isFinding).map((d) => ({ project: v.project, dep: d })))
    .sort((a, b) => cmpRank(a.dep, b.dep));
  const integrity = audits.flatMap((p) => (p.integrityFindings ?? []).map((f) => ({ project: p, finding: f })));

  if (findings.length > 0 || integrity.length > 0) {
    lines.push("", pc.bold("Findings"));
    for (const { project, dep } of findings) {
      lines.push(...findingLines(project, dep));
    }
    for (const { finding } of integrity) {
      const style = finding.kind === "mismatch" ? pc.red : finding.kind === "unexpected-source" ? pc.yellow : pc.dim;
      const version = finding.version ? ` ${finding.version}` : "";
      lines.push(`  ${style("!")} ${finding.name}${version}   ${style(finding.kind)}`);
      lines.push(`      ${pc.dim(finding.detail)}`);
    }
  }

  const checked = audits.filter((p) => p.integrityChecked);
  if (checked.length > 0 && !audits.some((p) => (p.integrityFindings ?? []).length > 0)) {
    lines.push(`  ${pc.green("integrity verified against the npm registry")}`);
  }

  lines.push(...driftLines(visible));
  lines.push(...cleanLines(visible, opts));
  return lines.join("\n");
}
