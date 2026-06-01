// SPDX-License-Identifier: AGPL-3.0-or-later
import pc from "picocolors";
import { SemverDrift, PinStatus, type ProjectAudit, type DepAudit } from "../models.js";

export type View = "tree" | "table" | "summary";

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function colorDrift(d: SemverDrift): string {
  switch (d) {
    case SemverDrift.MAJOR:
      return pc.red(d);
    case SemverDrift.MINOR:
      return pc.yellow(d);
    case SemverDrift.PATCH:
      return pc.cyan(d);
    case SemverDrift.NONE:
      return pc.green(d);
    default:
      return pc.dim(d);
  }
}

function cveCell(a: DepAudit): string {
  if (a.vulnerabilities.length === 0) return pc.green("-");
  const fix = a.minSafeVersion ? `->${a.minSafeVersion}` : "";
  return pc.red(`${a.vulnerabilities.length}${fix}`);
}

function ageCell(a: DepAudit): string {
  return a.latestReleaseAgeDays === null ? "-" : `${a.latestReleaseAgeDays}d`;
}

function projectHeader(p: ProjectAudit): string {
  const score = p.pinningScore === null ? "n/a" : `${Math.round(p.pinningScore * 100)}%`;
  const direct = p.deps.filter((d) => d.dep.direct).length;
  const cve = p.vulnCount > 0 ? pc.red(`${p.vulnCount} CVE`) : pc.green("0 CVE");
  return pc.bold(p.project.name) + pc.dim(`  (${p.deps.length} deps, ${direct} direct, pinning ${score}, `) + cve + pc.dim(")");
}

// pad a possibly-colored cell to a visible width (accounts for ANSI escape length)
function padColored(colored: string, visible: string, width: number): string {
  const extra = colored.length - visible.length;
  return pad(colored, width + extra);
}

function renderTable(p: ProjectAudit): string {
  const lines: string[] = [projectHeader(p)];
  lines.push(pc.dim("  " + pad("PACKAGE", 28) + pad("POSTURE", 12) + pad("CURRENT", 14) + pad("LATEST", 14) + pad("DRIFT", 12) + pad("CVE", 12) + "AGE"));
  const sorted = [...p.deps].sort((a, b) => (a.dep.direct === b.dep.direct ? a.dep.name.localeCompare(b.dep.name) : a.dep.direct ? -1 : 1));
  for (const a of sorted) {
    lines.push(
      "  " +
        pad(a.dep.name, 28) +
        pad(a.pinStatus, 12) +
        pad(a.dep.resolved ?? a.dep.range, 14) +
        pad(a.latest ?? "-", 14) +
        padColored(colorDrift(a.drift), a.drift, 12) +
        padColored(cveCell(a), cveCell(a).replace(/\[[0-9;]*m/g, ""), 12) +
        ageCell(a),
    );
  }
  return lines.join("\n");
}

function renderSummary(audits: readonly ProjectAudit[]): string {
  const lines: string[] = [
    pc.dim(pad("PROJECT", 28) + pad("DEPS", 7) + pad("DIRECT", 8) + pad("PINNING", 9) + pad("PATCH", 7) + pad("MINOR", 7) + pad("MAJOR", 7) + pad("CVE", 6) + "DEP"),
  ];
  for (const p of audits) {
    const score = p.pinningScore === null ? "n/a" : `${Math.round(p.pinningScore * 100)}%`;
    const direct = p.deps.filter((d) => d.dep.direct).length;
    const cveStr = p.vulnCount > 0 ? pc.red(String(p.vulnCount)) : "0";
    lines.push(
      pad(p.project.name, 28) +
        pad(String(p.deps.length), 7) +
        pad(String(direct), 8) +
        pad(score, 9) +
        pad(String(p.driftSummary[SemverDrift.PATCH] ?? 0), 7) +
        pad(String(p.driftSummary[SemverDrift.MINOR] ?? 0), 7) +
        pad(String(p.driftSummary[SemverDrift.MAJOR] ?? 0), 7) +
        padColored(cveStr, String(p.vulnCount), 6) +
        String(p.deprecatedCount),
    );
  }
  return lines.join("\n");
}

function renderTree(p: ProjectAudit): string {
  const lines: string[] = [projectHeader(p)];
  const sorted = [...p.deps].sort((a, b) => a.dep.name.localeCompare(b.dep.name));
  for (const a of sorted) {
    const drift =
      a.drift === SemverDrift.NONE || a.drift === SemverDrift.UNKNOWN
        ? ""
        : `  ${a.dep.resolved ?? a.dep.range} -> ${a.latest ?? "?"} (${colorDrift(a.drift)})`;
    const cve = a.vulnerabilities.length > 0 ? "  " + cveCell(a) : "";
    lines.push(`  - ${a.dep.name}  ${pc.dim(a.pinStatus)}${drift}${cve}`);
  }
  return lines.join("\n");
}

function aggregateFooter(audits: readonly ProjectAudit[]): string {
  const projects = audits.length;
  const deps = audits.reduce((n, p) => n + p.deps.length, 0);
  const cve = audits.reduce((n, p) => n + p.vulnCount, 0);
  const dep = audits.reduce((n, p) => n + p.deprecatedCount, 0);
  const parts = [`${projects} project(s)`, `${deps} dep(s)`];
  if (cve > 0) parts.push(pc.red(`${cve} CVE`));
  if (dep > 0) parts.push(pc.yellow(`${dep} deprecated`));
  return pc.dim("- " + parts.join(", "));
}

export function renderTerminal(audits: readonly ProjectAudit[], view: View): string {
  let body: string;
  if (view === "summary") body = renderSummary(audits);
  else if (view === "table") body = audits.map(renderTable).join("\n\n");
  else body = audits.map(renderTree).join("\n\n");
  if (audits.length > 1) body += "\n\n" + aggregateFooter(audits);
  return body;
}
