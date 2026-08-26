// SPDX-License-Identifier: AGPL-3.0-or-later
import { PinStatus, SemverDrift, type ProjectAudit } from "./models.js";

export const STATS_SCHEMA_VERSION = 1;

export interface StatsReport {
  readonly kind: "stats";
  readonly schemaVersion: number;
  readonly totals: {
    readonly projects: number;
    readonly deps: number;
    readonly cves: number;
    readonly deprecated: number;
  };
  readonly topPackages: readonly { readonly name: string; readonly count: number }[];
  readonly fragmented: readonly { readonly name: string; readonly versions: readonly string[] }[];
  readonly deprecated: readonly { readonly project: string; readonly package: string; readonly version: string }[];
  readonly licenses: readonly { readonly license: string; readonly count: number }[];
  readonly driftHistogram: Readonly<Record<string, number>>;
  readonly pinHistogram: Readonly<Record<string, number>>;
}

export function buildStats(audits: readonly ProjectAudit[], top: number): StatsReport {
  const counts = new Map<string, number>();
  const versions = new Map<string, string[]>();
  const deprecated: { project: string; package: string; version: string }[] = [];
  const drift: Record<string, number> = {};
  const pins: Record<string, number> = {};
  const licenses = new Map<string, number>();
  let deps = 0;

  for (const p of audits) {
    for (const d of p.deps) {
      deps += 1;
      counts.set(d.dep.name, (counts.get(d.dep.name) ?? 0) + 1);
      const current = d.dep.resolved;
      if (current) {
        const vs = versions.get(d.dep.name) ?? [];
        if (!vs.includes(current)) {
          vs.push(current);
          versions.set(d.dep.name, vs);
        }
      }
      if (d.deprecated !== null) {
        deprecated.push({ project: p.project.name, package: d.dep.name, version: current ?? "" });
      }
      drift[d.drift] = (drift[d.drift] ?? 0) + 1;
      pins[d.pinStatus] = (pins[d.pinStatus] ?? 0) + 1;
      if (d.license) licenses.set(d.license, (licenses.get(d.license) ?? 0) + 1);
    }
  }

  const topPackages = [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, top)
    .map(([name, count]) => ({ name, count }));

  const fragmented = [...versions.entries()]
    .filter(([, vs]) => vs.length > 1)
    .map(([name, vs]) => ({ name, versions: [...vs].sort((a, b) => a.localeCompare(b)) }))
    .sort((a, b) => b.versions.length - a.versions.length || a.name.localeCompare(b.name));

  const licensesSorted = [...licenses.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([license, count]) => ({ license, count }));

  const driftHistogram: Record<string, number> = {};
  for (const k of [
    SemverDrift.NONE,
    SemverDrift.PRERELEASE,
    SemverDrift.PATCH,
    SemverDrift.MINOR,
    SemverDrift.MAJOR,
    SemverDrift.UNKNOWN,
  ]) {
    driftHistogram[k] = drift[k] ?? 0;
  }

  const pinHistogram: Record<string, number> = {};
  for (const s of Object.values(PinStatus)) {
    pinHistogram[s] = pins[s] ?? 0;
  }

  return {
    kind: "stats",
    schemaVersion: STATS_SCHEMA_VERSION,
    totals: {
      projects: audits.length,
      deps,
      cves: audits.reduce((n, p) => n + p.vulnCount, 0),
      deprecated: deprecated.length,
    },
    topPackages,
    fragmented,
    deprecated,
    licenses: licensesSorted,
    driftHistogram,
    pinHistogram,
  };
}

export function renderStats(report: StatsReport): string {
  const t = report.totals;
  const lines: string[] = [
    `${t.projects} project(s) | ${t.deps} dep(s) | ${t.cves} CVE(s) | ${t.deprecated} deprecated`,
    "",
    "Most-depended-upon packages:",
  ];
  if (report.topPackages.length === 0) lines.push("  (none)");
  for (const item of report.topPackages) {
    lines.push(`  ${String(item.count).padStart(4)}  ${item.name}`);
  }

  lines.push("", "Version fragmentation:");
  if (report.fragmented.length === 0) lines.push("  (none)");
  for (const item of report.fragmented) {
    lines.push(`  ${item.name}: ${item.versions.join(", ")}`);
  }

  lines.push("", "Deprecated pins still declared:");
  if (report.deprecated.length === 0) lines.push("  (none)");
  for (const item of report.deprecated) {
    lines.push(`  ${item.project}: ${item.package} ${item.version}`);
  }

  lines.push("", "Licenses:");
  if (report.licenses.length === 0) lines.push("  (none)");
  for (const item of report.licenses) {
    lines.push(`  ${String(item.count).padStart(4)}  ${item.license}`);
  }

  const d = report.driftHistogram;
  lines.push(
    "",
    `Drift: none ${d["none"] ?? 0} / patch ${d["patch"] ?? 0} / minor ${d["minor"] ?? 0} / major ${d["major"] ?? 0} / prerelease ${d["prerelease"] ?? 0} / unknown ${d["unknown"] ?? 0}`,
  );
  const pin = report.pinHistogram;
  lines.push("Pin posture: " + Object.entries(pin).map(([k, v]) => `${k} ${v}`).join("  "));
  return lines.join("\n");
}
