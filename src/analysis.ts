// SPDX-License-Identifier: AGPL-3.0-or-later
import semver from "semver";
import { PinStatus, SemverDrift } from "./models.js";
import type { PackageMeta, ReleaseInfo } from "./models.js";
import { collectDeps } from "./parsing.js";
import { computeMinSafeVersion } from "./vulns.js";
import { loadSuppressions, isSuppressed } from "./suppressions.js";
import { makeDepAudit, makeProjectAudit } from "./models.js";
import type { Dep, DepAudit, Project, ProjectAudit } from "./models.js";
import type { RegistryClient } from "./registry.js";
import type { VulnClient } from "./vulns.js";

export function classifyPinStatus(range: string, url: string | null): PinStatus {
  if (url) return PinStatus.URL;
  const r = range.trim();
  if (r === "" || r === "*" || r === "x" || r === "X" || r.toLowerCase() === "latest") {
    return PinStatus.UNPINNED;
  }
  if (r.startsWith("^") || r.startsWith("~")) return PinStatus.COMPATIBLE;
  if (semver.valid(r) !== null) return PinStatus.PINNED;
  let parsed: InstanceType<typeof semver.Range>;
  try {
    parsed = new semver.Range(r);
  } catch {
    return PinStatus.RANGE;
  }
  const ops = parsed.set.flat().map((c) => c.operator);
  const hasLower = ops.some((o) => o === ">" || o === ">=");
  const hasUpper = ops.some((o) => o === "<" || o === "<=");
  if (hasLower && !hasUpper) return PinStatus.FLOOR;
  return PinStatus.RANGE;
}

export function classifyDrift(current: string | null, latest: string | null): SemverDrift {
  if (!current || !latest) return SemverDrift.UNKNOWN;
  const cv = semver.valid(current);
  const lv = semver.valid(latest);
  if (!cv || !lv) return SemverDrift.UNKNOWN;
  if (semver.eq(cv, lv)) return SemverDrift.NONE;
  // Same release core (major.minor.patch) but differing prerelease tags is a
  // prerelease-level move — semver.diff reports this as "patch", and the
  // current-ahead shortcut below would otherwise swallow it as NONE.
  const cp = semver.parse(cv);
  const lp = semver.parse(lv);
  if (
    cp !== null &&
    lp !== null &&
    cp.major === lp.major &&
    cp.minor === lp.minor &&
    cp.patch === lp.patch &&
    (cp.prerelease.length > 0 || lp.prerelease.length > 0)
  ) {
    return SemverDrift.PRERELEASE;
  }
  if (semver.gt(cv, lv)) return SemverDrift.NONE; // current ahead of latest stable
  const d = semver.diff(cv, lv);
  switch (d) {
    case "major":
    case "premajor":
      return SemverDrift.MAJOR;
    case "minor":
    case "preminor":
      return SemverDrift.MINOR;
    case "patch":
    case "prepatch":
      return SemverDrift.PATCH;
    case "prerelease":
      return SemverDrift.PRERELEASE;
    default:
      return SemverDrift.NONE;
  }
}

export interface LatestPick {
  latest: string | null;
  latestIncludingPrereleases: string | null;
  latestReleaseDate: string | null;
}

function maxRelease(releases: readonly ReleaseInfo[]): ReleaseInfo | null {
  let best: ReleaseInfo | null = null;
  for (const r of releases) {
    if (semver.valid(r.version) === null) continue;
    if (best === null || semver.gt(r.version, best.version)) best = r;
  }
  return best;
}

export function pickLatest(meta: PackageMeta, includePrereleases: boolean): LatestPick {
  const valid = meta.releases.filter((r) => semver.valid(r.version) !== null);
  const stable = valid.filter((r) => semver.prerelease(r.version) === null);
  const latestStable = maxRelease(stable.filter((r) => !r.deprecated)) ?? maxRelease(stable);
  const latestIncl = maxRelease(valid.filter((r) => !r.deprecated)) ?? maxRelease(valid);
  const effective = includePrereleases ? latestIncl : latestStable;
  return {
    latest: latestStable?.version ?? null,
    latestIncludingPrereleases: latestIncl?.version ?? null,
    latestReleaseDate: effective?.uploadTime ?? null,
  };
}

export interface AuditOptions {
  readonly includePrereleases?: boolean;
}

function currentVersion(dep: Dep): string | null {
  if (dep.resolved && semver.valid(dep.resolved)) return dep.resolved;
  if (semver.valid(dep.range)) return dep.range;
  return null;
}

function ageDays(iso: string | null): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((Date.now() - t) / 86_400_000);
}

function emptyDriftSummary(): Record<string, number> {
  return {
    [SemverDrift.NONE]: 0,
    [SemverDrift.PRERELEASE]: 0,
    [SemverDrift.PATCH]: 0,
    [SemverDrift.MINOR]: 0,
    [SemverDrift.MAJOR]: 0,
    [SemverDrift.UNKNOWN]: 0,
  };
}

export async function auditProject(
  project: Project,
  registry: RegistryClient,
  vuln: VulnClient,
  opts: AuditOptions,
): Promise<ProjectAudit> {
  const includePre = opts.includePrereleases ?? false;
  const deps = collectDeps(project);
  const suppressionRules = loadSuppressions(project.root);

  const metaMap = await registry.fetchMany(deps.map((d) => d.name));
  const pairs = deps
    .filter((d) => d.resolved !== null && semver.valid(d.resolved) !== null)
    .map((d) => ({ name: d.name, version: d.resolved as string }));
  const vulnMap = await vuln.fetchFor(pairs);

  const depAudits: DepAudit[] = deps.map((d) => {
    const meta = metaMap.get(d.name) ?? null;
    const pick = meta
      ? pickLatest(meta, includePre)
      : { latest: null, latestIncludingPrereleases: null, latestReleaseDate: null };
    const effectiveLatest = includePre ? pick.latestIncludingPrereleases : pick.latest;
    const current = currentVersion(d);
    const drift = meta ? classifyDrift(current, effectiveLatest) : SemverDrift.UNKNOWN;
    const pinStatus = classifyPinStatus(d.range, d.url);
    const deprecated =
      meta && current ? (meta.releases.find((r) => r.version === current)?.deprecated ?? null) : null;
    const key = d.resolved && semver.valid(d.resolved) ? `${d.name}@${d.resolved}` : null;
    const allVulns = key ? (vulnMap.get(key) ?? []) : [];
    const vulnerabilities = allVulns.filter((v) => !isSuppressed(suppressionRules, v, d.name));
    const suppressedVulnerabilities = allVulns.filter((v) => isSuppressed(suppressionRules, v, d.name));
    const minSafeVersion =
      key && vulnerabilities.length > 0 ? computeMinSafeVersion(d.resolved as string, vulnerabilities) : null;

    return makeDepAudit({
      dep: d,
      latest: pick.latest,
      latestIncludingPrereleases: pick.latestIncludingPrereleases,
      drift,
      pinStatus,
      deprecated,
      vulnerabilities,
      suppressedVulnerabilities,
      minSafeVersion,
      latestReleaseDate: pick.latestReleaseDate,
      latestReleaseAgeDays: ageDays(pick.latestReleaseDate),
      warnings: [],
    });
  });

  const driftSummary = emptyDriftSummary();
  for (const a of depAudits) driftSummary[a.drift] = (driftSummary[a.drift] ?? 0) + 1;

  const directNonUrl = depAudits.filter((a) => a.dep.direct && a.pinStatus !== PinStatus.URL);
  const pinningScore =
    directNonUrl.length === 0
      ? null
      : directNonUrl.filter((a) => a.pinStatus === PinStatus.PINNED || a.pinStatus === PinStatus.COMPATIBLE).length /
        directNonUrl.length;

  const vulnCount = depAudits.reduce((n, a) => n + a.vulnerabilities.length, 0);
  const suppressedCount = depAudits.reduce((n, a) => n + (a.suppressedVulnerabilities?.length ?? 0), 0);
  const deprecatedCount = depAudits.filter((a) => a.deprecated !== null).length;
  const registryUnreachable = deps.filter((d) => !metaMap.has(d.name)).length;
  const vulnUnreachable = pairs.filter((p) => vuln.unreachable.has(`${p.name}@${p.version}`)).length;

  return makeProjectAudit({
    project,
    deps: depAudits,
    pinningScore,
    driftSummary,
    deprecatedCount,
    registryUnreachable,
    vulnCount,
    vulnUnreachable,
    suppressedCount,
  });
}
