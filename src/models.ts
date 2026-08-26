// SPDX-License-Identifier: AGPL-3.0-or-later

export enum PinStatus {
  PINNED = "pinned",
  COMPATIBLE = "compatible",
  RANGE = "range",
  FLOOR = "floor",
  UNPINNED = "unpinned",
  URL = "url",
}

/**
 * Drift differs from piptastic: npm semver has no epoch/build precedence,
 * so EPOCH/BUILD are dropped and PRERELEASE is added.
 * Order for gates: NONE < PRERELEASE < PATCH < MINOR < MAJOR. UNKNOWN is unordered.
 */
export enum SemverDrift {
  NONE = "none",
  PRERELEASE = "prerelease",
  PATCH = "patch",
  MINOR = "minor",
  MAJOR = "major",
  UNKNOWN = "unknown",
}

export enum DepSourceKind {
  MANIFEST = "manifest",
  NPM_LOCK = "npm-lock",
  PNPM_LOCK = "pnpm-lock",
  YARN_LOCK = "yarn-lock",
}

export const DRIFT_ORDER: readonly SemverDrift[] = [
  SemverDrift.NONE,
  SemverDrift.PRERELEASE,
  SemverDrift.PATCH,
  SemverDrift.MINOR,
  SemverDrift.MAJOR,
];

export interface DepSource {
  readonly kind: DepSourceKind;
  readonly path: string;
  readonly group: string; // "default" | "dev" | "peer" | "optional" | lockfile group
}

export interface Dep {
  readonly name: string; // canonical: lowercased; scope (@scope/) preserved
  readonly rawName: string;
  readonly range: string; // raw range/spec string from the source
  readonly resolved: string | null; // exact version when known (lockfiles); else null
  readonly source: DepSource;
  readonly url: string | null; // set when the spec is a url/git/file/workspace protocol
  readonly direct: boolean;
}

export interface Project {
  readonly root: string;
  readonly name: string;
  readonly sources: readonly DepSource[];
  readonly nodeVersion: string | null; // from engines.node, when present
}

export function makeDep(d: Dep): Dep {
  Object.freeze(d.source);
  return Object.freeze({ ...d });
}

export function makeProject(p: Project): Project {
  p.sources.forEach((s) => Object.freeze(s));
  return Object.freeze({ ...p, sources: Object.freeze([...p.sources]) });
}

export interface ReleaseInfo {
  readonly version: string;
  readonly deprecated: string | null;
  readonly enginesNode: string | null;
  readonly uploadTime: string | null; // ISO 8601
  readonly license: string | null;
  readonly integrity: string | null;

}

export interface PackageMeta {
  readonly name: string;
  readonly distTagLatest: string | null;
  readonly releases: readonly ReleaseInfo[];
}

export interface Vulnerability {
  readonly id: string;
  readonly aliases: readonly string[];
  readonly summary: string | null;
  readonly fixedVersions: readonly string[];
  readonly severity: string; // critical | high | moderate | low | unknown
  readonly cvss: string | null;
  readonly cweIds: readonly string[];
  readonly references: readonly string[];
  readonly published: string | null;
}

export interface IntegrityFinding {
  readonly name: string;
  readonly version: string;
  readonly kind: "mismatch" | "unexpected-source" | "unverifiable";
  readonly detail: string;
}

export interface LockPackage {
  readonly name: string;
  readonly version: string;
  readonly path: string;
  readonly integrity: string | null;
  readonly resolved: string | null;
  readonly dependencies: Readonly<Record<string, string>>;
  readonly link: boolean;
}


export interface DepAudit {
  readonly dep: Dep;
  readonly latest: string | null;
  readonly latestIncludingPrereleases: string | null;
  readonly drift: SemverDrift;
  readonly pinStatus: PinStatus;
  readonly deprecated: string | null; // deprecation message of the relevant version, else null
  readonly vulnerabilities: readonly Vulnerability[];
  readonly suppressedVulnerabilities?: readonly Vulnerability[];
  readonly minSafeVersion: string | null;
  readonly latestReleaseDate: string | null; // ISO 8601
  readonly latestReleaseAgeDays: number | null;
  readonly currentReleaseDate: string | null;
  readonly daysBehind: number | null;
  readonly license: string | null;
  readonly via: readonly string[];
  readonly available: readonly string[];

  readonly warnings: readonly string[];
  readonly registryUnreachable?: boolean;
  readonly vulnUnreachable?: boolean;
}

export interface ProjectAudit {
  readonly project: Project;
  readonly deps: readonly DepAudit[];
  readonly pinningScore: number | null;
  readonly driftSummary: Readonly<Record<string, number>>;
  readonly deprecatedCount: number;
  readonly registryUnreachable: number;
  readonly vulnCount: number;
  readonly vulnUnreachable: number;
  readonly suppressedCount: number;
  readonly integrityChecked: boolean;
  readonly integrityFindings: readonly IntegrityFinding[];

}

export function makeDepAudit(d: DepAudit): DepAudit {
  return Object.freeze({
    ...d,
    currentReleaseDate: d.currentReleaseDate ?? null,
    daysBehind: d.daysBehind ?? null,
    license: d.license ?? null,
    via: Object.freeze([...(d.via ?? [])]),
    available: Object.freeze([...(d.available ?? [])]),
    vulnerabilities: Object.freeze([...d.vulnerabilities]),
    suppressedVulnerabilities: Object.freeze([...(d.suppressedVulnerabilities ?? [])]),
    warnings: Object.freeze([...d.warnings]),
  });
}


export function makeProjectAudit(p: ProjectAudit): ProjectAudit {
  return Object.freeze({
    ...p,
    integrityChecked: p.integrityChecked ?? false,
    integrityFindings: Object.freeze([...(p.integrityFindings ?? [])]),
    deps: Object.freeze([...p.deps]),
    driftSummary: Object.freeze({ ...p.driftSummary }),
  });
}


export interface UpdateChange {
  readonly name: string; // canonical
  readonly from: string; // old spec
  readonly to: string; // new exact version
  readonly note: string | null; // e.g. "CVE floor: GHSA-..."
}

export interface SkippedUpdate {
  readonly name: string;
  readonly current: string | null;
  readonly minSafeVersion: string | null;
  readonly advisory: string | null;
  readonly reason: string;
}


export interface UpdateResult {
  readonly manifestPath: string;
  readonly backupPath: string | null;
  readonly changes: readonly UpdateChange[];
  readonly tested: boolean;
  readonly testPassed: boolean;
  readonly skipped: readonly SkippedUpdate[];

}

export interface BootstrapResult {
  readonly manifest: Record<string, unknown>;
  readonly source: "npm-lock" | "pnpm-lock" | "node-modules";
  readonly warnings: readonly string[];
}
