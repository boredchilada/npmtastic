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
