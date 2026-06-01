// SPDX-License-Identifier: AGPL-3.0-or-later
import semver from "semver";
import { PinStatus, SemverDrift } from "./models.js";

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
