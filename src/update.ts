// SPDX-License-Identifier: AGPL-3.0-or-later
import semver from "semver";
import { PinStatus, type Dep, type Vulnerability, type PackageMeta, type UpdateChange } from "./models.js";
import { classifyPinStatus, pickLatest } from "./analysis.js";
import { computeMinSafeVersion } from "./vulns.js";

export interface PlannedEdit {
  name: string; // canonical
  rawName: string; // as written in package.json
  oldSpec: string; // current spec value
  newVersion: string; // exact target
  note: string | null;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Replace the value of "rawName": "oldSpec" in raw package.json text, changing only
// the value. Returns null if the entry is absent or ambiguous (appears != once).
function replaceSpec(text: string, rawName: string, oldSpec: string, newVersion: string): string | null {
  const re = new RegExp(`("${escapeRegExp(rawName)}"\\s*:\\s*")${escapeRegExp(oldSpec)}(")`, "g");
  const count = (text.match(re) ?? []).length;
  if (count !== 1) return null;
  return text.replace(re, `$1${newVersion}$2`);
}

export interface RewriteResult {
  text: string;
  applied: PlannedEdit[];
  skipped: PlannedEdit[];
}

export function rewriteManifestText(text: string, edits: readonly PlannedEdit[]): RewriteResult {
  let out = text;
  const applied: PlannedEdit[] = [];
  const skipped: PlannedEdit[] = [];
  for (const e of edits) {
    const next = replaceSpec(out, e.rawName, e.oldSpec, e.newVersion);
    if (next === null) {
      skipped.push(e);
      continue;
    }
    out = next;
    applied.push(e);
  }
  return { text: out, applied, skipped };
}

export function editToChange(e: PlannedEdit): UpdateChange {
  return { name: e.name, from: e.oldSpec, to: e.newVersion, note: e.note };
}

export interface TargetInput {
  dep: Dep;
  pin: boolean;
  latest: string | null;
  maxSatisfying: string | null;
  vulns: readonly Vulnerability[];
}

function vulnNote(vulns: readonly Vulnerability[]): string {
  const ids = vulns.slice(0, 2).map((v) => v.id).join(", ");
  return vulns.length > 2 ? `${ids}, +${vulns.length - 2}` : ids;
}

// Apply the CVE floor to a base version: returns [target, note].
function applyFloor(base: string, vulns: readonly Vulnerability[]): [string, string | null] {
  if (vulns.length === 0) return [base, null];
  const minSafe = computeMinSafeVersion(base, vulns);
  const ids = vulnNote(vulns);
  if (minSafe && semver.gt(minSafe, base)) return [minSafe, `CVE floor: ${ids}`];
  if (minSafe) return [base, `CVE: ${ids}`];
  return [base, `CVE (no fix known): ${ids}`];
}

export function resolveTarget(input: TargetInput): { newVersion: string; note: string | null } | null {
  const { dep, pin, latest, maxSatisfying, vulns } = input;
  const posture = classifyPinStatus(dep.range, dep.url);
  if (posture === PinStatus.URL) return null;

  if (!pin) {
    if (posture !== PinStatus.PINNED) return null;
    if (!latest || semver.valid(latest) === null) return null;
    let target = latest;
    let note: string | null = null;
    if (vulns.length > 0) {
      const [floored, n] = applyFloor(dep.range, vulns);
      if (semver.valid(floored) && semver.gt(floored, latest)) target = floored;
      note = n;
    }
    return target === dep.range ? null : { newVersion: target, note };
  }

  const baseRaw = dep.resolved && semver.valid(dep.resolved) ? dep.resolved : maxSatisfying;
  if (!baseRaw || semver.valid(baseRaw) === null) return null;
  const [target, note] = applyFloor(baseRaw, vulns);
  return dep.range === target ? null : { newVersion: target, note };
}

// Highest stable version of `meta` that satisfies `range` (pin mode without a lockfile).
export function highestSatisfying(meta: PackageMeta, range: string): string | null {
  const stable = meta.releases.map((r) => r.version).filter((v) => semver.valid(v) && semver.prerelease(v) === null);
  return semver.maxSatisfying(stable, range);
}
