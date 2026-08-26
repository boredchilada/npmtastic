// SPDX-License-Identifier: AGPL-3.0-or-later
import { writeFileSync, copyFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import semver from "semver";
import {
  PinStatus,
  type Dep,
  type Vulnerability,
  type PackageMeta,
  type UpdateChange,
  type Project,
  type UpdateResult,
  type SkippedUpdate,
} from "./models.js";

import { classifyPinStatus, pickLatest } from "./analysis.js";
import { computeMinSafeVersion, type VulnClient } from "./vulns.js";
import { readText } from "./fsutil.js";
import { collectDeps, canonicalName } from "./parsing.js";
import { loadSuppressions, isSuppressed } from "./suppressions.js";
import { testInstall } from "./exec.js";
import { warn, error, info } from "./logging.js";
import { backupManifest } from "./backup.js";
import type { RegistryClient } from "./registry.js";

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

export type UpgradeLevel = "patch" | "minor" | "major";

export interface TargetInput {
  dep: Dep;
  pin: boolean;
  latest: string | null;
  maxSatisfying: string | null;
  vulns: readonly Vulnerability[];
  to?: UpgradeLevel;
  available?: readonly string[];
}


function vulnNote(vulns: readonly Vulnerability[]): string {
  const ids = vulns.slice(0, 2).map((v) => v.id).filter(Boolean).join(", ") || "unspecified";
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

/** Highest release within `level`, never below the advisory floor. */
export function selectTarget(
  current: string,
  latest: string,
  minSafe: string | null,
  level: UpgradeLevel,
  available?: readonly string[],
): string | null {
  const cur = semver.parse(current);
  if (!cur) return null;

  const parsed = (available ?? [])
    .map((v) => semver.parse(v))
    .filter((v): v is semver.SemVer => v !== null);
  const pool = parsed.length > 0 ? parsed : ([semver.parse(latest)].filter((v): v is semver.SemVer => v !== null));

  const bounded =
    level === "patch"
      ? pool.filter((v) => v.major === cur.major && v.minor === cur.minor)
      : level === "minor"
        ? pool.filter((v) => v.major === cur.major)
        : pool;

  const best = bounded.length > 0 ? bounded.reduce((a, b) => (semver.gt(b.version, a.version) ? b : a)) : null;
  const floor = minSafe ? semver.parse(minSafe) : null;
  if (floor !== null && (best === null || semver.lt(best.version, floor.version))) return minSafe;
  return best ? best.version : null;
}

export function resolveTarget(input: TargetInput): { newVersion: string; note: string | null } | null {
  const { dep, pin, latest, maxSatisfying, vulns } = input;
  const level = input.to ?? "major";
  const posture = classifyPinStatus(dep.range, dep.url);
  if (posture === PinStatus.URL) return null;

  if (!pin) {
    if (posture !== PinStatus.PINNED) return null;
    if (!latest || semver.valid(latest) === null) return null;
    const current = semver.valid(dep.range) ? dep.range : null;
    if (!current) return null;
    const minSafe = vulns.length > 0 ? computeMinSafeVersion(current, vulns) : null;
    const target = selectTarget(current, latest, minSafe, level, input.available);
    if (!target || target === dep.range) return null;
    const note = vulns.length > 0 ? applyFloor(current, vulns)[1] : null;
    return { newVersion: target, note };
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

function skipReason(dep: Dep): string | null {
  const spec = (dep.url ?? dep.range).trim();
  const lower = spec.toLowerCase();
  if (lower.startsWith("workspace:")) return "workspace";
  if (lower.startsWith("link:")) return "link";
  if (lower.startsWith("file:")) return "file";
  if (/^(git\+|git:|github:|gitlab:|bitbucket:)/i.test(spec)) return "git";
  if (/^https?:/i.test(spec)) return "url";
  if (/^(npm:|catalog:|portal:|patch:|jsr:)/i.test(spec)) return "non-version";
  if (dep.url) return "non-version";
  return null;
}

function skippedFrom(dep: Dep, reason: string, vulns: readonly Vulnerability[], current: string | null): SkippedUpdate {
  const minSafe = current && vulns.length > 0 ? computeMinSafeVersion(current, vulns) : null;
  return {
    name: dep.name,
    current: current ?? dep.range,
    minSafeVersion: minSafe,
    advisory: vulns[0]?.id ?? null,
    reason,
  };
}

function availableFrom(meta: PackageMeta | null): string[] {
  if (!meta) return [];
  const valid = meta.releases.filter((r) => semver.valid(r.version) && semver.prerelease(r.version) === null);
  const live = valid.filter((r) => !r.deprecated);
  return (live.length > 0 ? live : valid).map((r) => r.version);
}


export interface UpdateOptions {
  pin?: boolean;
  packages?: readonly string[];
  test?: boolean;
  dryRun?: boolean;
  installer?: (projectRoot: string, newManifestText: string) => Promise<boolean>;
  noConfig?: boolean;
  to?: UpgradeLevel;
  applyCveFloor?: boolean;
  /** Isolated test install already uses the OS temp dir; accepted for CLI parity. */
  tempTestDir?: boolean;
}

function atomicWrite(filePath: string, content: string): void {
  const tmp = filePath + `.npmtastic_tmp_${Date.now()}`;
  writeFileSync(tmp, content, "utf-8");
  renameSync(tmp, filePath);
}

export async function updateProject(
  project: Project,
  registry: RegistryClient,
  vuln: VulnClient,
  opts: UpdateOptions,
): Promise<UpdateResult> {
  const manifestPath = join(project.root, "package.json");
  const empty: UpdateResult = { manifestPath, backupPath: null, changes: [], tested: false, testPassed: true, skipped: [] };


  let rawText: string;
  try {
    rawText = readText(manifestPath);
    JSON.parse(rawText);
  } catch {
    error(`cannot update ${manifestPath}: not valid JSON`);
    return empty;
  }

  const pin = opts.pin ?? false;
  const applyCveFloor = opts.applyCveFloor !== false;
  const only = opts.packages ? new Set(opts.packages.map(canonicalName)) : null;
  const deps = collectDeps(project).filter((d) => d.direct && (!only || only.has(d.name)));
  if (deps.length === 0) {
    info(`update: nothing to do for ${project.name}`);
    return empty;
  }

  const metaMap = await registry.fetchMany(deps.map((d) => d.name));

  const baseFor = (d: Dep): string | null => {
    if (pin) {
      const meta = metaMap.get(d.name) ?? null;
      const ms = meta ? highestSatisfying(meta, d.range) : null;
      return d.resolved && semver.valid(d.resolved) ? d.resolved : ms;
    }
    return semver.valid(d.range) ? d.range : null;
  };

  const pairs: Array<{ name: string; version: string }> = deps
    .map((d) => ({ name: d.name, base: baseFor(d) }))
    .filter((x): x is { name: string; base: string } => x.base !== null && semver.valid(x.base) !== null)
    .map((x) => ({ name: x.name, version: x.base }));
  const extraPairs = deps
    .filter((d) => skipReason(d) !== null && d.resolved !== null && semver.valid(d.resolved) !== null)
    .map((d) => ({ name: d.name, version: d.resolved as string }));
  const pairKeys = new Set(pairs.map((p) => `${p.name}@${p.version}`));
  for (const extra of extraPairs) {
    if (!pairKeys.has(`${extra.name}@${extra.version}`)) pairs.push(extra);
  }

  const vulnMap = applyCveFloor ? await vuln.fetchFor(pairs) : new Map<string, Vulnerability[]>();
  const suppressions = opts.noConfig || !applyCveFloor ? [] : loadSuppressions(project.root);
  if (registry.offlineMisses.length > 0 || vuln.offlineMisses.length > 0) {
    return empty;
  }

  const level = opts.to ?? "major";
  const edits: PlannedEdit[] = [];
  const skipped: SkippedUpdate[] = [];
  for (const d of deps) {
    const meta = metaMap.get(d.name) ?? null;
    const latest = meta ? pickLatest(meta, false).latest : null;
    const maxSat = meta ? highestSatisfying(meta, d.range) : null;
    const base = baseFor(d);
    const resolvedBase = d.resolved && semver.valid(d.resolved) ? d.resolved : base;
    const active =
      resolvedBase && semver.valid(resolvedBase)
        ? (vulnMap.get(`${d.name}@${resolvedBase}`) ?? []).filter((v) => !isSuppressed(suppressions, v, d.name))
        : [];
    const reason = skipReason(d);
    if (reason) {
      skipped.push(skippedFrom(d, reason, active, resolvedBase));
      continue;
    }
    const t = resolveTarget({
      dep: d,
      pin,
      latest,
      maxSatisfying: maxSat,
      vulns: active,
      to: level,
      available: availableFrom(meta),
    });
    if (t) {
      edits.push({ name: d.name, rawName: d.rawName, oldSpec: d.range, newVersion: t.newVersion, note: t.note });
      continue;
    }
    if (active.length > 0) {
      const posture = classifyPinStatus(d.range, d.url);
      skipped.push(skippedFrom(d, !pin && posture !== PinStatus.PINNED ? "not-eligible" : "up-to-date", active, resolvedBase));
    }
  }

  if (edits.length === 0) {
    info(`update: no changes for ${project.name}`);
    return { ...empty, skipped };
  }


  const rewritten = rewriteManifestText(rawText, edits);
  const newText = rewritten.text;
  const applied = rewritten.applied;
  for (const s of rewritten.skipped) {
    warn(`update: could not locate "${s.rawName}" in ${manifestPath}; left unchanged`);
    skipped.push({
      name: s.name,
      current: s.oldSpec,
      minSafeVersion: null,
      advisory: s.note && s.note.includes("CVE") ? s.note : null,
      reason: "not-found",
    });
  }

  const changes = applied.map(editToChange);


  // Safety: the surgical edit is textual — confirm it produced valid JSON and that
  // every applied edit actually landed on the right dependency before we touch disk.
  if (applied.length > 0) {
    let reparsed: Record<string, unknown>;
    try {
      reparsed = JSON.parse(newText) as Record<string, unknown>;
    } catch {
      error(`update: rewrite produced invalid JSON for ${manifestPath}; aborting (no changes written)`);
      return { ...empty, skipped };
    }
    const GROUPS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
    for (const e of applied) {
      const landed = GROUPS.some((g) => {
        const sec = reparsed[g];
        return sec !== null && typeof sec === "object" && (sec as Record<string, unknown>)[e.rawName] === e.newVersion;
      });
      if (!landed) {
        error(`update: post-edit verification failed for "${e.rawName}" in ${manifestPath}; aborting (no changes written)`);
        return { ...empty, skipped };

      }
    }
  }

  if (opts.dryRun) {
    return { manifestPath, backupPath: null, changes, tested: false, testPassed: true, skipped };
  }
  if (applied.length === 0) return { ...empty, skipped };


  const backupPath = backupManifest(manifestPath, project.root, rawText);
  atomicWrite(manifestPath, newText);

  let tested = false;
  let testPassed = true;
  if (opts.test !== false) {
    tested = true;
    const install = opts.installer ?? testInstall;
    testPassed = await install(project.root, newText);
    if (!testPassed) {
      try {
        copyFileSync(backupPath, manifestPath);
        warn(`update: test install failed; restored ${manifestPath} from ${backupPath}`);
      } catch (e) {
        error(
          `update: test install failed AND automatic restore failed — ${manifestPath} is left MODIFIED. ` +
            `Restore it manually from ${backupPath}: ${(e as Error).message}`,
        );
      }
    }
  }
  return { manifestPath, backupPath, changes, tested, testPassed, skipped };

}
