// SPDX-License-Identifier: AGPL-3.0-or-later
import { writeFileSync, mkdirSync, copyFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import semver from "semver";
import {
  PinStatus,
  type Dep,
  type Vulnerability,
  type PackageMeta,
  type UpdateChange,
  type Project,
  type UpdateResult,
} from "./models.js";
import { classifyPinStatus, pickLatest } from "./analysis.js";
import { computeMinSafeVersion, type VulnClient } from "./vulns.js";
import { readText } from "./fsutil.js";
import { collectDeps, canonicalName } from "./parsing.js";
import { loadSuppressions, isSuppressed } from "./suppressions.js";
import { testInstall } from "./exec.js";
import { warn, error, info } from "./logging.js";
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

export interface TargetInput {
  dep: Dep;
  pin: boolean;
  latest: string | null;
  maxSatisfying: string | null;
  vulns: readonly Vulnerability[];
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

export interface UpdateOptions {
  pin?: boolean;
  packages?: readonly string[];
  test?: boolean;
  dryRun?: boolean;
  installer?: (projectRoot: string, newManifestText: string) => Promise<boolean>;
}

function backupManifest(manifestPath: string, projectRoot: string, raw: string): string {
  const dir = join(projectRoot, ".npmtastic_backups");
  mkdirSync(dir, { recursive: true });
  const sha = createHash("sha256").update(raw).digest("hex").slice(0, 8);
  const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 15);
  const dest = join(dir, `package.json_${stamp}_${sha}.json`);
  copyFileSync(manifestPath, dest);
  return dest;
}

export async function updateProject(
  project: Project,
  registry: RegistryClient,
  vuln: VulnClient,
  opts: UpdateOptions,
): Promise<UpdateResult> {
  const manifestPath = join(project.root, "package.json");
  const empty: UpdateResult = { manifestPath, backupPath: null, changes: [], tested: false, testPassed: true };

  let rawText: string;
  try {
    rawText = readText(manifestPath);
    JSON.parse(rawText);
  } catch {
    error(`cannot update ${manifestPath}: not valid JSON`);
    return empty;
  }

  const pin = opts.pin ?? false;
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

  const pairs = deps
    .map((d) => ({ name: d.name, base: baseFor(d) }))
    .filter((x): x is { name: string; base: string } => x.base !== null && semver.valid(x.base) !== null)
    .map((x) => ({ name: x.name, version: x.base }));
  const vulnMap = await vuln.fetchFor(pairs);
  const suppressions = loadSuppressions(project.root);

  const edits: PlannedEdit[] = [];
  for (const d of deps) {
    const meta = metaMap.get(d.name) ?? null;
    const latest = meta ? pickLatest(meta, false).latest : null;
    const maxSat = meta ? highestSatisfying(meta, d.range) : null;
    const base = baseFor(d);
    const active =
      base && semver.valid(base)
        ? (vulnMap.get(`${d.name}@${base}`) ?? []).filter((v) => !isSuppressed(suppressions, v, d.name))
        : [];
    const t = resolveTarget({ dep: d, pin, latest, maxSatisfying: maxSat, vulns: active });
    if (t) edits.push({ name: d.name, rawName: d.rawName, oldSpec: d.range, newVersion: t.newVersion, note: t.note });
  }

  if (edits.length === 0) {
    info(`update: no changes for ${project.name}`);
    return empty;
  }

  const { text: newText, applied, skipped } = rewriteManifestText(rawText, edits);
  for (const s of skipped) warn(`update: could not locate "${s.rawName}" in ${manifestPath}; left unchanged`);
  const changes = applied.map(editToChange);

  // Safety: the surgical edit is textual — confirm it produced valid JSON and that
  // every applied edit actually landed on the right dependency before we touch disk.
  if (applied.length > 0) {
    let reparsed: Record<string, unknown>;
    try {
      reparsed = JSON.parse(newText) as Record<string, unknown>;
    } catch {
      error(`update: rewrite produced invalid JSON for ${manifestPath}; aborting (no changes written)`);
      return empty;
    }
    const GROUPS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
    for (const e of applied) {
      const landed = GROUPS.some((g) => {
        const sec = reparsed[g];
        return sec !== null && typeof sec === "object" && (sec as Record<string, unknown>)[e.rawName] === e.newVersion;
      });
      if (!landed) {
        error(`update: post-edit verification failed for "${e.rawName}" in ${manifestPath}; aborting (no changes written)`);
        return empty;
      }
    }
  }

  if (opts.dryRun) {
    return { manifestPath, backupPath: null, changes, tested: false, testPassed: true };
  }
  if (applied.length === 0) return empty;

  const backupPath = backupManifest(manifestPath, project.root, rawText);
  writeFileSync(manifestPath, newText);

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
  return { manifestPath, backupPath, changes, tested, testPassed };
}
