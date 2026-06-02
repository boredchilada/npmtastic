// SPDX-License-Identifier: AGPL-3.0-or-later
import { readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { readText } from "./fsutil.js";
import { canonicalName } from "./parsing.js";

function readPkgMeta(dir: string): { name: string; version: string } | null {
  const p = join(dir, "package.json");
  if (!existsSync(p)) return null;
  try {
    const o = JSON.parse(readText(p)) as Record<string, unknown>;
    const name = typeof o["name"] === "string" ? (o["name"] as string) : null;
    const version = typeof o["version"] === "string" ? (o["version"] as string) : null;
    return name && version ? { name, version } : null;
  } catch {
    return null;
  }
}

export function enumerateNodeModules(
  root: string,
  selfName: string | null,
): { deps: Record<string, string>; warnings: string[] } {
  const nm = join(root, "node_modules");
  const warnings: string[] = [];
  const deps: Record<string, string> = {};
  let topEntries: string[];
  try {
    topEntries = readdirSync(nm, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
  } catch {
    return { deps, warnings };
  }
  const self = selfName ? canonicalName(selfName) : null;

  const consider = (dir: string): void => {
    const meta = readPkgMeta(dir);
    if (!meta) {
      warnings.push(`bootstrap: skipped ${dir} (no readable package.json)`);
      return;
    }
    if (self && canonicalName(meta.name) === self) return;
    deps[meta.name] = meta.version;
  };

  for (const name of topEntries) {
    if (name.startsWith(".")) continue; // .bin, .cache, .pnpm, .modules.yaml, etc.
    if (name.startsWith("@")) {
      let scoped: string[] = [];
      try {
        scoped = readdirSync(join(nm, name), { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
      } catch {
        continue;
      }
      for (const sub of scoped) consider(join(nm, name, sub));
    } else {
      consider(join(nm, name));
    }
  }

  if (Object.keys(deps).length > 0) {
    warnings.push("bootstrap: --from-node-modules output includes hoisted transitive dependencies; review and prune.");
  }
  return { deps, warnings };
}

export interface LockReconstruction {
  name: string | null;
  version: string | null;
  groups: Record<string, Record<string, string>>; // group -> { name: declaredRange }
  warnings: string[];
}

const GROUP_KEYS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
const NONINSTALLABLE = /^(workspace:|link:|catalog:|file:|portal:|git\+|git:|github:|gitlab:|bitbucket:|https?:)/i;

function sortKeys(obj: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of Object.keys(obj).sort((a, b) => a.localeCompare(b))) out[k] = obj[k]!;
  return out;
}

// Build from a per-group accessor. Returns null if zero installable deps remain (unusable root).
function buildReconstruction(
  name: string | null,
  version: string | null,
  getGroup: (key: string) => Record<string, unknown> | undefined,
): LockReconstruction | null {
  const warnings: string[] = [];
  const groups: Record<string, Record<string, string>> = {};
  let total = 0;
  for (const key of GROUP_KEYS) {
    const sec = getGroup(key);
    if (!sec || typeof sec !== "object") continue;
    const clean: Record<string, string> = {};
    for (const [n, specUnknown] of Object.entries(sec)) {
      if (typeof specUnknown !== "string") continue;
      const spec = specUnknown;
      if (NONINSTALLABLE.test(spec)) {
        warnings.push(`bootstrap: skipped "${n}" (${spec.split(":")[0]}: not installable in a standalone package.json)`);
        continue;
      }
      clean[n] = spec;
      total++;
    }
    if (Object.keys(clean).length > 0) groups[key] = sortKeys(clean);
  }
  if (total === 0) return null;
  return { name, version, groups, warnings };
}

export function reconstructFromNpmLock(text: string): LockReconstruction | null {
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return null;
  }
  const packages = raw["packages"];
  if (!packages || typeof packages !== "object") return null; // v1 / no packages map
  const root = (packages as Record<string, unknown>)[""];
  if (!root || typeof root !== "object") return null;
  const r = root as Record<string, unknown>;
  return buildReconstruction(
    typeof r["name"] === "string" ? (r["name"] as string) : null,
    typeof r["version"] === "string" ? (r["version"] as string) : null,
    (key) => (r[key] && typeof r[key] === "object" ? (r[key] as Record<string, unknown>) : undefined),
  );
}

export function reconstructFromPnpmLock(text: string): LockReconstruction | null {
  let raw: Record<string, unknown>;
  try {
    raw = parseYaml(text) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (!raw || typeof raw !== "object") return null;
  const importers = raw["importers"];
  const root = importers && typeof importers === "object" ? (importers as Record<string, unknown>)["."] : undefined;
  if (!root || typeof root !== "object") return null;
  const r = root as Record<string, unknown>;
  const accessor = (key: string): Record<string, unknown> | undefined => {
    const sec = r[key];
    if (!sec || typeof sec !== "object") return undefined;
    const flat: Record<string, unknown> = {};
    for (const [n, val] of Object.entries(sec as Record<string, unknown>)) {
      if (typeof val === "string") flat[n] = val;
      else if (val && typeof val === "object" && typeof (val as Record<string, unknown>)["specifier"] === "string") {
        flat[n] = (val as Record<string, unknown>)["specifier"];
      }
    }
    return flat;
  };
  return buildReconstruction(null, null, accessor);
}
