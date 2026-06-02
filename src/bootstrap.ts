// SPDX-License-Identifier: AGPL-3.0-or-later
import { readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
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
