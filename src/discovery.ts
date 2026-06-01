// SPDX-License-Identifier: AGPL-3.0-or-later
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, basename } from "node:path";
import { DepSourceKind, makeProject, type DepSource, type Project } from "./models.js";

const ALWAYS_SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage"]);

const GROUP_KEYS: ReadonlyArray<[string, string]> = [
  ["dependencies", "default"],
  ["devDependencies", "dev"],
  ["peerDependencies", "peer"],
  ["optionalDependencies", "optional"],
];

const LOCK_FILES: ReadonlyArray<[string, DepSourceKind]> = [
  ["package-lock.json", DepSourceKind.NPM_LOCK],
  ["npm-shrinkwrap.json", DepSourceKind.NPM_LOCK],
  ["pnpm-lock.yaml", DepSourceKind.PNPM_LOCK],
  ["yarn.lock", DepSourceKind.YARN_LOCK],
];

export interface DiscoverOptions {
  readonly exclude: readonly string[];
}

function readManifest(dir: string): Record<string, unknown> | null {
  const p = join(dir, "package.json");
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, "utf-8")) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function buildProject(dir: string, manifest: Record<string, unknown>): Project {
  const sources: DepSource[] = [];
  const manifestPath = join(dir, "package.json");

  for (const [key, group] of GROUP_KEYS) {
    const section = manifest[key];
    if (section && typeof section === "object" && Object.keys(section).length > 0) {
      sources.push({ kind: DepSourceKind.MANIFEST, path: manifestPath, group });
    }
  }

  for (const [file, kind] of LOCK_FILES) {
    const lp = join(dir, file);
    if (existsSync(lp)) sources.push({ kind, path: lp, group: "locked" });
  }

  const engines = manifest["engines"] as Record<string, unknown> | undefined;
  const nodeVersion = engines && typeof engines["node"] === "string" ? (engines["node"] as string) : null;

  const name = typeof manifest["name"] === "string" ? (manifest["name"] as string) : basename(dir);

  return makeProject({ root: dir, name, sources, nodeVersion });
}

export function discoverOne(root: string): Project {
  const manifest = readManifest(root);
  if (!manifest) throw new Error(`no package.json at ${root}`);
  return buildProject(root, manifest);
}

export function discoverTree(root: string, opts: DiscoverOptions): Project[] {
  const exclude = new Set(opts.exclude);
  const projects: Project[] = [];

  const walk = (dir: string): void => {
    const manifest = readManifest(dir);
    if (manifest) projects.push(buildProject(dir, manifest));

    let entries: string[];
    try {
      entries = readdirSync(dir, { withFileTypes: true })
        .filter((e) => e.isDirectory())
        .map((e) => e.name);
    } catch {
      return;
    }

    for (const childName of entries) {
      if (ALWAYS_SKIP.has(childName)) continue;
      if (exclude.has(childName)) continue;
      walk(join(dir, childName));
    }
  };

  walk(root);
  projects.sort((a, b) => a.name.localeCompare(b.name));
  return projects;
}
