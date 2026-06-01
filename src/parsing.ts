// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { DepSourceKind, makeDep, type Dep, type DepSource } from "./models.js";

const GROUP_TO_KEY: Record<string, string> = {
  default: "dependencies",
  dev: "devDependencies",
  peer: "peerDependencies",
  optional: "optionalDependencies",
};

const URL_PROTOCOL = /^(git\+|git:|github:|gitlab:|bitbucket:|file:|link:|workspace:|https?:)/i;

export function canonicalName(raw: string): string {
  // npm lowercases names; scope is part of the name and is also lowercase.
  return raw.toLowerCase();
}

function classifySpec(spec: string): { range: string; url: string | null } {
  const trimmed = spec.trim();
  if (URL_PROTOCOL.test(trimmed)) return { range: trimmed, url: trimmed };
  return { range: trimmed, url: null };
}

function parseManifest(source: DepSource): Dep[] {
  const raw = JSON.parse(readFileSync(source.path, "utf-8")) as Record<string, unknown>;
  const key = GROUP_TO_KEY[source.group] ?? "dependencies";
  const section = raw[key];
  if (!section || typeof section !== "object") return [];

  const deps: Dep[] = [];
  for (const [rawName, specUnknown] of Object.entries(section as Record<string, unknown>)) {
    const spec = typeof specUnknown === "string" ? specUnknown : "";
    const { range, url } = classifySpec(spec);
    deps.push(
      makeDep({
        name: canonicalName(rawName),
        rawName,
        range,
        resolved: null,
        source,
        url,
        direct: true,
      }),
    );
  }
  return deps;
}

function nameFromLockPath(installPath: string): string | null {
  // "node_modules/a/node_modules/@scope/b" -> "@scope/b"
  const idx = installPath.lastIndexOf("node_modules/");
  if (idx === -1) return null;
  const tail = installPath.slice(idx + "node_modules/".length);
  return tail.length > 0 ? tail : null;
}

function lockDep(name: string, version: string, source: DepSource): Dep {
  return makeDep({
    name: canonicalName(name),
    rawName: name,
    range: version,
    resolved: version,
    source,
    url: null,
    direct: false, // direct set is computed in collectDeps
  });
}

function parseNpmLock(source: DepSource): Dep[] {
  const raw = JSON.parse(readFileSync(source.path, "utf-8")) as Record<string, unknown>;
  const deps: Dep[] = [];

  const packages = raw["packages"] as Record<string, { version?: string }> | undefined;
  if (packages) {
    // lockfileVersion 2/3
    for (const [installPath, entry] of Object.entries(packages)) {
      if (installPath === "") continue; // root project
      const name = nameFromLockPath(installPath);
      if (!name || !entry || typeof entry.version !== "string") continue;
      deps.push(lockDep(name, entry.version, source));
    }
    return deps;
  }

  // lockfileVersion 1: nested dependencies tree
  const walk = (tree: Record<string, { version?: string; dependencies?: Record<string, unknown> }>): void => {
    for (const [name, entry] of Object.entries(tree)) {
      if (entry && typeof entry.version === "string") deps.push(lockDep(name, entry.version, source));
      if (entry && entry.dependencies && typeof entry.dependencies === "object") {
        walk(entry.dependencies as Record<string, { version?: string; dependencies?: Record<string, unknown> }>);
      }
    }
  };
  const top = raw["dependencies"];
  if (top && typeof top === "object") {
    walk(top as Record<string, { version?: string; dependencies?: Record<string, unknown> }>);
  }
  return deps;
}

function splitPnpmKey(key: string): { name: string; version: string } | null {
  // Strip leading slash (pre-v6) and any peer-deps suffix "(...)".
  let k = key.startsWith("/") ? key.slice(1) : key;
  const paren = k.indexOf("(");
  if (paren !== -1) k = k.slice(0, paren);
  // name@version, where name may be "@scope/pkg" and may use "/version" (old) or "@version".
  const at = k.lastIndexOf("@");
  if (at <= 0) {
    // old style: name/version
    const slash = k.lastIndexOf("/");
    if (slash <= 0) return null;
    return { name: k.slice(0, slash), version: k.slice(slash + 1) };
  }
  return { name: k.slice(0, at), version: k.slice(at + 1) };
}

function parsePnpmLock(source: DepSource): Dep[] {
  const raw = parseYaml(readFileSync(source.path, "utf-8")) as Record<string, unknown>;
  const packages = raw["packages"];
  if (!packages || typeof packages !== "object") return [];
  const deps: Dep[] = [];
  for (const key of Object.keys(packages as Record<string, unknown>)) {
    const parsed = splitPnpmKey(key);
    if (!parsed || !parsed.version) continue;
    deps.push(lockDep(parsed.name, parsed.version, source));
  }
  return deps;
}

export function parseSource(source: DepSource): Dep[] {
  switch (source.kind) {
    case DepSourceKind.MANIFEST:
      return parseManifest(source);
    case DepSourceKind.NPM_LOCK:
      return parseNpmLock(source);
    case DepSourceKind.PNPM_LOCK:
      return parsePnpmLock(source);
    default:
      // lockfile parsers added in later tasks
      return [];
  }
}
