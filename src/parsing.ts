// SPDX-License-Identifier: AGPL-3.0-or-later
import { parse as parseYaml } from "yaml";
import { DepSourceKind, makeDep, type Dep, type DepSource, type Project } from "./models.js";
import { readText } from "./fsutil.js";
import { warn } from "./logging.js";

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
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(readText(source.path)) as Record<string, unknown>;
  } catch (e) {
    warn(`could not parse ${source.path}: ${(e as Error).message}`);
    return [];
  }
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
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(readText(source.path)) as Record<string, unknown>;
  } catch (e) {
    warn(`could not parse ${source.path}: ${(e as Error).message}`);
    return [];
  }
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
  let raw: Record<string, unknown>;
  try {
    raw = parseYaml(readText(source.path)) as Record<string, unknown>;
  } catch (e) {
    warn(`could not parse ${source.path}: ${(e as Error).message}`);
    return [];
  }
  if (!raw || typeof raw !== "object") return [];
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

function descriptorName(descriptor: string): string | null {
  // descriptor examples: 'left-pad@^1.3.0', '@scope/util@~2.0.0', 'left-pad@npm:^1.3.0'
  let d = descriptor.trim().replace(/^"|"$/g, "");
  const scoped = d.startsWith("@");
  const body = scoped ? d.slice(1) : d;
  const at = body.indexOf("@");
  if (at === -1) return null;
  return (scoped ? "@" : "") + body.slice(0, at);
}

function parseYarnClassic(text: string, source: DepSource): Dep[] {
  const deps: Dep[] = [];
  const lines = text.split(/\r?\n/);
  let pendingName: string | null = null;

  for (const line of lines) {
    if (!line.trim() || line.startsWith("#")) continue;
    if (!line.startsWith(" ") && line.trimEnd().endsWith(":")) {
      // descriptor header line: "a@^1, b@^2:" — take the first descriptor's name
      const header = line.trimEnd().replace(/:$/, "");
      const firstDescriptor = header.split(",")[0]!.trim();
      pendingName = descriptorName(firstDescriptor);
      continue;
    }
    const m = line.trim().match(/^version\s+"?([^"\s]+)"?/);
    if (m && pendingName) {
      deps.push(lockDep(pendingName, m[1]!, source));
      pendingName = null;
    }
  }
  return deps;
}

function parseYarnBerry(text: string, source: DepSource): Dep[] {
  const raw = parseYaml(text) as Record<string, unknown>;
  const deps: Dep[] = [];
  for (const [key, entryUnknown] of Object.entries(raw)) {
    if (key === "__metadata") continue;
    const entry = entryUnknown as { version?: unknown };
    if (!entry || typeof entry.version === "undefined") continue;
    const name = descriptorName(key.split(",")[0]!.trim());
    if (!name) continue;
    deps.push(lockDep(name, String(entry.version), source));
  }
  return deps;
}

function parseYarnLock(source: DepSource): Dep[] {
  try {
    const text = readText(source.path);
    const isBerry = /^\s*__metadata:/m.test(text);
    return isBerry ? parseYarnBerry(text, source) : parseYarnClassic(text, source);
  } catch (e) {
    warn(`could not parse ${source.path}: ${(e as Error).message}`);
    return [];
  }
}

export function parseSource(source: DepSource): Dep[] {
  switch (source.kind) {
    case DepSourceKind.MANIFEST:
      return parseManifest(source);
    case DepSourceKind.NPM_LOCK:
      return parseNpmLock(source);
    case DepSourceKind.PNPM_LOCK:
      return parsePnpmLock(source);
    case DepSourceKind.YARN_LOCK:
      return parseYarnLock(source);
    default:
      // exhaustiveness guard: DepSourceKind is closed and all kinds are handled above
      return [];
  }
}

const LOCK_KINDS = new Set([DepSourceKind.NPM_LOCK, DepSourceKind.PNPM_LOCK, DepSourceKind.YARN_LOCK]);

function directRangesFromManifest(manifestPath: string): Map<string, string> | null {
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(readText(manifestPath)) as Record<string, unknown>;
  } catch {
    return null;
  }
  const ranges = new Map<string, string>();
  for (const key of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
    const section = raw[key];
    if (section && typeof section === "object") {
      for (const [n, spec] of Object.entries(section as Record<string, unknown>)) {
        if (typeof spec === "string") ranges.set(canonicalName(n), spec);
      }
    }
  }
  return ranges;
}

function withDirect(dep: Dep, direct: boolean): Dep {
  return makeDep({ ...dep, direct });
}

export function collectDeps(project: Project): Dep[] {
  const lockSources = project.sources.filter((s) => LOCK_KINDS.has(s.kind));
  const manifestSources = project.sources.filter((s) => s.kind === DepSourceKind.MANIFEST);

  let raw: Dep[];
  if (lockSources.length > 0) {
    // Use the first lock source in discovery order (package-lock → npm-shrinkwrap
    // → pnpm → yarn). A repo with multiple coexisting locks picks one arbitrarily;
    // Plan 2 may add explicit precedence + a warning for the multi-lock case.
    const lock = lockSources[0]!;
    const manifestPath = manifestSources[0]?.path ?? null;
    const declared = manifestPath ? directRangesFromManifest(manifestPath) : null;
    raw = parseSource(lock).map((d) => {
      if (!declared) return withDirect(d, true);
      const declaredRange = declared.get(d.name);
      if (declaredRange !== undefined) return makeDep({ ...d, range: declaredRange, direct: true });
      return withDirect(d, false);
    });
  } else {
    raw = manifestSources.flatMap((s) => parseSource(s));
  }

  // Dedup by (name, resolved ?? range), preserving first-seen order.
  const seen = new Set<string>();
  const out: Dep[] = [];
  for (const d of raw) {
    const key = `${d.name}@${d.resolved ?? d.range}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(d);
  }
  return out;
}
