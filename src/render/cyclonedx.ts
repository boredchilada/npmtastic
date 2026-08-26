// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { DepSourceKind, type ProjectAudit, type Vulnerability } from "../models.js";

const VERSION = "0.1.1";
export const SPEC_VERSION = "1.5";
const CWE = /CWE-(\d+)/gi;

function npmPurl(name: string, version: string): string {
  if (name.startsWith("@")) {
    const slash = name.indexOf("/");
    if (slash > 0) {
      return `pkg:npm/%40${name.slice(1, slash)}/${name.slice(slash + 1)}@${version}`;
    }
  }
  return `pkg:npm/${name}@${version}`;
}

function component(name: string, version: string): Record<string, unknown> {
  const ref = npmPurl(name, version);
  return {
    "bom-ref": ref,
    type: "library",
    name,
    version,
    purl: ref,
  };
}

function nameFromLockPath(installPath: string): string | null {
  const idx = installPath.lastIndexOf("node_modules/");
  if (idx === -1) return null;
  const tail = installPath.slice(idx + "node_modules/".length);
  return tail.length > 0 ? tail : null;
}

function resolveChild(
  parentPath: string,
  childName: string,
  byPath: Map<string, { name: string; version: string }>,
): string | null {
  const nested = parentPath ? `${parentPath}/node_modules/${childName}` : `node_modules/${childName}`;
  const direct = byPath.get(nested);
  if (direct) return npmPurl(direct.name, direct.version);
  // Walk up: node_modules/a/node_modules/b depending on c → node_modules/c
  let cursor = parentPath;
  while (true) {
    const idx = cursor.lastIndexOf("/node_modules/");
    cursor = idx === -1 ? "" : cursor.slice(0, idx);
    const candidate = cursor ? `${cursor}/node_modules/${childName}` : `node_modules/${childName}`;
    const hit = byPath.get(candidate);
    if (hit) return npmPurl(hit.name, hit.version);
    if (cursor === "") break;
  }
  return null;
}

function npmLockGraph(raw: Record<string, unknown>, known: Set<string>): Record<string, unknown>[] {
  const packages = raw["packages"];
  if (!packages || typeof packages !== "object") {
    // lockfileVersion 1: nested dependencies
    const edges: Record<string, Set<string>> = {};
    let saw = false;
    const walk = (
      tree: Record<string, { version?: string; dependencies?: Record<string, unknown> }>,
    ): void => {
      for (const [name, entry] of Object.entries(tree)) {
        if (!entry || typeof entry.version !== "string") continue;
        const ref = npmPurl(name, entry.version);
        if (!known.has(ref) || !entry.dependencies) continue;
        saw = true;
        for (const [child, childEntry] of Object.entries(
          entry.dependencies as Record<string, { version?: string; dependencies?: Record<string, unknown> }>,
        )) {
          if (!childEntry || typeof childEntry.version !== "string") continue;
          const childRef = npmPurl(child, childEntry.version);
          if (known.has(childRef)) {
            if (!edges[ref]) edges[ref] = new Set();
            edges[ref]!.add(childRef);
          }
        }
        if (entry.dependencies) {
          walk(entry.dependencies as Record<string, { version?: string; dependencies?: Record<string, unknown> }>);
        }
      }
    };
    const top = raw["dependencies"];
    if (top && typeof top === "object") {
      walk(top as Record<string, { version?: string; dependencies?: Record<string, unknown> }>);
    }
    if (!saw) return [];
    return Object.keys(edges)
      .sort()
      .map((ref) => ({ ref, dependsOn: [...edges[ref]!].sort() }));
  }

  const byPath = new Map<string, { name: string; version: string }>();
  for (const [installPath, entryUnknown] of Object.entries(packages as Record<string, unknown>)) {
    if (installPath === "") continue;
    const entry = entryUnknown as { version?: string };
    const name = nameFromLockPath(installPath);
    if (!name || typeof entry?.version !== "string") continue;
    byPath.set(installPath, { name, version: entry.version });
  }

  const edges: Record<string, Set<string>> = {};
  let saw = false;
  for (const [installPath, entryUnknown] of Object.entries(packages as Record<string, unknown>)) {
    const entry = entryUnknown as {
      version?: string;
      dependencies?: Record<string, string>;
      requires?: Record<string, string>;
    };
    const kids = { ...(entry.dependencies ?? {}), ...(entry.requires ?? {}) };
    if (Object.keys(kids).length === 0) continue;
    saw = true;
    const parent =
      installPath === ""
        ? null
        : byPath.get(installPath);
    const ref = parent ? npmPurl(parent.name, parent.version) : null;
    if (installPath !== "" && (!ref || !known.has(ref))) continue;
    const from = ref ?? `root`;
    for (const childName of Object.keys(kids)) {
      const childRef = resolveChild(installPath, childName, byPath);
      if (!childRef || !known.has(childRef)) continue;
      if (installPath === "") continue; // root edges omitted unless we add a root component later
      if (!edges[from]) edges[from] = new Set();
      edges[from]!.add(childRef);
    }
  }
  if (!saw) return [];
  return Object.keys(edges)
    .sort()
    .map((ref) => ({ ref, dependsOn: [...edges[ref]!].sort() }));
}

function splitPnpmKey(key: string): { name: string; version: string } | null {
  let k = key.startsWith("/") ? key.slice(1) : key;
  const paren = k.indexOf("(");
  if (paren !== -1) k = k.slice(0, paren);
  const at = k.lastIndexOf("@");
  if (at <= 0) {
    const slash = k.lastIndexOf("/");
    if (slash <= 0) return null;
    return { name: k.slice(0, slash), version: k.slice(slash + 1) };
  }
  return { name: k.slice(0, at), version: k.slice(at + 1) };
}

function pnpmLockGraph(raw: Record<string, unknown>, known: Set<string>): Record<string, unknown>[] {
  const packages = raw["packages"];
  if (!packages || typeof packages !== "object") return [];
  const index = new Map<string, { name: string; version: string }>();
  for (const key of Object.keys(packages as Record<string, unknown>)) {
    const parsed = splitPnpmKey(key);
    if (parsed) index.set(parsed.name, parsed);
  }
  const edges: Record<string, Set<string>> = {};
  let saw = false;
  for (const [key, entryUnknown] of Object.entries(packages as Record<string, unknown>)) {
    const parsed = splitPnpmKey(key);
    if (!parsed) continue;
    const ref = npmPurl(parsed.name, parsed.version);
    if (!known.has(ref)) continue;
    const entry = entryUnknown as { dependencies?: Record<string, string> };
    const deps = entry.dependencies;
    if (!deps || Object.keys(deps).length === 0) continue;
    saw = true;
    for (const [childName, childVer] of Object.entries(deps)) {
      const child = index.get(childName);
      const version = typeof childVer === "string" ? childVer : child?.version;
      if (!version) continue;
      const childRef = npmPurl(childName, version);
      if (!known.has(childRef)) continue;
      if (!edges[ref]) edges[ref] = new Set();
      edges[ref]!.add(childRef);
    }
  }
  if (!saw) return [];
  return Object.keys(edges)
    .sort()
    .map((ref) => ({ ref, dependsOn: [...edges[ref]!].sort() }));
}

function readJson(path: string): Record<string, unknown> | null {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function readYaml(path: string): Record<string, unknown> | null {
  try {
    const raw = parseYaml(readFileSync(path, "utf8"));
    return raw && typeof raw === "object" ? (raw as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function dependencyGraph(audits: readonly ProjectAudit[], known: Set<string>): Record<string, unknown>[] {
  const merged: Record<string, Set<string>> = {};
  let saw = false;
  for (const project of audits) {
    const lock = project.project.sources.find(
      (s) => s.kind === DepSourceKind.NPM_LOCK || s.kind === DepSourceKind.PNPM_LOCK,
    );
    if (!lock) continue;
    const raw = lock.kind === DepSourceKind.PNPM_LOCK ? readYaml(lock.path) : readJson(lock.path);
    if (!raw) continue;
    const graph =
      lock.kind === DepSourceKind.PNPM_LOCK ? pnpmLockGraph(raw, known) : npmLockGraph(raw, known);
    if (graph.length === 0) continue;
    saw = true;
    for (const node of graph) {
      const ref = String(node["ref"]);
      const kids = node["dependsOn"] as string[];
      if (!merged[ref]) merged[ref] = new Set();
      for (const kid of kids) merged[ref]!.add(kid);
    }
  }
  if (!saw) return [];
  return Object.keys(merged)
    .sort()
    .map((ref) => ({ ref, dependsOn: [...merged[ref]!].sort() }));
}

function vulnerabilities(audits: readonly ProjectAudit[]): Record<string, unknown>[] {
  const collected = new Map<string, Record<string, unknown>>();
  for (const project of audits) {
    for (const dep of project.deps) {
      const version = dep.dep.resolved;
      if (!version) continue;
      const ref = npmPurl(dep.dep.name, version);
      const advisories: Vulnerability[] = [
        ...dep.vulnerabilities,
        ...(dep.suppressedVulnerabilities ?? []),
      ];
      for (const advisory of advisories) {
        let entry = collected.get(advisory.id);
        if (!entry) {
          entry = {
            id: advisory.id,
            source: { name: "OSV", url: "https://osv.dev" },
            affects: [],
          };
          const ratings: Record<string, unknown>[] = [];
          if (advisory.severity && advisory.severity !== "unknown") {
            ratings.push({ severity: advisory.severity });
          }
          if (advisory.cvss) ratings.push({ method: "CVSSv3", vector: advisory.cvss });
          if (ratings.length > 0) entry["ratings"] = ratings;
          const cwes = [...`${advisory.cweIds.join(" ")}`.matchAll(CWE)].map((m) => Number.parseInt(m[1]!, 10));
          if (cwes.length > 0) entry["cwes"] = cwes;
          if (advisory.summary) entry["description"] = advisory.summary;
          if (advisory.references.length > 0) {
            entry["advisories"] = advisory.references.map((url) => ({ url }));
          }
          if (advisory.published) entry["published"] = advisory.published;
          collected.set(advisory.id, entry);
        }
        const affects = entry["affects"] as Array<{ ref: string }>;
        if (!affects.some((a) => a.ref === ref)) affects.push({ ref });
      }
    }
  }
  return [...collected.keys()].sort().map((key) => collected.get(key)!);
}

export function renderCycloneDx(audits: readonly ProjectAudit[]): string {
  const components: Record<string, Record<string, unknown>> = {};
  for (const project of audits) {
    for (const dep of project.deps) {
      const version = dep.dep.resolved;
      if (!version) continue;
      const ref = npmPurl(dep.dep.name, version);
      if (components[ref]) continue;
      components[ref] = component(dep.dep.name, version);
    }
  }

  const roots = audits.map((project) => ({
    "bom-ref": `root:${project.project.name}`,
    type: "application",
    name: project.project.name,
  }));
  const metadata: Record<string, unknown> = {
    timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    tools: [{ vendor: "npmtastic", name: "npmtastic", version: VERSION }],
  };
  if (roots.length === 1) {
    metadata["component"] = roots[0];
  } else if (roots.length > 1) {
    metadata["component"] = {
      "bom-ref": "root:workspace",
      type: "application",
      name: "workspace",
      components: roots,
    };
  }

  const bom: Record<string, unknown> = {
    bomFormat: "CycloneDX",
    specVersion: SPEC_VERSION,
    version: 1,
    metadata,
    components: Object.keys(components)
      .sort()
      .map((ref) => components[ref]!),
  };
  const graph = dependencyGraph(audits, new Set(Object.keys(components)));
  if (graph.length > 0) bom["dependencies"] = graph;
  const vulns = vulnerabilities(audits);
  if (vulns.length > 0) bom["vulnerabilities"] = vulns;
  return JSON.stringify(bom, null, 2);
}
