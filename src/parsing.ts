// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
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

export function parseSource(source: DepSource): Dep[] {
  switch (source.kind) {
    case DepSourceKind.MANIFEST:
      return parseManifest(source);
    default:
      // lockfile parsers added in later tasks
      return [];
  }
}
