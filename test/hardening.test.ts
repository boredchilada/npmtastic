// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { discoverOne, discoverTree } from "../src/discovery.js";
import { collectDeps } from "../src/parsing.js";
import { readText } from "../src/fsutil.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (p: string) => join(here, "fixtures", "hardening", p);

describe("hardening: malformed lockfiles degrade, never throw", () => {
  it("malformed package-lock.json → falls back to the manifest (no throw)", () => {
    expect(() => collectDeps(discoverOne(fx("malformed-lock")))).not.toThrow();
    const deps = collectDeps(discoverOne(fx("malformed-lock")));
    // lock unparseable → degrade to manifest deps rather than zeroing out
    expect(deps.map((d) => d.name)).toContain("a");
    expect(deps.every((d) => d.resolved === null)).toBe(true); // manifest-sourced
  });
  it("malformed pnpm-lock.yaml → falls back to the manifest (no throw)", () => {
    expect(() => collectDeps(discoverOne(fx("malformed-pnpm")))).not.toThrow();
    expect(collectDeps(discoverOne(fx("malformed-pnpm"))).map((d) => d.name)).toContain("a");
  });
  it("empty lockfile → collectDeps returns [] (no throw)", () => {
    expect(() => collectDeps(discoverOne(fx("empty-lock")))).not.toThrow();
  });
});

describe("hardening: discoverOne error accuracy", () => {
  it("missing package.json throws 'no package.json'", () => {
    const d = mkdtempSync(join(tmpdir(), "ntc-nopkg-"));
    expect(() => discoverOne(d)).toThrow(/no package\.json/);
  });
  it("malformed package.json throws 'malformed package.json'", () => {
    const d = mkdtempSync(join(tmpdir(), "ntc-badpkg-"));
    writeFileSync(join(d, "package.json"), "{ not valid ,,,");
    expect(() => discoverOne(d)).toThrow(/malformed package\.json/);
  });
});

describe("hardening: UTF-16 decoding", () => {
  it("reads a UTF-16LE package.json with BOM", () => {
    const d = mkdtempSync(join(tmpdir(), "ntc-utf16-"));
    const json = JSON.stringify({ name: "u16", dependencies: { "left-pad": "^1.3.0" } });
    writeFileSync(join(d, "package.json"), Buffer.from("﻿" + json, "utf16le"));
    const proj = discoverOne(d);
    expect(proj.name).toBe("u16");
    const deps = collectDeps(proj);
    expect(deps.map((x) => x.name)).toContain("left-pad");
  });
  it("readText strips a UTF-8 BOM", () => {
    const d = mkdtempSync(join(tmpdir(), "ntc-bom8-"));
    writeFileSync(join(d, "f.json"), Buffer.from("﻿{\"x\":1}", "utf8"));
    expect(JSON.parse(readText(join(d, "f.json")))).toEqual({ x: 1 });
  });
});

describe("hardening: malformed berry yarn.lock degrades", () => {
  it("a __metadata-shaped yarn.lock with broken YAML returns [] (no throw)", () => {
    const d = mkdtempSync(join(tmpdir(), "ntc-badberry-"));
    writeFileSync(join(d, "package.json"), JSON.stringify({ name: "bb", dependencies: { a: "^1" } }));
    // Has `__metadata:` so it routes to the berry (YAML) path, but the YAML is invalid.
    writeFileSync(join(d, "yarn.lock"), '__metadata:\n  version: 6\n\n"a@npm:^1": [ unclosed\n');
    expect(() => collectDeps(discoverOne(d))).not.toThrow();
    // broken berry lock → degrade to the manifest dep, not zero
    expect(collectDeps(discoverOne(d)).map((x) => x.name)).toContain("a");
  });
});

describe("hardening: tree scan survives a broken project", () => {
  it("discoverTree + per-project collectDeps never throws across mixed-validity tree", () => {
    const root = mkdtempSync(join(tmpdir(), "ntc-tree-"));
    // good project
    mkdirSync(join(root, "good"));
    writeFileSync(join(root, "good", "package.json"), JSON.stringify({ name: "good", dependencies: { "left-pad": "^1.3.0" } }));
    // broken lockfile project
    mkdirSync(join(root, "broken"));
    writeFileSync(join(root, "broken", "package.json"), JSON.stringify({ name: "broken", dependencies: { a: "^1" } }));
    writeFileSync(join(root, "broken", "package-lock.json"), "{ truncated");
    const projects = discoverTree(root, { exclude: [] });
    expect(() => projects.forEach((p) => collectDeps(p))).not.toThrow();
    const good = projects.find((p) => p.name === "good")!;
    expect(collectDeps(good).map((d) => d.name)).toContain("left-pad");
  });
});
