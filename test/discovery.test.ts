// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { discoverOne, discoverTree } from "../src/discovery.js";
import { DepSourceKind } from "../src/models.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (p: string) => join(here, "fixtures", p);

describe("discovery", () => {
  it("discoverOne reads name, engines, and group + lock sources", () => {
    const proj = discoverOne(fx("single"));
    expect(proj.name).toBe("single-app");
    expect(proj.nodeVersion).toBe(">=18");
    const groups = proj.sources
      .filter((s) => s.kind === DepSourceKind.MANIFEST)
      .map((s) => s.group)
      .sort();
    expect(groups).toEqual(["default", "dev"]);
  });

  it("discoverTree finds nested projects and prunes node_modules", () => {
    const projects = discoverTree(fx("tree"), { exclude: [] });
    const names = projects.map((p) => p.name).sort();
    expect(names).toEqual(["app-a", "app-b"]);
    expect(names).not.toContain("should-be-pruned");
  });

  it("discoverTree emits a lock source when a lockfile is present", () => {
    const projects = discoverTree(fx("tree"), { exclude: [] });
    const appA = projects.find((p) => p.name === "app-a")!;
    expect(appA.sources.some((s) => s.kind === DepSourceKind.NPM_LOCK)).toBe(true);
  });

  it("discoverTree honors exclude basenames", () => {
    const projects = discoverTree(fx("tree"), { exclude: ["nested"] });
    expect(projects.map((p) => p.name)).toEqual(["app-a"]);
  });
});
