// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { discoverOne } from "../src/discovery.js";
import { collectDeps } from "../src/parsing.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (p: string) => join(here, "fixtures", p);

describe("collectDeps", () => {
  it("uses the lock graph and tags direct from the manifest", () => {
    const project = discoverOne(fx("locked-project"));
    const deps = collectDeps(project);
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));

    expect(Object.keys(byName).sort()).toEqual(["left-pad", "transitive-only", "vitest"]);
    expect(byName["left-pad"].direct).toBe(true);
    expect(byName["vitest"].direct).toBe(true);
    expect(byName["transitive-only"].direct).toBe(false);
    expect(deps.length).toBe(3);
  });

  it("falls back to manifest deps when no lock is present", () => {
    const project = discoverOne(fx("manifest"));
    const deps = collectDeps(project);
    expect(deps.find((d) => d.name === "left-pad")?.direct).toBe(true);
    expect(deps.every((d) => d.resolved === null)).toBe(true);
  });
});
