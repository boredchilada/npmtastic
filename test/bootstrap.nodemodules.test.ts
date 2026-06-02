// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { enumerateNodeModules } from "../src/bootstrap.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "fixtures", "bootstrap-nm");

describe("enumerateNodeModules", () => {
  it("collects installed packages exact, handles scopes, skips dot-dirs and broken entries", () => {
    const { deps, warnings } = enumerateNodeModules(root, null);
    expect(deps["left-pad"]).toBe("1.3.0");
    expect(deps["@scope/util"]).toBe("2.0.1");
    expect(deps[".bin"]).toBeUndefined();
    expect(Object.keys(deps)).not.toContain("broken");
    expect(warnings.some((w) => w.includes("broken"))).toBe(true);
    expect(warnings.some((w) => w.toLowerCase().includes("transitive"))).toBe(true);
  });

  it("skips the self entry by name", () => {
    const { deps } = enumerateNodeModules(root, "left-pad");
    expect(deps["left-pad"]).toBeUndefined();
    expect(deps["@scope/util"]).toBe("2.0.1");
  });

  it("returns empty (no throw) when node_modules is absent", () => {
    const { deps } = enumerateNodeModules(join(here, "fixtures", "single"), null);
    expect(deps).toEqual({});
  });
});
