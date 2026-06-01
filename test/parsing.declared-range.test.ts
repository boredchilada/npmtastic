// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { discoverOne } from "../src/discovery.js";
import { collectDeps } from "../src/parsing.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (p: string) => join(here, "fixtures", p);

describe("collectDeps declared-range threading", () => {
  it("direct lock deps keep the declared manifest range; resolved holds the locked version", () => {
    const deps = collectDeps(discoverOne(fx("locked-project")));
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
    expect(byName["left-pad"].range).toBe("^1.3.0");
    expect(byName["left-pad"].resolved).toBe("1.3.0");
    expect(byName["left-pad"].direct).toBe(true);
    expect(byName["transitive-only"].direct).toBe(false);
    expect(byName["transitive-only"].range).toBe(byName["transitive-only"].resolved);
  });
});
