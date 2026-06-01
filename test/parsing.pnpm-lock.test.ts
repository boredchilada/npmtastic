// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parseSource } from "../src/parsing.js";
import { DepSourceKind } from "../src/models.js";

const here = dirname(fileURLToPath(import.meta.url));
const path = join(here, "fixtures", "pnpm", "pnpm-lock.yaml");

describe("parse pnpm-lock.yaml", () => {
  it("extracts name@version from the packages map, handling scopes", () => {
    const deps = parseSource({ kind: DepSourceKind.PNPM_LOCK, path, group: "locked" });
    const map = Object.fromEntries(deps.map((d) => [d.name, d.resolved]));
    expect(map["left-pad"]).toBe("1.3.0");
    expect(map["@scope/util"]).toBe("2.0.1");
    expect(map["dep-dep"]).toBe("0.5.0");
    expect(deps.every((d) => d.range === d.resolved)).toBe(true);
  });
});
