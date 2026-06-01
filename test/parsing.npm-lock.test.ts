// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parseSource } from "../src/parsing.js";
import { DepSourceKind } from "../src/models.js";

const here = dirname(fileURLToPath(import.meta.url));
const lock = (d: string) => join(here, "fixtures", d, "package-lock.json");

describe("parse package-lock.json", () => {
  it("v3: reads the packages map as exact pins, skips root, derives names from paths", () => {
    const deps = parseSource({ kind: DepSourceKind.NPM_LOCK, path: lock("npm-lock-v3"), group: "locked" });
    const map = Object.fromEntries(deps.map((d) => [d.name, d.resolved]));
    expect(map["left-pad"]).toBe("1.3.0");
    expect(map["@scope/util"]).toBe("2.0.1");
    expect(map["dep-dep"]).toBe("0.5.0"); // nested transitive
    expect(deps.find((d) => d.name === "v3-app")).toBeUndefined(); // root skipped
    expect(deps.every((d) => d.range === d.resolved)).toBe(true); // exact pin
  });

  it("v1: walks the nested dependencies tree", () => {
    const deps = parseSource({ kind: DepSourceKind.NPM_LOCK, path: lock("npm-lock-v1"), group: "locked" });
    const map = Object.fromEntries(deps.map((d) => [d.name, d.resolved]));
    expect(map["left-pad"]).toBe("1.3.0");
    expect(map["dep-dep"]).toBe("0.5.0");
    expect(map["@scope/util"]).toBe("2.0.1");
  });
});
