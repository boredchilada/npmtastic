// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parseSource } from "../src/parsing.js";
import { DepSourceKind } from "../src/models.js";

const here = dirname(fileURLToPath(import.meta.url));
const yl = (d: string) => join(here, "fixtures", d, "yarn.lock");

describe("parse yarn.lock", () => {
  it("classic v1: one entry per descriptor stanza", () => {
    const deps = parseSource({ kind: DepSourceKind.YARN_LOCK, path: yl("yarn-classic"), group: "locked" });
    const map = Object.fromEntries(deps.map((d) => [d.name, d.resolved]));
    expect(map["left-pad"]).toBe("1.3.0");
    expect(map["@scope/util"]).toBe("2.0.1");
    expect(map["dep-dep"]).toBe("0.5.0");
  });

  it("berry v6 (YAML): reads version from each resolution block", () => {
    const deps = parseSource({ kind: DepSourceKind.YARN_LOCK, path: yl("yarn-berry"), group: "locked" });
    const map = Object.fromEntries(deps.map((d) => [d.name, d.resolved]));
    expect(map["left-pad"]).toBe("1.3.0");
    expect(map["@scope/util"]).toBe("2.0.1");
  });
});
