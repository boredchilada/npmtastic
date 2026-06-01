// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parseSource } from "../src/parsing.js";
import { DepSourceKind } from "../src/models.js";

const here = dirname(fileURLToPath(import.meta.url));
const manifestPath = join(here, "fixtures", "manifest", "package.json");

describe("parse package.json", () => {
  it("parses the default group, canonicalizing names", () => {
    const deps = parseSource({ kind: DepSourceKind.MANIFEST, path: manifestPath, group: "default" });
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));

    expect(byName["left-pad"].range).toBe("^1.3.0");
    expect(byName["left-pad"].url).toBeNull();
    expect(byName["left-pad"].direct).toBe(true);

    expect(byName["lodash"].rawName).toBe("Lodash");
    expect(byName["lodash"].range).toBe("4.17.21");

    expect(byName["@scope/util"].range).toBe("~2.0.0");
  });

  it("flags non-semver protocols as url deps", () => {
    const deps = parseSource({ kind: DepSourceKind.MANIFEST, path: manifestPath, group: "default" });
    const byName = Object.fromEntries(deps.map((d) => [d.name, d]));
    expect(byName["from-git"].url).toBe("github:user/repo#v1");
    expect(byName["local-dep"].url).toBe("file:../local");
    expect(byName["tarball"].url).toBe("https://example.com/pkg.tgz");
  });

  it("reads a non-default group when asked", () => {
    const deps = parseSource({ kind: DepSourceKind.MANIFEST, path: manifestPath, group: "dev" });
    expect(deps.map((d) => d.name)).toEqual(["vitest"]);
    expect(deps[0].range).toBe("*");
  });
});
