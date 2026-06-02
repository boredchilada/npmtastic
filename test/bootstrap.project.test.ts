// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { bootstrapProject } from "../src/bootstrap.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (p: string) => join(here, "fixtures", p);

describe("bootstrapProject", () => {
  it("default: reconstructs from the npm lockfile root (no package.json present)", () => {
    const res = bootstrapProject(fx("bootstrap-npm"), {})!;
    expect(res.source).toBe("npm-lock");
    expect(res.manifest["name"]).toBe("recovered");
    expect(res.manifest["version"]).toBe("2.1.0");
    expect(res.manifest["dependencies"]).toEqual({ "left-pad": "^1.3.0" });
    expect(res.manifest["devDependencies"]).toEqual({ vitest: "^4.1.0" });
  });

  it("--from-node-modules: freezes installed packages exact", () => {
    const res = bootstrapProject(fx("bootstrap-nm"), { fromNodeModules: true })!;
    expect(res.source).toBe("node-modules");
    const deps = res.manifest["dependencies"] as Record<string, string>;
    expect(deps["left-pad"]).toBe("1.3.0");
    expect(deps["@scope/util"]).toBe("2.0.1");
    expect(res.warnings.some((w) => w.toLowerCase().includes("transitive"))).toBe(true);
  });

  it("falls back to node_modules when no usable lockfile (warns)", () => {
    const res = bootstrapProject(fx("bootstrap-nm"), {})!;
    expect(res.source).toBe("node-modules");
    expect(res.warnings.some((w) => w.includes("no usable lockfile"))).toBe(true);
  });

  it("returns null when neither a lockfile nor node_modules exists", () => {
    const empty = mkdtempSync(join(tmpdir(), "ntc-bsempty-"));
    expect(bootstrapProject(empty, {})).toBeNull();
  });
});
