// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { reconstructFromNpmLock, reconstructFromPnpmLock } from "../src/bootstrap.js";

const NPM_LOCK = JSON.stringify({
  name: "demo",
  lockfileVersion: 3,
  packages: {
    "": {
      name: "demo",
      version: "1.0.0",
      dependencies: { "left-pad": "^1.3.0", "local": "workspace:^" },
      devDependencies: { vitest: "^4.1.0" },
    },
    "node_modules/left-pad": { version: "1.3.0" },
  },
});

const PNPM_LOCK = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      left-pad:
        specifier: ^1.3.0
        version: 1.3.0
      sibling:
        specifier: workspace:^
        version: link:packages/sibling
    devDependencies:
      vitest:
        specifier: ^4.1.0
        version: 4.1.8
`;

describe("reconstructFromNpmLock", () => {
  it("recovers groups + declared ranges, skips non-installable (workspace:) specifiers", () => {
    const r = reconstructFromNpmLock(NPM_LOCK)!;
    expect(r.name).toBe("demo");
    expect(r.version).toBe("1.0.0");
    expect(r.groups["dependencies"]).toEqual({ "left-pad": "^1.3.0" });
    expect(r.groups["devDependencies"]).toEqual({ vitest: "^4.1.0" });
    expect(r.warnings.some((w) => w.includes("local"))).toBe(true);
  });
  it("returns null for lockfileVersion 1 (no packages map)", () => {
    expect(reconstructFromNpmLock(JSON.stringify({ lockfileVersion: 1, dependencies: {} }))).toBeNull();
  });
  it("returns null when the root yields zero installable deps", () => {
    const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { a: "workspace:^" } } } });
    expect(reconstructFromNpmLock(lock)).toBeNull();
  });
});

describe("reconstructFromPnpmLock", () => {
  it("recovers groups + specifiers from importers['.'], skips workspace:/link:", () => {
    const r = reconstructFromPnpmLock(PNPM_LOCK)!;
    expect(r.groups["dependencies"]).toEqual({ "left-pad": "^1.3.0" });
    expect(r.groups["devDependencies"]).toEqual({ vitest: "^4.1.0" });
    expect(r.warnings.some((w) => w.includes("sibling"))).toBe(true);
  });
  it("returns null when there is no importers section", () => {
    expect(reconstructFromPnpmLock("lockfileVersion: '5.4'\n")).toBeNull();
  });
});
