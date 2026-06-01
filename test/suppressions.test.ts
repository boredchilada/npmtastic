// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadSuppressions, isSuppressed } from "../src/suppressions.js";

function projectWith(suppressions: unknown): string {
  const d = mkdtempSync(join(tmpdir(), "ntc-supp-"));
  writeFileSync(join(d, "package.json"), JSON.stringify({ name: "x", npmtastic: { suppressions } }));
  return d;
}
const vuln = (id: string, aliases: string[] = []) => ({ id, aliases, summary: null, fixedVersions: [] });

describe("loadSuppressions", () => {
  it("reads rules from package.json npmtastic.suppressions", () => {
    const rules = loadSuppressions(projectWith([{ id: "GHSA-a", package: "tar-fs", reason: "ok" }]));
    expect(rules).toEqual([{ id: "GHSA-a", package: "tar-fs", reason: "ok" }]);
  });
  it("returns [] when absent or malformed", () => {
    const d = mkdtempSync(join(tmpdir(), "ntc-supp-none-"));
    writeFileSync(join(d, "package.json"), JSON.stringify({ name: "x" }));
    expect(loadSuppressions(d)).toEqual([]);
    expect(loadSuppressions("/does/not/exist")).toEqual([]);
  });
});

describe("isSuppressed", () => {
  it("matches by id", () => {
    expect(isSuppressed([{ id: "GHSA-a" }], vuln("GHSA-a"), "anything")).toBe(true);
    expect(isSuppressed([{ id: "GHSA-a" }], vuln("GHSA-b"), "anything")).toBe(false);
  });
  it("matches by id via alias", () => {
    expect(isSuppressed([{ id: "CVE-1" }], vuln("GHSA-a", ["CVE-1"]), "x")).toBe(true);
  });
  it("matches by package only (all advisories for that package)", () => {
    expect(isSuppressed([{ package: "tar-fs" }], vuln("GHSA-a"), "tar-fs")).toBe(true);
    expect(isSuppressed([{ package: "tar-fs" }], vuln("GHSA-a"), "other")).toBe(false);
  });
  it("requires BOTH when both id and package given", () => {
    const rule = { id: "GHSA-a", package: "tar-fs" };
    expect(isSuppressed([rule], vuln("GHSA-a"), "tar-fs")).toBe(true);
    expect(isSuppressed([rule], vuln("GHSA-a"), "other")).toBe(false);
  });
  it("an empty rule (neither id nor package) suppresses nothing", () => {
    expect(isSuppressed([{}], vuln("GHSA-a"), "x")).toBe(false);
  });
});
