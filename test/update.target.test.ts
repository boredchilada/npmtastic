// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { resolveTarget } from "../src/update.js";
import { makeDep, DepSourceKind, type Vulnerability } from "../src/models.js";

function dep(range: string, resolved: string | null) {
  return makeDep({ name: "p", rawName: "p", range, resolved, source: { kind: DepSourceKind.MANIFEST, path: "package.json", group: "default" }, url: null, direct: true });
}
const vuln = (id: string, fixed: string[]): Vulnerability => ({ id, aliases: [], summary: null, fixedVersions: fixed });

describe("resolveTarget — default mode (exact pins → latest + CVE floor)", () => {
  it("bumps an exact pin to latest", () => {
    const t = resolveTarget({ dep: dep("1.2.0", "1.2.0"), pin: false, latest: "1.5.0", maxSatisfying: null, vulns: [] });
    expect(t).toEqual({ newVersion: "1.5.0", note: null });
  });
  it("does not touch a range in default mode", () => {
    expect(resolveTarget({ dep: dep("^1.2.0", "1.4.0"), pin: false, latest: "1.5.0", maxSatisfying: "1.4.0", vulns: [] })).toBeNull();
  });
  it("CVE floor overrides latest when minSafe is higher", () => {
    const t = resolveTarget({ dep: dep("1.2.0", "1.2.0"), pin: false, latest: "1.5.0", maxSatisfying: null, vulns: [vuln("GHSA-a", ["1.6.0"])] });
    expect(t).toEqual({ newVersion: "1.6.0", note: "CVE floor: GHSA-a" });
  });
  it("no-op when already at latest and clean", () => {
    expect(resolveTarget({ dep: dep("1.5.0", "1.5.0"), pin: false, latest: "1.5.0", maxSatisfying: null, vulns: [] })).toBeNull();
  });
});

describe("resolveTarget — pin mode (ranges → resolved exact + CVE floor)", () => {
  it("pins a caret range to the resolved version", () => {
    const t = resolveTarget({ dep: dep("^1.3.0", "1.3.5"), pin: true, latest: "1.9.0", maxSatisfying: "1.3.5", vulns: [] });
    expect(t).toEqual({ newVersion: "1.3.5", note: null });
  });
  it("uses maxSatisfying when there is no lockfile resolution", () => {
    const t = resolveTarget({ dep: dep("^1.3.0", null), pin: true, latest: "1.9.0", maxSatisfying: "1.4.2", vulns: [] });
    expect(t).toEqual({ newVersion: "1.4.2", note: null });
  });
  it("CVE-floors the pin when the resolved version is vulnerable", () => {
    const t = resolveTarget({ dep: dep("^1.3.0", "1.3.5"), pin: true, latest: "1.9.0", maxSatisfying: "1.3.5", vulns: [vuln("GHSA-b", ["1.3.6"])] });
    expect(t).toEqual({ newVersion: "1.3.6", note: "CVE floor: GHSA-b" });
  });
  it("skips a url dep", () => {
    const d = makeDep({ name: "p", rawName: "p", range: "github:u/r", resolved: null, source: { kind: DepSourceKind.MANIFEST, path: "package.json", group: "default" }, url: "github:u/r", direct: true });
    expect(resolveTarget({ dep: d, pin: true, latest: null, maxSatisfying: null, vulns: [] })).toBeNull();
  });
});
