// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, beforeAll } from "vitest";
import { renderTerminal } from "../src/render/terminal.js";
import { makeProjectAudit, makeDepAudit, makeDep, PinStatus, SemverDrift, DepSourceKind } from "../src/models.js";

beforeAll(() => {
  process.env["NO_COLOR"] = "1";
});

function audit(name: string) {
  const lp = makeDepAudit({
    dep: makeDep({ name: "left-pad", rawName: "left-pad", range: "^1.0.0", resolved: "1.3.0", source: { kind: DepSourceKind.MANIFEST, path: "package.json", group: "default" }, url: null, direct: true }),
    latest: "2.0.0", latestIncludingPrereleases: "2.0.0", drift: SemverDrift.MAJOR, pinStatus: PinStatus.COMPATIBLE,
    deprecated: null, vulnerabilities: [], minSafeVersion: null, latestReleaseDate: null, latestReleaseAgeDays: 120, warnings: [],
  });
  const mm = makeDepAudit({
    dep: makeDep({ name: "minimist", rawName: "minimist", range: "1.2.0", resolved: "1.2.0", source: { kind: DepSourceKind.MANIFEST, path: "package.json", group: "default" }, url: null, direct: true }),
    latest: "1.2.6", latestIncludingPrereleases: "1.2.6", drift: SemverDrift.PATCH, pinStatus: PinStatus.PINNED,
    deprecated: null, vulnerabilities: [{ id: "GHSA-min", aliases: [], summary: "x", fixedVersions: ["1.2.6"] }], minSafeVersion: "1.2.6", latestReleaseDate: null, latestReleaseAgeDays: null, warnings: [],
  });
  return makeProjectAudit({
    project: { root: "/p", name, sources: [], nodeVersion: null }, deps: [lp, mm],
    pinningScore: 1, driftSummary: { none: 0, prerelease: 0, patch: 1, minor: 0, major: 1, unknown: 0 },
    deprecatedCount: 0, registryUnreachable: 0, vulnCount: 1, vulnUnreachable: 0, suppressedCount: 0,
  });
}

describe("renderTerminal", () => {
  it("table view lists packages with posture/drift/cve", () => {
    const out = renderTerminal([audit("p")], "table");
    expect(out).toContain("left-pad");
    expect(out).toContain("compatible");
    expect(out).toContain("major");
    expect(out).toContain("minimist");
    expect(out).toContain("1.2.6"); // minSafe / latest shown
  });
  it("summary view has one row per project with pinning + cve count", () => {
    const out = renderTerminal([audit("alpha"), audit("beta")], "summary");
    expect(out).toContain("alpha");
    expect(out).toContain("beta");
    expect(out).toContain("100%");
  });
  it("tree view uses ASCII bullets and groups under the project name", () => {
    const out = renderTerminal([audit("p")], "tree");
    expect(out).toContain("p");
    expect(out).toContain("- left-pad");
    expect(out).not.toMatch(/[├└│]/);
  });
});
