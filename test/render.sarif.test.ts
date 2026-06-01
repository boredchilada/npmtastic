// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { renderSarif } from "../src/render/sarif.js";
import { makeProjectAudit, makeDepAudit, makeDep, PinStatus, SemverDrift, DepSourceKind } from "../src/models.js";

function auditWithVuln() {
  const dep = makeDep({ name: "minimist", rawName: "minimist", range: "1.2.0", resolved: "1.2.0", source: { kind: DepSourceKind.MANIFEST, path: "package.json", group: "default" }, url: null, direct: true });
  const da = makeDepAudit({
    dep, latest: "1.2.6", latestIncludingPrereleases: "1.2.6", drift: SemverDrift.PATCH, pinStatus: PinStatus.PINNED,
    deprecated: null, vulnerabilities: [{ id: "GHSA-min", aliases: ["CVE-2021-x"], summary: "proto pollution", fixedVersions: ["1.2.6"] }],
    minSafeVersion: "1.2.6", latestReleaseDate: null, latestReleaseAgeDays: null, warnings: [],
  });
  return makeProjectAudit({
    project: { root: "/p", name: "p", sources: [], nodeVersion: null }, deps: [da],
    pinningScore: 1, driftSummary: {}, deprecatedCount: 0, registryUnreachable: 0, vulnCount: 1, vulnUnreachable: 0, suppressedCount: 0,
  });
}

describe("renderSarif", () => {
  it("emits SARIF 2.1.0 with one rule per advisory and one result per (dep, advisory)", () => {
    const sarif = JSON.parse(renderSarif([auditWithVuln()]));
    expect(sarif.version).toBe("2.1.0");
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("npmtastic");
    expect(run.tool.driver.rules.map((r: { id: string }) => r.id)).toContain("GHSA-min");
    expect(run.results).toHaveLength(1);
    expect(run.results[0].ruleId).toBe("GHSA-min");
    expect(run.results[0].level).toBe("error");
    expect(run.results[0].message.text).toContain("minimist");
    expect(run.results[0].locations[0].physicalLocation.artifactLocation.uri).toContain("package.json");
  });
  it("emits an empty results array when there are no vulnerabilities", () => {
    const empty = makeProjectAudit({ project: { root: "/p", name: "p", sources: [], nodeVersion: null }, deps: [], pinningScore: null, driftSummary: {}, deprecatedCount: 0, registryUnreachable: 0, vulnCount: 0, vulnUnreachable: 0, suppressedCount: 0 });
    const sarif = JSON.parse(renderSarif([empty]));
    expect(sarif.runs[0].results).toEqual([]);
    expect(sarif.runs[0].tool.driver.rules).toEqual([]);
  });
});
