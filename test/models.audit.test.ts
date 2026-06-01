// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { makeDepAudit, makeProjectAudit, SemverDrift, PinStatus, DepSourceKind, makeDep } from "../src/models.js";

describe("audit models", () => {
  it("makeDepAudit freezes nested arrays", () => {
    const dep = makeDep({ name: "a", rawName: "a", range: "^1", resolved: "1.0.0", source: { kind: DepSourceKind.MANIFEST, path: "p", group: "default" }, url: null, direct: true });
    const da = makeDepAudit({
      dep, latest: "1.2.0", latestIncludingPrereleases: "1.3.0-rc.1",
      drift: SemverDrift.MINOR, pinStatus: PinStatus.COMPATIBLE, deprecated: null,
      vulnerabilities: [], minSafeVersion: null, latestReleaseDate: null,
      latestReleaseAgeDays: null, warnings: [],
    });
    expect(Object.isFrozen(da)).toBe(true);
    expect(Object.isFrozen(da.vulnerabilities)).toBe(true);
    expect(da.drift).toBe("minor");
  });
  it("makeProjectAudit freezes deps + driftSummary", () => {
    const pa = makeProjectAudit({
      project: { root: "r", name: "n", sources: [], nodeVersion: null },
      deps: [], pinningScore: null, driftSummary: { none: 0 },
      deprecatedCount: 0, registryUnreachable: 0, vulnCount: 0, vulnUnreachable: 0, suppressedCount: 0,
    });
    expect(Object.isFrozen(pa)).toBe(true);
    expect(Object.isFrozen(pa.deps)).toBe(true);
  });
});
