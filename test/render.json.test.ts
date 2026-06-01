// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { renderAuditJson, SCHEMA_VERSION } from "../src/render/json.js";
import { makeProjectAudit, makeDepAudit, makeDep, PinStatus, SemverDrift, DepSourceKind } from "../src/models.js";

function sampleAudit() {
  const dep = makeDep({ name: "left-pad", rawName: "left-pad", range: "^1.0.0", resolved: "1.3.0", source: { kind: DepSourceKind.MANIFEST, path: "package.json", group: "default" }, url: null, direct: true });
  const da = makeDepAudit({
    dep, latest: "2.0.0", latestIncludingPrereleases: "2.0.0", drift: SemverDrift.MAJOR, pinStatus: PinStatus.COMPATIBLE,
    deprecated: null, vulnerabilities: [{ id: "GHSA-x", aliases: ["CVE-1"], summary: "bad", fixedVersions: ["1.3.1"] }],
    minSafeVersion: "1.3.1", latestReleaseDate: "2021-01-01T00:00:00Z", latestReleaseAgeDays: 100, warnings: [],
  });
  return makeProjectAudit({
    project: { root: "/p", name: "p", sources: [], nodeVersion: null }, deps: [da],
    pinningScore: 1, driftSummary: { none: 0, major: 1 }, deprecatedCount: 0, registryUnreachable: 0,
    vulnCount: 1, vulnUnreachable: 0, suppressedCount: 0,
  });
}

describe("renderAuditJson", () => {
  it("emits kind=audit, schemaVersion, and a parseable structure", () => {
    const out = JSON.parse(renderAuditJson([sampleAudit()]));
    expect(out.kind).toBe("audit");
    expect(out.schemaVersion).toBe(SCHEMA_VERSION);
    expect(out.projects).toHaveLength(1);
    const p = out.projects[0];
    expect(p.name).toBe("p");
    expect(p.vulnCount).toBe(1);
    const d = p.deps[0];
    expect(d.name).toBe("left-pad");
    expect(d.pinStatus).toBe("compatible");
    expect(d.drift).toBe("major");
    expect(d.resolved).toBe("1.3.0");
    expect(d.group).toBe("default");
    expect(d.vulnerabilities[0].id).toBe("GHSA-x");
    expect(d.minSafeVersion).toBe("1.3.1");
  });
});
