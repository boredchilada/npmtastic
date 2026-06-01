// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { gatesTripped, filterAudits, main, EXIT_OK, EXIT_GATE } from "../src/cli.js";
import { RegistryClient } from "../src/registry.js";
import { VulnClient } from "../src/vulns.js";
import { makeProjectAudit, makeDepAudit, makeDep, PinStatus, SemverDrift, DepSourceKind } from "../src/models.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (p: string) => join(here, "fixtures", p);

function depAudit(name: string, drift: SemverDrift, vulnCount: number, ageDays: number | null) {
  return makeDepAudit({
    dep: makeDep({ name, rawName: name, range: "1.0.0", resolved: "1.0.0", source: { kind: DepSourceKind.MANIFEST, path: "package.json", group: "default" }, url: null, direct: true }),
    latest: "2.0.0", latestIncludingPrereleases: "2.0.0", drift, pinStatus: PinStatus.PINNED, deprecated: null,
    vulnerabilities: Array.from({ length: vulnCount }, (_, i) => ({ id: `V-${name}-${i}`, aliases: [], summary: null, fixedVersions: [] })),
    minSafeVersion: null, latestReleaseDate: null, latestReleaseAgeDays: ageDays, warnings: [],
  });
}
function proj(name: string, deps: ReturnType<typeof depAudit>[]) {
  const vulnCount = deps.reduce((n, d) => n + d.vulnerabilities.length, 0);
  return makeProjectAudit({ project: { root: "/p", name, sources: [], nodeVersion: null }, deps, pinningScore: 1, driftSummary: {}, deprecatedCount: 0, registryUnreachable: 0, vulnCount, vulnUnreachable: 0, suppressedCount: 0 });
}

describe("gatesTripped", () => {
  const audits = [proj("p", [depAudit("a", SemverDrift.MINOR, 0, 30), depAudit("b", SemverDrift.NONE, 1, 500)])];
  it("fail-on-drift trips when a dep meets the threshold", () => {
    expect(gatesTripped(audits, { failOnDrift: "minor" })).toBe(true);
    expect(gatesTripped(audits, { failOnDrift: "major" })).toBe(false);
  });
  it("fail-on-vuln any / N", () => {
    expect(gatesTripped(audits, { failOnVuln: "any" })).toBe(true);
    expect(gatesTripped(audits, { failOnVuln: "2" })).toBe(false);
  });
  it("fail-on-age trips on a stale latest (strict >)", () => {
    expect(gatesTripped(audits, { failOnAge: 365 })).toBe(true);
    expect(gatesTripped(audits, { failOnAge: 500 })).toBe(false);
  });
  it("no gates → never trips", () => {
    expect(gatesTripped(audits, {})).toBe(false);
  });
});

describe("filterAudits", () => {
  const audits = [proj("p", [depAudit("a", SemverDrift.MINOR, 0, null), depAudit("b", SemverDrift.NONE, 1, null)])];
  it("vulnerable-only keeps only deps with vulns, drops emptied projects", () => {
    const out = filterAudits(audits, { vulnerableOnly: true });
    expect(out[0]?.deps.map((d) => d.dep.name)).toEqual(["b"]);
  });
  it("drift-min keeps deps at/above the level", () => {
    const out = filterAudits(audits, { driftMin: "minor" });
    expect(out[0]?.deps.map((d) => d.dep.name)).toEqual(["a"]);
  });
  it("no filter → unchanged", () => {
    expect(filterAudits(audits, {})[0]?.deps.length).toBe(2);
  });
});

describe("main (integration, mocked clients)", () => {
  let out = "";
  beforeEach(() => {
    out = "";
    vi.spyOn(process.stdout, "write").mockImplementation((s: string | Uint8Array) => { out += String(s); return true; });
    vi.spyOn(RegistryClient.prototype as unknown as { _httpGet: (u: string) => Promise<unknown> }, "_httpGet").mockImplementation(async (url: string) => {
      const name = decodeURIComponent(url.split("/").slice(3).join("/"));
      if (name === "left-pad") return { name, "dist-tags": { latest: "2.0.0" }, versions: { "1.3.0": {}, "2.0.0": {} }, time: {} };
      if (name === "minimist") return { name, "dist-tags": { latest: "1.2.6" }, versions: { "1.2.0": {}, "1.2.6": {} }, time: {} };
      return null;
    });
    vi.spyOn(VulnClient.prototype as unknown as { _runOsvQuery: (n: string, v: string) => Promise<unknown> }, "_runOsvQuery").mockImplementation(async (name: string, version: string) => {
      if (name === "minimist" && version === "1.2.0") return { vulns: [{ id: "GHSA-min", aliases: [], summary: "x", affected: [{ ranges: [{ events: [{ fixed: "1.2.6" }] }] }] }] };
      return { vulns: [] };
    });
  });

  it("audit --json --no-cache emits parseable JSON and exits OK", async () => {
    const code = await main(["audit", fx("audit-sample"), "--json", "--no-cache"]);
    expect(code).toBe(EXIT_OK);
    const parsed = JSON.parse(out);
    expect(parsed.kind).toBe("audit");
    expect(parsed.projects[0].deps.find((d: { name: string }) => d.name === "minimist").vulnerabilities.length).toBe(1);
  });

  it("--fail-on-vuln any returns EXIT_GATE when a CVE is present", async () => {
    const code = await main(["audit", fx("audit-sample"), "--json", "--no-cache", "--fail-on-vuln", "any"]);
    expect(code).toBe(EXIT_GATE);
  });
});
