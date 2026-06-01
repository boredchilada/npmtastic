// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { VulnClient, parseOsvPayload, dedupeVulns, computeMinSafeVersion } from "../src/vulns.js";

const OSV_SAMPLE = {
  vulns: [
    {
      id: "GHSA-aaaa",
      aliases: ["CVE-2020-1"],
      summary: "bad thing",
      affected: [
        { ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.3.1" }] }] },
        { ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.4.0" }] }] },
      ],
    },
    {
      id: "GHSA-aaaa",
      aliases: ["GHSA-aaaa"],
      affected: [{ ranges: [{ events: [{ fixed: "1.3.1" }] }] }],
    },
  ],
};

function client() {
  return new VulnClient({ cacheDir: mkdtempSync(join(tmpdir(), "ntc-vuln-")), ttlSeconds: 3600 });
}

describe("parseOsvPayload + dedupeVulns", () => {
  it("collapses duplicate ids and unions fixed versions + aliases", () => {
    const deduped = dedupeVulns(parseOsvPayload(OSV_SAMPLE));
    expect(deduped.length).toBe(1);
    expect(deduped[0]!.id).toBe("GHSA-aaaa");
    expect([...deduped[0]!.fixedVersions].sort()).toEqual(["1.3.1", "1.4.0"]);
    expect([...deduped[0]!.aliases].sort()).toEqual(["CVE-2020-1", "GHSA-aaaa"]);
    expect(deduped[0]!.summary).toBe("bad thing");
  });
  it("tolerates junk payloads", () => {
    expect(parseOsvPayload(null)).toEqual([]);
    expect(parseOsvPayload({ vulns: "nope" })).toEqual([]);
    expect(parseOsvPayload({})).toEqual([]);
  });
});

describe("computeMinSafeVersion", () => {
  it("picks the lowest fix above installed, max across advisories", () => {
    const vulns = [
      { id: "a", aliases: [], summary: null, fixedVersions: ["1.3.1", "1.4.0"] },
      { id: "b", aliases: [], summary: null, fixedVersions: ["1.5.0"] },
    ];
    expect(computeMinSafeVersion("1.2.0", vulns)).toBe("1.5.0");
  });
  it("returns null if any advisory has no fix above installed", () => {
    const vulns = [{ id: "a", aliases: [], summary: null, fixedVersions: ["1.0.0"] }];
    expect(computeMinSafeVersion("1.2.0", vulns)).toBeNull();
  });
  it("returns null for an invalid installed version", () => {
    expect(computeMinSafeVersion("not-a-version", [{ id: "a", aliases: [], summary: null, fixedVersions: ["2.0.0"] }])).toBeNull();
  });
});

describe("VulnClient", () => {
  it("fetchFor maps (name,version) → deduped vulns", async () => {
    const c = client();
    vi.spyOn(c as unknown as { _runOsvQuery: () => Promise<unknown> }, "_runOsvQuery").mockResolvedValue(OSV_SAMPLE);
    const map = await c.fetchFor([{ name: "left-pad", version: "1.3.0" }]);
    expect(map.get("left-pad@1.3.0")?.length).toBe(1);
  });
  it("marks unreachable on network miss (never silently clean)", async () => {
    const c = client();
    vi.spyOn(c as unknown as { _runOsvQuery: () => Promise<unknown> }, "_runOsvQuery").mockResolvedValue(null);
    const map = await c.fetchFor([{ name: "x", version: "1.0.0" }]);
    expect(map.get("x@1.0.0")).toBeUndefined();
    expect(c.unreachable.has("x@1.0.0")).toBe(true);
  });
  it("caches empty results so clean pins do not re-query", async () => {
    const c = client();
    const spy = vi.spyOn(c as unknown as { _runOsvQuery: () => Promise<unknown> }, "_runOsvQuery").mockResolvedValue({ vulns: [] });
    await c.fetchFor([{ name: "clean", version: "1.0.0" }]);
    await c.fetchFor([{ name: "clean", version: "1.0.0" }]);
    expect(spy).toHaveBeenCalledTimes(1);
  });
});

const NPM_BULK_SAMPLE = {
  minimist: [
    { id: 1179, github_advisory_id: "GHSA-min", title: "proto pollution", url: "https://x", vulnerable_versions: "<1.2.6", severity: "high" },
  ],
};

describe("VulnClient npm-audit source", () => {
  it("source=npm-audit matches vulnerable_versions and maps to Vulnerability", async () => {
    const c = new VulnClient({ cacheDir: mkdtempSync(join(tmpdir(), "ntc-npm-")), ttlSeconds: 3600, source: "npm-audit" });
    vi.spyOn(c as unknown as { _runNpmAudit: (n: string, v: string) => Promise<unknown> }, "_runNpmAudit").mockResolvedValue(NPM_BULK_SAMPLE);
    const map = await c.fetchFor([{ name: "minimist", version: "1.2.0" }]);
    const vulns = map.get("minimist@1.2.0") ?? [];
    expect(vulns.length).toBe(1);
    expect(vulns[0]!.id).toBe("GHSA-min");
  });
  it("source=npm-audit skips advisories whose range excludes the version", async () => {
    const c = new VulnClient({ cacheDir: mkdtempSync(join(tmpdir(), "ntc-npm2-")), ttlSeconds: 3600, source: "npm-audit" });
    vi.spyOn(c as unknown as { _runNpmAudit: (n: string, v: string) => Promise<unknown> }, "_runNpmAudit").mockResolvedValue(NPM_BULK_SAMPLE);
    const map = await c.fetchFor([{ name: "minimist", version: "1.2.6" }]); // not < 1.2.6
    expect((map.get("minimist@1.2.6") ?? []).length).toBe(0);
  });
  it("source=both unions OSV + npm-audit deduped by id", async () => {
    const c = new VulnClient({ cacheDir: mkdtempSync(join(tmpdir(), "ntc-both-")), ttlSeconds: 3600, source: "both" });
    vi.spyOn(c as unknown as { _runOsvQuery: () => Promise<unknown> }, "_runOsvQuery").mockResolvedValue({ vulns: [{ id: "GHSA-min", aliases: [], summary: "osv", affected: [{ ranges: [{ events: [{ fixed: "1.2.6" }] }] }] }] });
    vi.spyOn(c as unknown as { _runNpmAudit: () => Promise<unknown> }, "_runNpmAudit").mockResolvedValue(NPM_BULK_SAMPLE);
    const vulns = (await c.fetchFor([{ name: "minimist", version: "1.2.0" }])).get("minimist@1.2.0") ?? [];
    expect(vulns.length).toBe(1); // same advisory id from both → deduped
    expect(vulns[0]!.fixedVersions).toContain("1.2.6"); // OSV's fixed version survives the union
  });
});
