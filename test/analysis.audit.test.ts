// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { discoverOne } from "../src/discovery.js";
import { auditProject } from "../src/analysis.js";
import { RegistryClient } from "../src/registry.js";
import { VulnClient } from "../src/vulns.js";
import { PinStatus, SemverDrift } from "../src/models.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (p: string) => join(here, "fixtures", p);

function regPayload(name: string): unknown {
  if (name === "left-pad") {
    return { name, "dist-tags": { latest: "2.0.0" }, versions: { "1.0.0": {}, "1.3.0": {}, "2.0.0": {} }, time: { "2.0.0": "2021-01-01T00:00:00Z" } };
  }
  if (name === "minimist") {
    return { name, "dist-tags": { latest: "1.2.6" }, versions: { "1.2.0": {}, "1.2.6": {} }, time: {} };
  }
  return null; // "transitive" → registry miss
}

function makeClients() {
  const registry = new RegistryClient({ cacheDir: mkdtempSync(join(tmpdir(), "ntc-areg-")), ttlSeconds: 3600 });
  vi.spyOn(registry as unknown as { _httpGet: (u: string) => Promise<unknown> }, "_httpGet").mockImplementation(
    async (url: string) => {
      const name = decodeURIComponent(url.split("/").slice(3).join("/"));
      return regPayload(name);
    },
  );
  const vuln = new VulnClient({ cacheDir: mkdtempSync(join(tmpdir(), "ntc-avuln-")), ttlSeconds: 3600 });
  vi.spyOn(vuln as unknown as { _runOsvQuery: (n: string, v: string) => Promise<unknown> }, "_runOsvQuery").mockImplementation(
    async (name: string, version: string) => {
      if (name === "minimist" && version === "1.2.0") {
        return { vulns: [{ id: "GHSA-min", aliases: ["CVE-2021-x"], summary: "bad", affected: [{ ranges: [{ events: [{ fixed: "1.2.6" }] }] }] }] };
      }
      return { vulns: [] };
    },
  );
  return { registry, vuln };
}

describe("auditProject", () => {
  it("produces a ProjectAudit with posture, drift, vulns, rollups", async () => {
    const { registry, vuln } = makeClients();
    const audit = await auditProject(discoverOne(fx("audit-sample")), registry, vuln, {});
    const byName = Object.fromEntries(audit.deps.map((d) => [d.dep.name, d]));

    expect(byName["left-pad"].pinStatus).toBe(PinStatus.COMPATIBLE);
    expect(byName["left-pad"].drift).toBe(SemverDrift.MAJOR);
    expect(byName["left-pad"].latest).toBe("2.0.0");

    expect(byName["minimist"].pinStatus).toBe(PinStatus.PINNED);
    expect(byName["minimist"].drift).toBe(SemverDrift.PATCH);
    expect(byName["minimist"].vulnerabilities.length).toBe(1);
    expect(byName["minimist"].minSafeVersion).toBe("1.2.6");

    expect(byName["transitive"].dep.direct).toBe(false);
    expect(byName["transitive"].drift).toBe(SemverDrift.UNKNOWN);

    expect(audit.vulnCount).toBe(1);
    expect(audit.registryUnreachable).toBe(1);
    expect(audit.pinningScore).toBe(1);
    expect(audit.driftSummary[SemverDrift.MAJOR]).toBe(1);
    expect(audit.driftSummary[SemverDrift.PATCH]).toBe(1);
    expect(audit.driftSummary[SemverDrift.UNKNOWN]).toBe(1);
  });
});
