// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, cpSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { updateProject } from "../src/update.js";
import { RegistryClient } from "../src/registry.js";
import { VulnClient } from "../src/vulns.js";
import { discoverOne } from "../src/discovery.js";

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(here, "fixtures", "update-sample");

function copyFixture(): string {
  const d = mkdtempSync(join(tmpdir(), "ntc-upd-"));
  cpSync(FIXTURE, d, { recursive: true });
  return d;
}

function clients(reg: (name: string) => unknown, osv: (n: string, v: string) => unknown) {
  const registry = new RegistryClient({ cacheDir: mkdtempSync(join(tmpdir(), "r-")), ttlSeconds: 3600 });
  vi.spyOn(registry as unknown as { _httpGet: (u: string) => Promise<unknown> }, "_httpGet").mockImplementation(
    async (url: string) => reg(decodeURIComponent(url.split("/").slice(3).join("/"))),
  );
  const vuln = new VulnClient({ cacheDir: mkdtempSync(join(tmpdir(), "v-")), ttlSeconds: 3600 });
  vi.spyOn(vuln as unknown as { _runOsvQuery: (n: string, v: string) => Promise<unknown> }, "_runOsvQuery").mockImplementation(
    async (n: string, v: string) => osv(n, v),
  );
  return { registry, vuln };
}
const reg = (name: string) =>
  name === "left-pad" ? { name, "dist-tags": { latest: "1.9.0" }, versions: { "1.0.0": {}, "1.3.0": {}, "1.9.0": {} }, time: {} } : null;
const noVulns = () => ({ vulns: [] });

describe("updateProject", () => {
  it("--pin freezes the caret dep to its resolved version, writes, and tests install", async () => {
    const root = copyFixture();
    const { registry, vuln } = clients(reg, noVulns);
    const installer = vi.fn(async () => true);
    const res = await updateProject(discoverOne(root), registry, vuln, { pin: true, test: true, installer });

    expect(res.changes.find((c) => c.name === "left-pad")).toMatchObject({ from: "^1.0.0", to: "1.3.0" });
    expect(readFileSync(join(root, "package.json"), "utf-8")).toContain('"left-pad": "1.3.0"');
    expect(res.tested).toBe(true);
    expect(res.testPassed).toBe(true);
    expect(installer).toHaveBeenCalledOnce();
    expect(res.backupPath && existsSync(res.backupPath)).toBe(true);
  });

  it("rolls back the manifest when the test install fails", async () => {
    const root = copyFixture();
    const original = readFileSync(join(root, "package.json"), "utf-8");
    const { registry, vuln } = clients(reg, noVulns);
    const installer = vi.fn(async () => false);
    const res = await updateProject(discoverOne(root), registry, vuln, { pin: true, test: true, installer });

    expect(res.testPassed).toBe(false);
    expect(readFileSync(join(root, "package.json"), "utf-8")).toBe(original);
  });

  it("--dry-run computes changes but writes nothing", async () => {
    const root = copyFixture();
    const original = readFileSync(join(root, "package.json"), "utf-8");
    const { registry, vuln } = clients(reg, noVulns);
    const res = await updateProject(discoverOne(root), registry, vuln, { pin: true, dryRun: true });

    expect(res.changes.length).toBeGreaterThan(0);
    expect(res.backupPath).toBeNull();
    expect(res.tested).toBe(false);
    expect(readFileSync(join(root, "package.json"), "utf-8")).toBe(original);
  });
});
