// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { updateProject } from "../src/update.js";
import { RegistryClient } from "../src/registry.js";
import { VulnClient } from "../src/vulns.js";
import { discoverOne } from "../src/discovery.js";

describe("update preserves the manifest's actual key casing", () => {
  it("rewrites a mixed-case dependency name using the manifest key", async () => {
    const root = mkdtempSync(join(tmpdir(), "ntc-case-"));
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "x", dependencies: { "Lodash": "^4.0.0" } }, null, 2) + "\n");
    writeFileSync(join(root, "package-lock.json"), JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": {}, "node_modules/Lodash": { version: "4.17.21" } } }));
    const registry = new RegistryClient({ cacheDir: mkdtempSync(join(tmpdir(), "r-")), ttlSeconds: 3600 });
    vi.spyOn(registry as unknown as { _httpGet: () => Promise<unknown> }, "_httpGet").mockResolvedValue({ name: "lodash", "dist-tags": { latest: "4.17.21" }, versions: { "4.17.21": {} }, time: {} });
    const vuln = new VulnClient({ cacheDir: mkdtempSync(join(tmpdir(), "v-")), ttlSeconds: 3600 });
    vi.spyOn(vuln as unknown as { _runOsvQuery: () => Promise<unknown> }, "_runOsvQuery").mockResolvedValue({ vulns: [] });

    const res = await updateProject(discoverOne(root), registry, vuln, { pin: true, test: false });
    expect(res.changes.find((c) => c.name === "lodash")).toMatchObject({ to: "4.17.21" });
    expect(readFileSync(join(root, "package.json"), "utf-8")).toContain('"Lodash": "4.17.21"');
  });
});
