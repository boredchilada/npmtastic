// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from "vitest";
import { mkdtempSync, cpSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { main, EXIT_OK } from "../src/cli.js";
import { RegistryClient } from "../src/registry.js";
import { VulnClient } from "../src/vulns.js";

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(here, "fixtures", "update-sample");

describe("cli update (integration)", () => {
  beforeEach(() => {
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    vi.spyOn(RegistryClient.prototype as unknown as { _httpGet: (u: string) => Promise<unknown> }, "_httpGet").mockImplementation(
      async (url: string) => {
        const name = decodeURIComponent(url.split("/").slice(3).join("/"));
        return name === "left-pad" ? { name, "dist-tags": { latest: "1.9.0" }, versions: { "1.0.0": {}, "1.3.0": {}, "1.9.0": {} }, time: {} } : null;
      },
    );
    vi.spyOn(VulnClient.prototype as unknown as { _runOsvQuery: () => Promise<unknown> }, "_runOsvQuery").mockResolvedValue({ vulns: [] });
  });

  it("update --pin --no-test rewrites package.json in place and exits OK", async () => {
    const root = mkdtempSync(join(tmpdir(), "ntc-cliupd-"));
    cpSync(FIXTURE, root, { recursive: true });
    const code = await main(["update", root, "--pin", "--no-test", "--no-cache"]);
    expect(code).toBe(EXIT_OK);
    expect(readFileSync(join(root, "package.json"), "utf-8")).toContain('"left-pad": "1.3.0"');
  });

  it("update --dry-run does not modify package.json", async () => {
    const root = mkdtempSync(join(tmpdir(), "ntc-clidry-"));
    cpSync(FIXTURE, root, { recursive: true });
    const before = readFileSync(join(root, "package.json"), "utf-8");
    const code = await main(["update", root, "--pin", "--dry-run", "--no-cache"]);
    expect(code).toBe(EXIT_OK);
    expect(readFileSync(join(root, "package.json"), "utf-8")).toBe(before);
  });
});
