// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, cpSync, readFileSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { main, EXIT_OK, EXIT_ERROR } from "../src/cli.js";

const here = dirname(fileURLToPath(import.meta.url));
const NPM_FX = join(here, "fixtures", "bootstrap-npm");

describe("cli bootstrap (integration)", () => {
  let out = "";
  beforeEach(() => {
    out = "";
    vi.spyOn(process.stdout, "write").mockImplementation((s: string | Uint8Array) => { out += String(s); return true; });
  });

  it("prints reconstructed package.json to stdout by default, writes nothing", async () => {
    const code = await main(["bootstrap", NPM_FX]);
    expect(code).toBe(EXIT_OK);
    const parsed = JSON.parse(out);
    expect(parsed.name).toBe("recovered");
    expect(parsed.dependencies["left-pad"]).toBe("^1.3.0");
  });

  it("--write creates package.json when absent", async () => {
    const root = mkdtempSync(join(tmpdir(), "ntc-bw-"));
    cpSync(NPM_FX, root, { recursive: true });
    const code = await main(["bootstrap", root, "--write"]);
    expect(code).toBe(EXIT_OK);
    expect(existsSync(join(root, "package.json"))).toBe(true);
    expect(JSON.parse(readFileSync(join(root, "package.json"), "utf-8")).name).toBe("recovered");
  });

  it("--write refuses when package.json already exists (no --force)", async () => {
    const root = mkdtempSync(join(tmpdir(), "ntc-bwex-"));
    cpSync(NPM_FX, root, { recursive: true });
    writeFileSync(join(root, "package.json"), '{"name":"keep"}');
    const code = await main(["bootstrap", root, "--write"]);
    expect(code).toBe(EXIT_ERROR);
    expect(JSON.parse(readFileSync(join(root, "package.json"), "utf-8")).name).toBe("keep");
  });

  it("--write --force backs up then overwrites", async () => {
    const root = mkdtempSync(join(tmpdir(), "ntc-bwf-"));
    cpSync(NPM_FX, root, { recursive: true });
    writeFileSync(join(root, "package.json"), '{"name":"old"}');
    const code = await main(["bootstrap", root, "--write", "--force"]);
    expect(code).toBe(EXIT_OK);
    expect(JSON.parse(readFileSync(join(root, "package.json"), "utf-8")).name).toBe("recovered");
    expect(existsSync(join(root, ".npmtastic_backups"))).toBe(true);
  });
});
