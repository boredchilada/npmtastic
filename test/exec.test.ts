// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detectPackageManager, testInstall, type RunFn } from "../src/exec.js";

function tmp(files: string[] = []): string {
  const d = mkdtempSync(join(tmpdir(), "ntc-exec-"));
  for (const f of files) writeFileSync(join(d, f), "");
  return d;
}

describe("detectPackageManager", () => {
  it("pnpm-lock.yaml → pnpm", () => expect(detectPackageManager(tmp(["pnpm-lock.yaml"]))).toBe("pnpm"));
  it("yarn.lock → yarn", () => expect(detectPackageManager(tmp(["yarn.lock"]))).toBe("yarn"));
  it("package-lock.json → npm", () => expect(detectPackageManager(tmp(["package-lock.json"]))).toBe("npm"));
  it("nothing → npm (default)", () => expect(detectPackageManager(tmp())).toBe("npm"));
});

describe("testInstall", () => {
  it("returns true when the install command exits 0", async () => {
    const run: RunFn = async (cmd, args) => {
      expect(args).toEqual(["install"]);
      expect(cmd.startsWith("npm")).toBe(true);
      return { code: 0, output: "ok" };
    };
    const ok = await testInstall(tmp(["package-lock.json"]), '{"name":"x"}', { run });
    expect(ok).toBe(true);
  });
  it("returns false when the install command exits non-zero", async () => {
    const run: RunFn = async () => ({ code: 1, output: "boom" });
    const ok = await testInstall(tmp(["package-lock.json"]), '{"name":"x"}', { run });
    expect(ok).toBe(false);
  });
  it("uses the detected package manager's command", async () => {
    const seen: string[] = [];
    const run: RunFn = async (cmd) => { seen.push(cmd); return { code: 0, output: "" }; };
    await testInstall(tmp(["pnpm-lock.yaml"]), '{"name":"x"}', { run });
    expect(seen[0]!.startsWith("pnpm")).toBe(true);
  });
});
