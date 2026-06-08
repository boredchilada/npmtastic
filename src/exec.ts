// SPDX-License-Identifier: AGPL-3.0-or-later
import { existsSync, mkdtempSync, writeFileSync, copyFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { warn } from "./logging.js";

export type PackageManager = "npm" | "pnpm" | "yarn";

export function detectPackageManager(projectRoot: string): PackageManager {
  if (existsSync(join(projectRoot, "pnpm-lock.yaml"))) return "pnpm";
  if (existsSync(join(projectRoot, "yarn.lock"))) return "yarn";
  return "npm";
}

export interface RunResult {
  code: number;
  output: string;
}

export type RunFn = (cmd: string, args: string[], cwd: string, timeoutMs: number) => Promise<RunResult>;

// The real subprocess boundary. Tests inject a fake `run` instead of calling this.
// On Windows the package managers are `.cmd` shims; since the CVE-2024-27980 fix,
// spawning a `.cmd` without `shell: true` throws EINVAL. The command + args here are
// fully controlled (a package-manager name + literal flags, no untrusted input), so
// running through the shell on Windows is safe.
export const defaultRun: RunFn = (cmd, args, cwd, timeoutMs) =>
  new Promise<RunResult>((resolve) => {
    const child = spawn(cmd, args, { cwd, shell: process.platform === "win32" });
    let output = "";
    const timer = setTimeout(() => {
      child.kill();
      resolve({ code: 124, output: output + "\n[timeout]" });
    }, timeoutMs);
    child.stdout?.on("data", (d: Buffer) => (output += d.toString()));
    child.stderr?.on("data", (d: Buffer) => (output += d.toString()));
    child.on("error", (e) => {
      clearTimeout(timer);
      resolve({ code: 127, output: String(e) });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, output });
    });
  });

const LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"];

export interface TestInstallOptions {
  pm?: PackageManager;
  timeoutMs?: number;
  run?: RunFn;
}

/**
 * Validate that `newManifestText` installs cleanly WITHOUT touching the real
 * project: copy the manifest + any lockfiles into a temp dir and install there.
 */
export async function testInstall(
  projectRoot: string,
  newManifestText: string,
  opts: TestInstallOptions = {},
): Promise<boolean> {
  const pm = opts.pm ?? detectPackageManager(projectRoot);
  const run = opts.run ?? defaultRun;
  const timeoutMs = opts.timeoutMs ?? 120_000;
  const dir = mkdtempSync(join(tmpdir(), "npmtastic-test-"));
  try {
    writeFileSync(join(dir, "package.json"), newManifestText);
    for (const lf of LOCKFILES) {
      const src = join(projectRoot, lf);
      if (existsSync(src)) copyFileSync(src, join(dir, lf));
    }
    // Bare name on both platforms; on Windows defaultRun's shell resolves the .cmd shim.
    const { code, output } = await run(pm, ["install"], dir, timeoutMs);
    if (code !== 0) {
      warn(`test install (${pm}) failed: ${output.split("\n").slice(-3).join(" ").slice(0, 300)}`);
    }
    return code === 0;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
