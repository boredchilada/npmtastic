// SPDX-License-Identifier: AGPL-3.0-or-later
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { info } from "./logging.js";

const GIT_PREFIXES = ["http://", "https://", "git@", "ssh://", "git://"] as const;
const SHORTHAND = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export function splitRef(source: string): [string, string | null] {
  if (!source.includes("#")) return [source, null];
  const idx = source.lastIndexOf("#");
  const base = source.slice(0, idx);
  const ref = source.slice(idx + 1);
  return [base, ref || null];
}

export function isRemote(source: string): boolean {
  const [base] = splitRef(source);
  if (base === "." || base === "..") return false;
  if (base.startsWith("/") || base.startsWith("./") || base.startsWith("../")) return false;
  if (base.startsWith("\\") || base.startsWith(".\\") || base.startsWith("..\\")) return false;
  if (/^[A-Za-z]:[\\/]/.test(base)) return false;
  if (GIT_PREFIXES.some((p) => base.startsWith(p)) || base.endsWith(".git")) return true;
  if (existsSync(base)) return false;
  return SHORTHAND.test(base);
}

function toUrl(base: string): string {
  if (GIT_PREFIXES.some((p) => base.startsWith(p)) || base.endsWith(".git")) return base;
  if (SHORTHAND.test(base)) return `https://github.com/${base}`;
  return base;
}

function runGit(args: string[]): { status: number; stderr: string; stdout: string } {
  const result = spawnSync("git", args, { encoding: "utf8" });
  if (result.error) {
    const err = result.error as NodeJS.ErrnoException;
    if (err.code === "ENOENT") throw new Error("git is not available");
    throw new Error(`could not execute git: ${err.message}`);
  }
  return {
    status: result.status ?? 1,
    stderr: result.stderr ?? "",
    stdout: result.stdout ?? "",
  };
}

function clone(source: string, dest: string): void {
  const [base, ref] = splitRef(source);
  const url = toUrl(base);
  if (!ref) {
    const result = runGit(["clone", "--depth", "1", url, dest]);
    if (result.status !== 0) throw new Error(`git clone failed: ${result.stderr.trim()}`);
    return;
  }
  const commands = [
    ["init", dest],
    ["-C", dest, "remote", "add", "origin", url],
    ["-C", dest, "fetch", "--depth", "1", "origin", ref],
    ["-C", dest, "checkout", "--detach", "FETCH_HEAD"],
  ];
  for (const command of commands) {
    const result = runGit(command);
    if (result.status !== 0) {
      const detail = result.stderr.trim() || result.stdout.trim();
      throw new Error(`git fetch/checkout ${ref} failed: ${detail}`);
    }
  }
}

/** Yield a local directory for `source`; clean up any temp clone after. */
export async function acquire<T>(
  source: string,
  keep: boolean,
  fn: (root: string) => Promise<T>,
): Promise<T> {
  if (!isRemote(source)) return fn(source);
  const tmp = mkdtempSync(join(tmpdir(), "npmtastic_"));
  const cloneDir = join(tmp, "repo");
  try {
    info(`cloning ${source}`);
    clone(source, cloneDir);
    return await fn(cloneDir);
  } finally {
    if (keep) info(`kept clone at ${cloneDir}`);
    else rmSync(tmp, { recursive: true, force: true });
  }
}
