// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync, writeFileSync, mkdirSync, statSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { createHash } from "node:crypto";

export function cacheBaseDir(): string {
  const override = process.env["NPMTASTIC_CACHE_DIR"];
  if (override && override.length > 0) return override;
  const xdg = process.env["XDG_CACHE_HOME"];
  if (xdg && xdg.length > 0) return join(xdg, "npmtastic");
  return join(homedir(), ".cache", "npmtastic");
}

export function sha1(input: string): string {
  return createHash("sha1").update(input).digest("hex");
}

export class JsonCache {
  constructor(
    private readonly dir: string,
    private readonly ttlSeconds: number,
    private readonly offline = false,
    readonly enabled = true,
  ) {}
  private pathFor(segments: string[]): string {
    return join(this.dir, ...segments) + ".json";
  }

  read<T>(segments: string[]): T | null {
    if (!this.offline && this.ttlSeconds <= 0) return null;
    const p = this.pathFor(segments);
    if (!existsSync(p)) return null;
    try {
      const ageSeconds = (Date.now() - statSync(p).mtimeMs) / 1000;
      // Offline: an old answer beats no answer, so the TTL is ignored.
      if (!this.offline && ageSeconds > this.ttlSeconds) return null;
      return JSON.parse(readFileSync(p, "utf-8")) as T;
    } catch {
      return null;
    }
  }

  write(segments: string[], value: unknown): void {
    if (!this.enabled) return;
    if (this.offline) return;
    const p = this.pathFor(segments);
    try {
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, JSON.stringify(value));
    } catch {
      // cache write failures are non-fatal
    }
  }
}
