// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { mkdtempSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JsonCache, sha1, cacheBaseDir } from "../src/cache.js";

const tmp = () => mkdtempSync(join(tmpdir(), "ntc-cache-"));

describe("JsonCache", () => {
  it("round-trips a value", () => {
    const c = new JsonCache(tmp(), 3600);
    c.write(["a", "b"], { x: 1 });
    expect(c.read<{ x: number }>(["a", "b"])).toEqual({ x: 1 });
  });
  it("misses on expiry (backdated mtime)", () => {
    const dir = tmp();
    const c = new JsonCache(dir, 60);
    c.write(["k"], { v: 1 });
    const old = Date.now() / 1000 - 3600;
    utimesSync(join(dir, "k.json"), old, old);
    expect(c.read(["k"])).toBeNull();
  });
  it("ttl<=0 always misses", () => {
    const c = new JsonCache(tmp(), 0);
    c.write(["k"], { v: 1 });
    expect(c.read(["k"])).toBeNull();
  });
  it("missing key returns null", () => {
    expect(new JsonCache(tmp(), 3600).read(["nope"])).toBeNull();
  });
});

describe("sha1 + cacheBaseDir", () => {
  it("sha1 is deterministic hex", () => {
    expect(sha1("left-pad@1.3.0")).toMatch(/^[0-9a-f]{40}$/);
  });
  it("cacheBaseDir honors NPMTASTIC_CACHE_DIR", () => {
    const prev = process.env["NPMTASTIC_CACHE_DIR"];
    process.env["NPMTASTIC_CACHE_DIR"] = "/tmp/xyz";
    expect(cacheBaseDir()).toBe("/tmp/xyz");
    if (prev === undefined) delete process.env["NPMTASTIC_CACHE_DIR"];
    else process.env["NPMTASTIC_CACHE_DIR"] = prev;
  });
});
