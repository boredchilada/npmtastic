// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { mapPool } from "../src/pool.js";

describe("mapPool", () => {
  it("preserves input order", async () => {
    const out = await mapPool([1, 2, 3, 4], 2, async (n) => n * 10);
    expect(out).toEqual([10, 20, 30, 40]);
  });
  it("never exceeds the concurrency limit", async () => {
    let active = 0;
    let peak = 0;
    await mapPool([1, 2, 3, 4, 5, 6], 2, async () => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 5));
      active--;
      return 0;
    });
    expect(peak).toBeLessThanOrEqual(2);
  });
  it("handles empty input", async () => {
    expect(await mapPool([], 4, async () => 1)).toEqual([]);
  });
});
