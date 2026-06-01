// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RegistryClient } from "../src/registry.js";

const SAMPLE = {
  name: "left-pad",
  "dist-tags": { latest: "1.3.0" },
  versions: {
    "1.2.0": { engines: { node: ">=0.10" } },
    "1.3.0": {},
    "1.4.0-rc.1": { deprecated: "do not use" },
  },
  time: { "1.2.0": "2018-01-01T00:00:00Z", "1.3.0": "2019-06-01T00:00:00Z" },
};

function client() {
  return new RegistryClient({ cacheDir: mkdtempSync(join(tmpdir(), "ntc-reg-")), ttlSeconds: 3600 });
}

describe("RegistryClient", () => {
  it("parses releases, dist-tags, deprecation, upload time", async () => {
    const c = client();
    vi.spyOn(c as unknown as { _httpGet: () => Promise<unknown> }, "_httpGet").mockResolvedValue(SAMPLE);
    const meta = await c.fetchOne("left-pad");
    expect(meta?.distTagLatest).toBe("1.3.0");
    expect(meta?.releases.map((r) => r.version).sort()).toEqual(["1.2.0", "1.3.0", "1.4.0-rc.1"]);
    expect(meta?.releases.find((r) => r.version === "1.3.0")?.uploadTime).toBe("2019-06-01T00:00:00Z");
    expect(meta?.releases.find((r) => r.version === "1.4.0-rc.1")?.deprecated).toBe("do not use");
    expect(meta?.releases.find((r) => r.version === "1.2.0")?.enginesNode).toBe(">=0.10");
  });

  it("caches: a second fetch does not hit the network", async () => {
    const c = client();
    const spy = vi.spyOn(c as unknown as { _httpGet: () => Promise<unknown> }, "_httpGet").mockResolvedValue(SAMPLE);
    await c.fetchOne("left-pad");
    await c.fetchOne("left-pad");
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("returns null on network miss", async () => {
    const c = client();
    vi.spyOn(c as unknown as { _httpGet: () => Promise<unknown> }, "_httpGet").mockResolvedValue(null);
    expect(await c.fetchOne("nope")).toBeNull();
  });

  it("fetchMany dedupes names and maps results", async () => {
    const c = client();
    vi.spyOn(c as unknown as { _httpGet: () => Promise<unknown> }, "_httpGet").mockResolvedValue(SAMPLE);
    const map = await c.fetchMany(["left-pad", "left-pad"]);
    expect(map.size).toBe(1);
    expect(map.get("left-pad")?.distTagLatest).toBe("1.3.0");
  });
});
