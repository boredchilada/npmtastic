// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { pickLatest } from "../src/analysis.js";
import type { PackageMeta } from "../src/models.js";

function meta(releases: Array<{ version: string; deprecated?: string | null; uploadTime?: string | null }>): PackageMeta {
  return {
    name: "x",
    distTagLatest: null,
    releases: releases.map((r) => ({
      version: r.version,
      deprecated: r.deprecated ?? null,
      enginesNode: null,
      uploadTime: r.uploadTime ?? null,
    })),
  };
}

describe("pickLatest", () => {
  it("picks max stable, ignores prereleases by default", () => {
    const r = pickLatest(meta([{ version: "1.0.0" }, { version: "1.2.0" }, { version: "2.0.0-rc.1" }]), false);
    expect(r.latest).toBe("1.2.0");
    expect(r.latestIncludingPrereleases).toBe("2.0.0-rc.1");
  });
  it("prefers a non-deprecated stable when a higher version is deprecated", () => {
    const r = pickLatest(meta([{ version: "1.2.0" }, { version: "1.3.0", deprecated: "bad" }]), false);
    expect(r.latest).toBe("1.2.0");
  });
  it("falls back to deprecated when all are deprecated", () => {
    const r = pickLatest(meta([{ version: "1.2.0", deprecated: "old" }, { version: "1.3.0", deprecated: "bad" }]), false);
    expect(r.latest).toBe("1.3.0");
  });
  it("attaches the upload time of the effective latest", () => {
    const r = pickLatest(meta([{ version: "1.2.0", uploadTime: "2020-01-01T00:00:00Z" }]), false);
    expect(r.latestReleaseDate).toBe("2020-01-01T00:00:00Z");
  });
  it("empty release set → nulls", () => {
    const r = pickLatest(meta([]), false);
    expect(r.latest).toBeNull();
    expect(r.latestReleaseDate).toBeNull();
  });
});
