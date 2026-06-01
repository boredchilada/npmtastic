// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { classifyDrift } from "../src/analysis.js";
import { SemverDrift } from "../src/models.js";

describe("classifyDrift", () => {
  it("equal → NONE", () => expect(classifyDrift("1.2.3", "1.2.3")).toBe(SemverDrift.NONE));
  it("patch", () => expect(classifyDrift("1.2.0", "1.2.6")).toBe(SemverDrift.PATCH));
  it("minor", () => expect(classifyDrift("1.2.0", "1.5.0")).toBe(SemverDrift.MINOR));
  it("major", () => expect(classifyDrift("1.3.0", "2.0.0")).toBe(SemverDrift.MAJOR));
  it("prerelease bump → PRERELEASE", () => expect(classifyDrift("1.2.3", "1.2.3-rc.2")).toBe(SemverDrift.PRERELEASE));
  it("current ahead of latest → NONE", () => expect(classifyDrift("2.0.0", "1.9.0")).toBe(SemverDrift.NONE));
  it("missing/invalid → UNKNOWN", () => {
    expect(classifyDrift(null, "1.0.0")).toBe(SemverDrift.UNKNOWN);
    expect(classifyDrift("1.0.0", null)).toBe(SemverDrift.UNKNOWN);
    expect(classifyDrift("not-a-version", "1.0.0")).toBe(SemverDrift.UNKNOWN);
  });
});
