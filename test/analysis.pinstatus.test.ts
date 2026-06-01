// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { classifyPinStatus } from "../src/analysis.js";
import { PinStatus } from "../src/models.js";

describe("classifyPinStatus", () => {
  it("exact version → PINNED", () => {
    expect(classifyPinStatus("1.2.3", null)).toBe(PinStatus.PINNED);
    expect(classifyPinStatus("1.2.3-rc.1", null)).toBe(PinStatus.PINNED);
  });
  it("caret/tilde → COMPATIBLE", () => {
    expect(classifyPinStatus("^1.2.3", null)).toBe(PinStatus.COMPATIBLE);
    expect(classifyPinStatus("~1.2.3", null)).toBe(PinStatus.COMPATIBLE);
  });
  it("bounded / x-range → RANGE", () => {
    expect(classifyPinStatus(">=1.2.3 <2.0.0", null)).toBe(PinStatus.RANGE);
    expect(classifyPinStatus("1.x", null)).toBe(PinStatus.RANGE);
    expect(classifyPinStatus("1.2.3 - 2.0.0", null)).toBe(PinStatus.RANGE);
  });
  it("bare lower bound → FLOOR", () => {
    expect(classifyPinStatus(">=1.2.3", null)).toBe(PinStatus.FLOOR);
    expect(classifyPinStatus(">1.0.0", null)).toBe(PinStatus.FLOOR);
  });
  it("wildcards / empty / latest → UNPINNED", () => {
    expect(classifyPinStatus("*", null)).toBe(PinStatus.UNPINNED);
    expect(classifyPinStatus("", null)).toBe(PinStatus.UNPINNED);
    expect(classifyPinStatus("latest", null)).toBe(PinStatus.UNPINNED);
  });
  it("url present → URL (wins over range shape)", () => {
    expect(classifyPinStatus("github:u/r#v1", "github:u/r#v1")).toBe(PinStatus.URL);
  });
});
