// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import {
  PinStatus,
  SemverDrift,
  DepSourceKind,
  makeDep,
  type Dep,
} from "../src/models.js";

describe("models", () => {
  it("exposes the pin-posture and drift enums", () => {
    expect(PinStatus.PINNED).toBe("pinned");
    expect(PinStatus.COMPATIBLE).toBe("compatible");
    expect(PinStatus.URL).toBe("url");
    expect(SemverDrift.PRERELEASE).toBe("prerelease");
    expect(SemverDrift.MAJOR).toBe("major");
    expect(SemverDrift.UNKNOWN).toBe("unknown");
    expect(DepSourceKind.NPM_LOCK).toBe("npm-lock");
  });

  it("makeDep freezes the result (immutable container)", () => {
    const dep: Dep = makeDep({
      name: "left-pad",
      rawName: "left-pad",
      range: "^1.3.0",
      resolved: null,
      source: { kind: DepSourceKind.MANIFEST, path: "package.json", group: "default" },
      url: null,
      direct: true,
    });
    expect(Object.isFrozen(dep)).toBe(true);
    expect(Object.isFrozen(dep.source)).toBe(true);
    expect(() => {
      // @ts-expect-error readonly
      dep.range = "2.0.0";
    }).toThrow();
  });
});
