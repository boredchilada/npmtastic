// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { rewriteManifestText, type PlannedEdit } from "../src/update.js";

const MANIFEST = `{
  "name": "demo",
  "dependencies": {
    "left-pad": "^1.3.0",
    "minimist": "1.2.0",
    "@scope/util": "~2.0.0"
  },
  "devDependencies": {
    "vitest": "^4.1.0"
  }
}
`;

describe("rewriteManifestText", () => {
  it("changes only the targeted version strings, preserving everything else", () => {
    const edits: PlannedEdit[] = [
      { name: "left-pad", rawName: "left-pad", oldSpec: "^1.3.0", newVersion: "1.3.0", note: null },
      { name: "@scope/util", rawName: "@scope/util", oldSpec: "~2.0.0", newVersion: "2.0.1", note: null },
    ];
    const { text, applied, skipped } = rewriteManifestText(MANIFEST, edits);
    expect(applied.map((e) => e.name).sort()).toEqual(["@scope/util", "left-pad"]);
    expect(skipped).toEqual([]);
    expect(text).toContain('"left-pad": "1.3.0"');
    expect(text).toContain('"@scope/util": "2.0.1"');
    expect(text).toContain('"minimist": "1.2.0"');
    expect(text).toContain('"vitest": "^4.1.0"');
    expect(text.endsWith("\n")).toBe(true);
    // only the two version substrings differ from the original
    expect(text.replace('"1.3.0"', '"^1.3.0"').replace('"2.0.1"', '"~2.0.0"')).toBe(MANIFEST);
  });

  it("skips an edit whose (name, oldSpec) can't be located, leaving text unchanged for it", () => {
    const edits: PlannedEdit[] = [
      { name: "nope", rawName: "nope", oldSpec: "^9.9.9", newVersion: "9.9.9", note: null },
    ];
    const { text, applied, skipped } = rewriteManifestText(MANIFEST, edits);
    expect(applied).toEqual([]);
    expect(skipped.map((e) => e.name)).toEqual(["nope"]);
    expect(text).toBe(MANIFEST);
  });
});
