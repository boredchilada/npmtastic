// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { backupManifest } from "../src/backup.js";

describe("backupManifest", () => {
  it("copies the current file into .npmtastic_backups and returns the path", () => {
    const root = mkdtempSync(join(tmpdir(), "ntc-bk-"));
    const mp = join(root, "package.json");
    writeFileSync(mp, '{"name":"x"}');
    const dest = backupManifest(mp, root, '{"name":"x"}');
    expect(dest).toContain(".npmtastic_backups");
    expect(existsSync(dest)).toBe(true);
    expect(readFileSync(dest, "utf-8")).toBe('{"name":"x"}');
  });
});
