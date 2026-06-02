// SPDX-License-Identifier: AGPL-3.0-or-later
import { mkdirSync, copyFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

// Copy a manifest's CURRENT bytes into .npmtastic_backups/ before it is overwritten.
// `raw` is the content being replaced; the filename's sha is computed over it.
export function backupManifest(manifestPath: string, projectRoot: string, raw: string): string {
  const dir = join(projectRoot, ".npmtastic_backups");
  mkdirSync(dir, { recursive: true });
  const sha = createHash("sha256").update(raw).digest("hex").slice(0, 8);
  const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 15);
  const dest = join(dir, `package.json_${stamp}_${sha}.json`);
  copyFileSync(manifestPath, dest);
  return dest;
}
