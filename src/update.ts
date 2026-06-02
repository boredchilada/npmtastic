// SPDX-License-Identifier: AGPL-3.0-or-later
import type { UpdateChange } from "./models.js";

export interface PlannedEdit {
  name: string; // canonical
  rawName: string; // as written in package.json
  oldSpec: string; // current spec value
  newVersion: string; // exact target
  note: string | null;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Replace the value of "rawName": "oldSpec" in raw package.json text, changing only
// the value. Returns null if the entry is absent or ambiguous (appears != once).
function replaceSpec(text: string, rawName: string, oldSpec: string, newVersion: string): string | null {
  const re = new RegExp(`("${escapeRegExp(rawName)}"\\s*:\\s*")${escapeRegExp(oldSpec)}(")`, "g");
  const count = (text.match(re) ?? []).length;
  if (count !== 1) return null;
  return text.replace(re, `$1${newVersion}$2`);
}

export interface RewriteResult {
  text: string;
  applied: PlannedEdit[];
  skipped: PlannedEdit[];
}

export function rewriteManifestText(text: string, edits: readonly PlannedEdit[]): RewriteResult {
  let out = text;
  const applied: PlannedEdit[] = [];
  const skipped: PlannedEdit[] = [];
  for (const e of edits) {
    const next = replaceSpec(out, e.rawName, e.oldSpec, e.newVersion);
    if (next === null) {
      skipped.push(e);
      continue;
    }
    out = next;
    applied.push(e);
  }
  return { text: out, applied, skipped };
}

export function editToChange(e: PlannedEdit): UpdateChange {
  return { name: e.name, from: e.oldSpec, to: e.newVersion, note: e.note };
}
