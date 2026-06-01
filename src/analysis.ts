// SPDX-License-Identifier: AGPL-3.0-or-later
import semver from "semver";
import { PinStatus, SemverDrift } from "./models.js";

export function classifyPinStatus(range: string, url: string | null): PinStatus {
  if (url) return PinStatus.URL;
  const r = range.trim();
  if (r === "" || r === "*" || r === "x" || r === "X" || r.toLowerCase() === "latest") {
    return PinStatus.UNPINNED;
  }
  if (r.startsWith("^") || r.startsWith("~")) return PinStatus.COMPATIBLE;
  if (semver.valid(r) !== null) return PinStatus.PINNED;
  let parsed: InstanceType<typeof semver.Range>;
  try {
    parsed = new semver.Range(r);
  } catch {
    return PinStatus.RANGE;
  }
  const ops = parsed.set.flat().map((c) => c.operator);
  const hasLower = ops.some((o) => o === ">" || o === ">=");
  const hasUpper = ops.some((o) => o === "<" || o === "<=");
  if (hasLower && !hasUpper) return PinStatus.FLOOR;
  return PinStatus.RANGE;
}
