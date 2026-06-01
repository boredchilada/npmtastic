// SPDX-License-Identifier: AGPL-3.0-or-later
import { join } from "node:path";
import { existsSync } from "node:fs";
import { readText } from "./fsutil.js";
import { canonicalName } from "./parsing.js";
import type { Vulnerability } from "./models.js";

export interface SuppressionRule {
  id?: string;
  package?: string;
  reason?: string;
}

export function loadSuppressions(projectRoot: string): SuppressionRule[] {
  const p = join(projectRoot, "package.json");
  if (!existsSync(p)) return [];
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(readText(p)) as Record<string, unknown>;
  } catch {
    return [];
  }
  const cfg = raw["npmtastic"];
  const list = cfg && typeof cfg === "object" ? (cfg as Record<string, unknown>)["suppressions"] : undefined;
  if (!Array.isArray(list)) return [];
  const rules: SuppressionRule[] = [];
  for (const item of list) {
    if (!item || typeof item !== "object") continue;
    const o = item as Record<string, unknown>;
    const rule: SuppressionRule = {};
    if (typeof o["id"] === "string") rule.id = o["id"] as string;
    if (typeof o["package"] === "string") rule.package = o["package"] as string;
    if (typeof o["reason"] === "string") rule.reason = o["reason"] as string;
    rules.push(rule);
  }
  return rules;
}

export function isSuppressed(rules: readonly SuppressionRule[], vuln: Vulnerability, depName: string): boolean {
  return rules.some((r) => {
    if (r.id === undefined && r.package === undefined) return false; // empty rule matches nothing
    const idMatches = r.id === undefined || r.id === vuln.id || vuln.aliases.includes(r.id);
    const pkgMatches = r.package === undefined || canonicalName(r.package) === depName;
    return idMatches && pkgMatches;
  });
}
