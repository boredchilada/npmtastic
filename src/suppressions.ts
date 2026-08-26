// SPDX-License-Identifier: AGPL-3.0-or-later
import { join } from "node:path";
import { existsSync } from "node:fs";
import { readText } from "./fsutil.js";
import { canonicalName } from "./parsing.js";
import { warn } from "./logging.js";
import type { Vulnerability } from "./models.js";

export interface SuppressionRule {
  id?: string;
  package?: string;
  reason?: string;
  expires?: string;
}

function utcToday(): Date {
  const n = new Date();
  return new Date(Date.UTC(n.getUTCFullYear(), n.getUTCMonth(), n.getUTCDate()));
}

function parseExpires(s: string): Date | null {
  const parts = s.split("-");
  if (parts.length < 3) return null;
  const y = Number.parseInt(parts[0]!, 10);
  const m = Number.parseInt(parts[1]!, 10);
  const d = Number.parseInt(parts[2]!, 10);
  if (!Number.isFinite(y) || !Number.isFinite(m) || !Number.isFinite(d)) return null;
  if (m < 1 || m > 12 || d < 1 || d > 31) return null;
  const dt = new Date(Date.UTC(y, m - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) return null;
  return dt;
}

function ruleLabel(rule: SuppressionRule): string {
  return `${rule.package ?? "*"} / ${rule.id ?? "*"}`;
}

function isExpired(rule: SuppressionRule, today: Date): boolean {
  if (rule.expires === undefined) return false;
  const exp = parseExpires(rule.expires);
  if (exp === null) return true;
  return exp < today;
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
    if (typeof o["id"] === "string") rule.id = o["id"];
    if (typeof o["package"] === "string") rule.package = o["package"];
    if (typeof o["reason"] === "string") rule.reason = o["reason"];
    if (typeof o["expires"] === "string") rule.expires = o["expires"];
    if (!rule.id || !rule.package || !rule.reason || !rule.expires) {
      warn("suppression rule missing required fields — ignoring");
      continue;
    }
    rules.push(rule);
  }
  return filterActive(rules);
}

function filterActive(rules: SuppressionRule[]): SuppressionRule[] {
  const today = utcToday();
  const active: SuppressionRule[] = [];
  for (const rule of rules) {
    if (rule.expires === undefined) {
      warn("no expiry");
      continue;
    }
    const exp = parseExpires(rule.expires);
    if (exp === null) {
      warn(`suppression for ${ruleLabel(rule)} has an invalid expires (${rule.expires}) - ignoring`);
      continue;
    }
    if (exp < today) {
      warn(`suppression for ${ruleLabel(rule)} expired ${rule.expires} - ignoring`);
      continue;
    }
    const remaining = Math.round((exp.getTime() - today.getTime()) / 86_400_000);
    if (remaining <= 30) {
      warn(`suppression for ${ruleLabel(rule)} lapses on ${rule.expires} (in ${remaining} day(s))`);
    }
    active.push(rule);
  }
  return active;
}

export function isSuppressed(rules: readonly SuppressionRule[], vuln: Vulnerability, depName: string): boolean {
  const today = utcToday();
  return rules.some((r) => {
    if (isExpired(r, today)) return false;
    if (r.id === undefined && r.package === undefined) return false; // empty rule matches nothing
    const idMatches = r.id === undefined || r.id === vuln.id || vuln.aliases.includes(r.id);
    const pkgMatches = r.package === undefined || canonicalName(r.package) === depName;
    return idMatches && pkgMatches;
  });
}
