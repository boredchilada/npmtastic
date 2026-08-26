// SPDX-License-Identifier: AGPL-3.0-or-later
import { join } from "node:path";
import semver from "semver";
import { JsonCache, cacheBaseDir, sha1 } from "./cache.js";
import { mapPool } from "./pool.js";
import { requestJson } from "./http.js";
import type { Vulnerability } from "./models.js";

const OSV_URL = "https://api.osv.dev/v1/query";
const NPM_BULK = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk";

export interface VulnClientOptions {
  readonly cacheDir?: string;
  readonly ttlSeconds?: number;
  readonly timeout?: number;
  readonly concurrency?: number;
  readonly source?: "osv" | "npm-audit" | "both";
  readonly maxRetries?: number;
  readonly offline?: boolean;
  readonly enabled?: boolean;
}

export interface NameVersion {
  readonly name: string;
  readonly version: string;
}

function extractFixed(affected: unknown): string[] {
  const fixed = new Set<string>();
  if (!Array.isArray(affected)) return [];
  for (const a of affected) {
    const ranges = (a as Record<string, unknown> | null)?.["ranges"];
    if (!Array.isArray(ranges)) continue;
    for (const r of ranges) {
      const events = (r as Record<string, unknown> | null)?.["events"];
      if (!Array.isArray(events)) continue;
      for (const e of events) {
        const f = (e as Record<string, unknown> | null)?.["fixed"];
        if (typeof f === "string") fixed.add(f);
      }
    }
  }
  return [...fixed];
}

const SEVERITY_ORDER = ["unknown", "low", "moderate", "high", "critical"] as const;
const SEVERITY_ALIASES: Record<string, string> = { medium: "moderate", none: "unknown", "": "unknown" };

export function severityRank(severity: string | undefined | null): number {
  const raw = (severity ?? "unknown").toLowerCase();
  const normalized = SEVERITY_ALIASES[raw] ?? raw;
  const idx = (SEVERITY_ORDER as readonly string[]).indexOf(normalized);
  return idx === -1 ? 0 : idx;
}

function normalizeSeverity(severity: string | undefined | null): string {
  const raw = (severity ?? "unknown").toLowerCase();
  const normalized = SEVERITY_ALIASES[raw] ?? raw;
  return (SEVERITY_ORDER as readonly string[]).includes(normalized) ? normalized : "unknown";
}

function bandFromScore(score: number): string {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "moderate";
  if (score > 0.0) return "low";
  return "unknown";
}

const CVSS_WEIGHTS: Record<string, Record<string, number>> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0.0 },
  I: { H: 0.56, L: 0.22, N: 0.0 },
  A: { H: 0.56, L: 0.22, N: 0.0 },
};
const CVSS_PR: Record<"unchanged" | "changed", Record<string, number>> = {
  unchanged: { N: 0.85, L: 0.62, H: 0.27 },
  changed: { N: 0.85, L: 0.68, H: 0.5 },
};

function cvssBand(vector: string): string {
  if (!vector.toUpperCase().startsWith("CVSS:3")) return "unknown";
  const parts: Record<string, string> = {};
  for (const chunk of vector.split("/").slice(1)) {
    const sep = chunk.indexOf(":");
    if (sep <= 0) continue;
    parts[chunk.slice(0, sep).toUpperCase()] = chunk.slice(sep + 1).toUpperCase();
  }
  try {
    const scopeChanged = parts["S"] === "C";
    const c = CVSS_WEIGHTS["C"]![parts["C"]!];
    const i = CVSS_WEIGHTS["I"]![parts["I"]!];
    const a = CVSS_WEIGHTS["A"]![parts["A"]!];
    const av = CVSS_WEIGHTS["AV"]![parts["AV"]!];
    const ac = CVSS_WEIGHTS["AC"]![parts["AC"]!];
    const ui = CVSS_WEIGHTS["UI"]![parts["UI"]!];
    const pr = CVSS_PR[scopeChanged ? "changed" : "unchanged"][parts["PR"]!];
    if ([c, i, a, av, ac, ui, pr].some((n) => n === undefined)) return "unknown";
    const impactBase = 1 - (1 - c!) * (1 - i!) * (1 - a!);
    const exploitability = 8.22 * av! * ac! * pr! * ui!;
    if (impactBase <= 0) return "unknown";
    const impact = scopeChanged
      ? 7.52 * (impactBase - 0.029) - 3.25 * (impactBase - 0.02) ** 15
      : 6.42 * impactBase;
    const raw = Math.min(impact + exploitability, 10.0);
    return bandFromScore(Math.ceil(raw * 10) / 10);
  } catch {
    return "unknown";
  }
}

function extractSeverity(vuln: Record<string, unknown>): { severity: string; cvss: string | null } {
  const nodes = vuln["severity"];
  if (Array.isArray(nodes)) {
    for (const node of nodes) {
      if (!node || typeof node !== "object") continue;
      const score = (node as Record<string, unknown>)["score"];
      if (typeof score === "string" && score.toUpperCase().startsWith("CVSS:")) {
        return { severity: cvssBand(score), cvss: score };
      }
      if (typeof score === "number") return { severity: bandFromScore(score), cvss: null };
      if (typeof score === "string" && score) {
        const n = Number.parseFloat(score);
        if (!Number.isNaN(n)) return { severity: bandFromScore(n), cvss: null };
      }
    }
  }

  const ds = vuln["database_specific"];
  if (ds && typeof ds === "object") {
    const label = (ds as Record<string, unknown>)["severity"];
    if (typeof label === "string" && label) {
      const normalized = normalizeSeverity(label);
      if (normalized !== "unknown" || label.toLowerCase() === "unknown") {
        return { severity: normalized, cvss: null };
      }
    }
  }

  const affected = vuln["affected"];
  if (Array.isArray(affected)) {
    for (const entry of affected) {
      if (!entry || typeof entry !== "object") continue;
      const ads = (entry as Record<string, unknown>)["database_specific"];
      if (!ads || typeof ads !== "object") continue;
      const vector = (ads as Record<string, unknown>)["cvss"];
      if (typeof vector === "string" && vector.toUpperCase().startsWith("CVSS:")) {
        return { severity: cvssBand(vector), cvss: vector };
      }
    }
  }
  return { severity: "unknown", cvss: null };
}

function extractCweIds(vuln: Record<string, unknown>): string[] {
  const ds = vuln["database_specific"];
  if (!ds || typeof ds !== "object") return [];
  const raw = (ds as Record<string, unknown>)["cwe_ids"];
  if (!Array.isArray(raw)) return [];
  return raw.filter((c): c is string => typeof c === "string" && c.length > 0);
}

function extractReferences(vuln: Record<string, unknown>): string[] {
  const raw = vuln["references"];
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const node of raw) {
    if (!node || typeof node !== "object") continue;
    const url = (node as Record<string, unknown>)["url"];
    if (typeof url === "string" && url && !out.includes(url)) out.push(url);
  }
  return out;
}

function withDefaults(v: Vulnerability): Vulnerability {
  return {
    id: v.id,
    aliases: v.aliases ?? [],
    summary: v.summary ?? null,
    fixedVersions: v.fixedVersions ?? [],
    severity: normalizeSeverity(v.severity),
    cvss: v.cvss ?? null,
    cweIds: v.cweIds ?? [],
    references: v.references ?? [],
    published: v.published ?? null,
  };
}


export function parseOsvPayload(raw: unknown): Vulnerability[] {
  if (!raw || typeof raw !== "object") return [];
  const vulns = (raw as Record<string, unknown>)["vulns"];
  if (!Array.isArray(vulns)) return [];
  const out: Vulnerability[] = [];
  for (const v of vulns) {
    if (!v || typeof v !== "object") continue;
    const withdrawn = typeof (v as Record<string, unknown>)["withdrawn"] === "string"
      ? ((v as Record<string, unknown>)["withdrawn"] as string) : "";
    if (withdrawn) continue;
    const o = v as Record<string, unknown>;
    const id = typeof o["id"] === "string" ? (o["id"] as string) : null;
    if (!id) continue;
    const aliases = Array.isArray(o["aliases"])
      ? (o["aliases"] as unknown[]).filter((a): a is string => typeof a === "string")
      : [];
    const summary =
      typeof o["summary"] === "string" ? (o["summary"] as string)
      : typeof o["details"] === "string" ? (o["details"] as string)
      : null;
    const { severity, cvss } = extractSeverity(o);
    const published = typeof o["published"] === "string" ? (o["published"] as string) : null;
    out.push({
      id,
      aliases,
      summary,
      fixedVersions: extractFixed(o["affected"]),
      severity,
      cvss,
      cweIds: extractCweIds(o),
      references: extractReferences(o),
      published,
    });
  }
  return out;
}

export function parseNpmAudit(raw: unknown, name: string, version: string): Vulnerability[] {
  if (!raw || typeof raw !== "object") return [];
  const advs = (raw as Record<string, unknown>)[name];
  if (!Array.isArray(advs)) return [];
  const out: Vulnerability[] = [];
  for (const a of advs) {
    if (!a || typeof a !== "object") continue;
    const o = a as Record<string, unknown>;
    const range = typeof o["vulnerable_versions"] === "string" ? (o["vulnerable_versions"] as string) : null;
    if (range !== null) {
      try {
        if (!semver.satisfies(version, range, { includePrerelease: true })) continue;
      } catch {
        continue; // unparseable range → can't confirm → skip (avoid false positives)
      }
    }
    // Prefer a GHSA id so npm-audit results dedupe against OSV (which keys on GHSA).
    // The npm bulk endpoint usually omits a github_advisory_id field but embeds the
    // GHSA in the advisory `url` (https://github.com/advisories/GHSA-...).
    const urlStr = typeof o["url"] === "string" ? (o["url"] as string) : "";
    const ghsaField = typeof o["github_advisory_id"] === "string" ? (o["github_advisory_id"] as string) : null;
    const ghsaFromUrl = urlStr.match(/GHSA-[0-9a-z-]+/i)?.[0] ?? null;
    const ghsa = ghsaField ?? ghsaFromUrl;
    const numeric = o["id"] !== undefined && o["id"] !== null ? `NPM-${String(o["id"])}` : null;
    const id = ghsa ?? numeric;
    if (!id) continue;
    const cves = Array.isArray(o["cves"]) ? (o["cves"] as unknown[]).filter((c): c is string => typeof c === "string") : [];
    const aliases = [...new Set([...(ghsa && numeric ? [numeric] : []), ...cves])];
    const summary = typeof o["title"] === "string" ? (o["title"] as string) : null;
    const npmSev = typeof o["severity"] === "string" ? normalizeSeverity(o["severity"] as string) : "unknown";
    const cwesRaw = o["cwe"];
    const cweIds = Array.isArray(cwesRaw)
      ? cwesRaw.filter((c): c is string => typeof c === "string" && c.length > 0)
      : typeof cwesRaw === "string" && cwesRaw
        ? [cwesRaw]
        : [];
    out.push({
      id,
      aliases,
      summary,
      fixedVersions: [],
      severity: npmSev,
      cvss: null,
      cweIds,
      references: urlStr ? [urlStr] : [],
      published: null,
    });
  }
  return out;
}

export function dedupeVulns(vulns: readonly Vulnerability[]): Vulnerability[] {
  if (vulns.length === 0) return [];
  const items = vulns.map(withDefaults);
  const parent = items.map((_, i) => i);
  const find = (i: number): number => {
    const p = parent[i]!;
    if (p === i) return i;
    parent[i] = find(p);
    return parent[i]!;
  };
  const unite = (a: number, b: number): void => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent[rb] = ra;
  };
  const byKey = new Map<string, number>();
  items.forEach((v, i) => {
    for (const key of [v.id, ...v.aliases]) {
      const prev = byKey.get(key);
      if (prev !== undefined) unite(prev, i);
      else byKey.set(key, i);
    }
  });
  const groups = new Map<number, Vulnerability[]>();
  items.forEach((v, i) => {
    const root = find(i);
    const group = groups.get(root) ?? [];
    group.push(v);
    groups.set(root, group);
  });
  return [...groups.values()].map((group) => {
    const ids = new Set<string>();
    for (const v of group) {
      ids.add(v.id);
      v.aliases.forEach((a) => ids.add(a));
    }
    const primary = group.find((v) => v.id.startsWith("GHSA-"))?.id ?? group[0]!.id;
    const best = group.reduce((a, b) => (severityRank(b.severity) > severityRank(a.severity) ? b : a));
    const aliases = [...ids].filter((id) => id !== primary);
    const fixed = new Set<string>();
    const cwes = new Set<string>();
    const refs = new Set<string>();
    let summary: string | null = null;
    let published: string | null = null;
    let cvss: string | null = best.cvss;
    for (const v of group) {
      v.fixedVersions.forEach((f) => fixed.add(f));
      v.cweIds.forEach((c) => cwes.add(c));
      v.references.forEach((r) => refs.add(r));
      if (!summary && v.summary) summary = v.summary;
      if (!cvss && v.cvss) cvss = v.cvss;
      if (v.published && (published === null || v.published < published)) published = v.published;
    }
    return {
      id: primary,
      aliases,
      summary,
      fixedVersions: [...fixed],
      severity: best.severity,
      cvss,
      cweIds: [...cwes].sort(),
      references: [...refs],
      published,
    };
  });
}

export function computeMinSafeVersion(installed: string, vulns: readonly Vulnerability[]): string | null {
  if (!semver.valid(installed)) return null;
  let candidate: string | null = null;
  for (const v of vulns) {
    const above = v.fixedVersions.filter((f) => semver.valid(f) && semver.gt(f, installed));
    if (above.length === 0) return null;
    const lowest = above.sort(semver.compare)[0]!;
    if (candidate === null || semver.gt(lowest, candidate)) candidate = lowest;
  }
  return candidate;
}

export class VulnClient {
  private readonly cache: JsonCache;
  private readonly timeout: number;
  private readonly concurrency: number;
  private readonly source: "osv" | "npm-audit" | "both";
  private readonly maxRetries: number;
  readonly offline: boolean;
  readonly unreachable = new Set<string>();
  readonly offlineMisses: string[] = [];

  constructor(opts: VulnClientOptions = {}) {
    this.cache = new JsonCache(join(opts.cacheDir ?? cacheBaseDir(), "vulns"), opts.ttlSeconds ?? 3600, opts.offline ?? false, opts.enabled ?? true);
    this.timeout = opts.timeout ?? 15000;
    this.concurrency = opts.concurrency ?? 8;
    this.source = opts.source ?? "osv";
    this.maxRetries = opts.maxRetries ?? 5;
    this.offline = opts.offline ?? false;
  }

  async fetchFor(pairs: readonly NameVersion[]): Promise<Map<string, Vulnerability[]>> {
    const seen = new Set<string>();
    const unique: NameVersion[] = [];
    for (const p of pairs) {
      const key = `${p.name}@${p.version}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(p);
      }
    }
    const results = await mapPool(unique, this.concurrency, (p) => this.fetchPair(p));
    const out = new Map<string, Vulnerability[]>();
    for (const r of results) {
      if (r.vulns !== null) out.set(r.key, r.vulns);
    }
    return out;
  }

  private async fetchOneSource(pair: NameVersion, source: "osv" | "npm-audit"): Promise<Vulnerability[] | null> {
    const key = `${pair.name}@${pair.version}`;
    const h = sha1(`${source}:${key}`);
    const seg = [h.slice(0, 2), h];
    const cached = this.cache.read<Vulnerability[]>(seg);
    if (cached) return dedupeVulns(cached);
    if (this.offline) {
      if (!this.offlineMisses.includes(key)) this.offlineMisses.push(key);
      return null;
    }
    const raw = source === "osv" ? await this._runOsvQuery(pair.name, pair.version) : await this._runNpmAudit(pair.name, pair.version);
    if (raw === null) return null;
    const vulns = dedupeVulns(source === "osv" ? parseOsvPayload(raw) : parseNpmAudit(raw, pair.name, pair.version));
    this.cache.write(seg, vulns);
    return vulns;
  }

  private async fetchPair(pair: NameVersion): Promise<{ key: string; vulns: Vulnerability[] | null }> {
    const key = `${pair.name}@${pair.version}`;
    if (this.source === "both") {
      const [osv, npm] = await Promise.all([this.fetchOneSource(pair, "osv"), this.fetchOneSource(pair, "npm-audit")]);
      if (osv === null && npm === null) {
        this.unreachable.add(key);
        return { key, vulns: null };
      }
      return { key, vulns: dedupeVulns([...(osv ?? []), ...(npm ?? [])]) };
    }
    const vulns = await this.fetchOneSource(pair, this.source);
    if (vulns === null) {
      this.unreachable.add(key);
      return { key, vulns: null };
    }
    return { key, vulns };
  }

  // OSV boundary — mock this in tests.
  protected async _runOsvQuery(name: string, version: string): Promise<unknown | null> {
    return requestJson(
      OSV_URL,
      {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ package: { ecosystem: "npm", name }, version }),
      },
      { maxRetries: this.maxRetries, timeout: this.timeout, label: `OSV ${name}@${version}` },
    );
  }

  // npm bulk-advisories boundary — mock this in tests.
  protected async _runNpmAudit(name: string, version: string): Promise<unknown | null> {
    return requestJson(
      NPM_BULK,
      {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ [name]: [version] }),
      },
      { maxRetries: this.maxRetries, timeout: this.timeout, label: `npm audit ${name}@${version}` },
    );
  }
}
