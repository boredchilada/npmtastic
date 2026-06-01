// SPDX-License-Identifier: AGPL-3.0-or-later
import { join } from "node:path";
import semver from "semver";
import { JsonCache, cacheBaseDir, sha1 } from "./cache.js";
import { mapPool } from "./pool.js";
import { warn } from "./logging.js";
import type { Vulnerability } from "./models.js";

const OSV_URL = "https://api.osv.dev/v1/query";
const NPM_BULK = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk";

export interface VulnClientOptions {
  readonly cacheDir?: string;
  readonly ttlSeconds?: number;
  readonly timeout?: number;
  readonly concurrency?: number;
  readonly source?: "osv" | "npm-audit" | "both";
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

export function parseOsvPayload(raw: unknown): Vulnerability[] {
  if (!raw || typeof raw !== "object") return [];
  const vulns = (raw as Record<string, unknown>)["vulns"];
  if (!Array.isArray(vulns)) return [];
  const out: Vulnerability[] = [];
  for (const v of vulns) {
    if (!v || typeof v !== "object") continue;
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
    out.push({ id, aliases, summary, fixedVersions: extractFixed(o["affected"]) });
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
    const ghsa = typeof o["github_advisory_id"] === "string" ? (o["github_advisory_id"] as string) : null;
    const numeric = o["id"] !== undefined && o["id"] !== null ? `NPM-${String(o["id"])}` : null;
    const id = ghsa ?? numeric;
    if (!id) continue;
    const aliases = ghsa && numeric ? [numeric] : [];
    const summary = typeof o["title"] === "string" ? (o["title"] as string) : null;
    out.push({ id, aliases, summary, fixedVersions: [] });
  }
  return out;
}

export function dedupeVulns(vulns: readonly Vulnerability[]): Vulnerability[] {
  const byId = new Map<string, { aliases: Set<string>; summary: string | null; fixed: Set<string> }>();
  for (const v of vulns) {
    const e = byId.get(v.id) ?? { aliases: new Set<string>(), summary: null, fixed: new Set<string>() };
    v.aliases.forEach((a) => e.aliases.add(a));
    v.fixedVersions.forEach((f) => e.fixed.add(f));
    if (!e.summary && v.summary) e.summary = v.summary;
    byId.set(v.id, e);
  }
  return [...byId.entries()].map(([id, e]) => ({
    id,
    aliases: [...e.aliases],
    summary: e.summary,
    fixedVersions: [...e.fixed],
  }));
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
  readonly unreachable = new Set<string>();

  constructor(opts: VulnClientOptions = {}) {
    this.cache = new JsonCache(join(opts.cacheDir ?? cacheBaseDir(), "vulns"), opts.ttlSeconds ?? 3600);
    this.timeout = opts.timeout ?? 15000;
    this.concurrency = opts.concurrency ?? 8;
    this.source = opts.source ?? "osv";
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
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeout);
    try {
      const res = await fetch(OSV_URL, {
        method: "POST",
        signal: ctrl.signal,
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ package: { ecosystem: "npm", name }, version }),
      });
      if (!res.ok) {
        warn(`OSV ${res.status} for ${name}@${version}`);
        return null;
      }
      return await res.json();
    } catch (e) {
      warn(`OSV query failed for ${name}@${version}: ${(e as Error).message}`);
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  // npm bulk-advisories boundary — mock this in tests.
  protected async _runNpmAudit(name: string, version: string): Promise<unknown | null> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeout);
    try {
      const res = await fetch(NPM_BULK, {
        method: "POST",
        signal: ctrl.signal,
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ [name]: [version] }),
      });
      if (!res.ok) {
        warn(`npm audit ${res.status} for ${name}@${version}`);
        return null;
      }
      return await res.json();
    } catch (e) {
      warn(`npm audit query failed for ${name}@${version}: ${(e as Error).message}`);
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
}
