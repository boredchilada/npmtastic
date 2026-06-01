// SPDX-License-Identifier: AGPL-3.0-or-later
import { join } from "node:path";
import semver from "semver";
import { JsonCache, cacheBaseDir, sha1 } from "./cache.js";
import { mapPool } from "./pool.js";
import { warn } from "./logging.js";
import type { Vulnerability } from "./models.js";

const OSV_URL = "https://api.osv.dev/v1/query";

export interface VulnClientOptions {
  readonly cacheDir?: string;
  readonly ttlSeconds?: number;
  readonly timeout?: number;
  readonly concurrency?: number;
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
  readonly unreachable = new Set<string>();

  constructor(opts: VulnClientOptions = {}) {
    this.cache = new JsonCache(join(opts.cacheDir ?? cacheBaseDir(), "vulns"), opts.ttlSeconds ?? 3600);
    this.timeout = opts.timeout ?? 15000;
    this.concurrency = opts.concurrency ?? 8;
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

  private async fetchPair(pair: NameVersion): Promise<{ key: string; vulns: Vulnerability[] | null }> {
    const key = `${pair.name}@${pair.version}`;
    const h = sha1(key);
    const seg = [h.slice(0, 2), h];
    const cached = this.cache.read<Vulnerability[]>(seg);
    if (cached) return { key, vulns: dedupeVulns(cached) };
    const raw = await this._runOsvQuery(pair.name, pair.version);
    if (raw === null) {
      this.unreachable.add(key);
      return { key, vulns: null };
    }
    const vulns = dedupeVulns(parseOsvPayload(raw));
    this.cache.write(seg, vulns);
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
}
