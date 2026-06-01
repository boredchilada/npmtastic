// SPDX-License-Identifier: AGPL-3.0-or-later
import { join } from "node:path";
import { JsonCache, cacheBaseDir } from "./cache.js";
import { mapPool } from "./pool.js";
import { warn } from "./logging.js";
import type { PackageMeta, ReleaseInfo } from "./models.js";

const REGISTRY = "https://registry.npmjs.org";

export interface ClientOptions {
  readonly cacheDir?: string;
  readonly ttlSeconds?: number;
  readonly timeout?: number;
  readonly concurrency?: number;
}

function encodeName(name: string): string {
  return name.startsWith("@") ? "@" + encodeURIComponent(name.slice(1)) : encodeURIComponent(name);
}

function cacheSegments(name: string): string[] {
  return [name.replace(/[^a-zA-Z0-9._@-]/g, "_")];
}

export function parseRegistryPayload(name: string, raw: unknown): PackageMeta | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  const versionsObj = (obj["versions"] as Record<string, unknown>) ?? {};
  const timeObj = (obj["time"] as Record<string, unknown>) ?? {};
  const distTags = (obj["dist-tags"] as Record<string, unknown>) ?? {};
  const releases: ReleaseInfo[] = [];
  for (const [version, vmetaUnknown] of Object.entries(versionsObj)) {
    const vmeta = (vmetaUnknown ?? {}) as Record<string, unknown>;
    const deprecated = typeof vmeta["deprecated"] === "string" ? (vmeta["deprecated"] as string) : null;
    const engines = vmeta["engines"] as Record<string, unknown> | undefined;
    const enginesNode = engines && typeof engines["node"] === "string" ? (engines["node"] as string) : null;
    const uploadTime = typeof timeObj[version] === "string" ? (timeObj[version] as string) : null;
    releases.push({ version, deprecated, enginesNode, uploadTime });
  }
  const distTagLatest = typeof distTags["latest"] === "string" ? (distTags["latest"] as string) : null;
  return { name, distTagLatest, releases };
}

export class RegistryClient {
  private readonly cache: JsonCache;
  private readonly timeout: number;
  private readonly concurrency: number;

  constructor(opts: ClientOptions = {}) {
    this.cache = new JsonCache(join(opts.cacheDir ?? cacheBaseDir(), "registry"), opts.ttlSeconds ?? 3600);
    this.timeout = opts.timeout ?? 15000;
    this.concurrency = opts.concurrency ?? 8;
  }

  async fetchOne(name: string): Promise<PackageMeta | null> {
    const seg = cacheSegments(name);
    const cached = this.cache.read<PackageMeta>(seg);
    if (cached) return cached;
    const raw = await this._httpGet(`${REGISTRY}/${encodeName(name)}`);
    if (raw === null) return null;
    const meta = parseRegistryPayload(name, raw);
    if (meta) this.cache.write(seg, meta);
    return meta;
  }

  async fetchMany(names: readonly string[]): Promise<Map<string, PackageMeta>> {
    const unique = [...new Set(names)];
    const metas = await mapPool(unique, this.concurrency, (n) => this.fetchOne(n));
    const out = new Map<string, PackageMeta>();
    unique.forEach((n, i) => {
      const m = metas[i];
      if (m) out.set(n, m);
    });
    return out;
  }

  // HTTP boundary — mock this in tests.
  protected async _httpGet(url: string): Promise<unknown | null> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeout);
    try {
      const res = await fetch(url, { signal: ctrl.signal, headers: { accept: "application/json" } });
      if (!res.ok) {
        warn(`registry ${res.status} for ${url}`);
        return null;
      }
      return await res.json();
    } catch (e) {
      warn(`registry fetch failed for ${url}: ${(e as Error).message}`);
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
}
