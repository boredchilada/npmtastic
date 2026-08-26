// SPDX-License-Identifier: AGPL-3.0-or-later
import { join } from "node:path";
import { JsonCache, cacheBaseDir } from "./cache.js";
import { mapPool } from "./pool.js";
import { requestJson } from "./http.js";
import type { PackageMeta, ReleaseInfo } from "./models.js";

const REGISTRY = "https://registry.npmjs.org";

export interface ClientOptions {
  readonly cacheDir?: string;
  readonly ttlSeconds?: number;
  readonly timeout?: number;
  readonly concurrency?: number;
  readonly maxRetries?: number;
  readonly offline?: boolean;
  readonly enabled?: boolean;
}

function encodeName(name: string): string {
  return name.startsWith("@") ? "@" + encodeURIComponent(name.slice(1)) : encodeURIComponent(name);
}

function cacheSegments(name: string): string[] {
  return [name.replace(/[^a-zA-Z0-9._@-]/g, "_")];
}

function extractLicense(vmeta: Record<string, unknown>): string | null {
  const lic = vmeta["license"];
  if (typeof lic === "string" && lic.trim() !== "") return lic;
  if (lic && typeof lic === "object" && !Array.isArray(lic)) {
    const t = (lic as Record<string, unknown>)["type"];
    if (typeof t === "string" && t.trim() !== "") return t;
  }
  const licenses = vmeta["licenses"];
  if (Array.isArray(licenses)) {
    const types: string[] = [];
    for (const item of licenses) {
      if (typeof item === "string" && item.trim() !== "") types.push(item);
      else if (item && typeof item === "object") {
        const t = (item as Record<string, unknown>)["type"];
        if (typeof t === "string" && t.trim() !== "") types.push(t);
      }
    }
    if (types.length === 1) return types[0]!;
    if (types.length > 1) return types.join(" OR ");
  }
  return null;
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
    const dist = vmeta["dist"];
    let integrity: string | null = null;
    if (dist && typeof dist === "object") {
      const rawIntegrity = (dist as Record<string, unknown>)["integrity"];
      if (typeof rawIntegrity === "string" && rawIntegrity.trim() !== "") integrity = rawIntegrity;
    }
    releases.push({ version, deprecated, enginesNode, uploadTime, license: extractLicense(vmeta), integrity });

  }
  const distTagLatest = typeof distTags["latest"] === "string" ? (distTags["latest"] as string) : null;
  return { name, distTagLatest, releases };
}

export class RegistryClient {
  private readonly cache: JsonCache;
  private readonly timeout: number;
  private readonly concurrency: number;
  private readonly maxRetries: number;
  readonly offline: boolean;
  readonly offlineMisses: string[] = [];

  constructor(opts: ClientOptions = {}) {
    this.cache = new JsonCache(join(opts.cacheDir ?? cacheBaseDir(), "registry"), opts.ttlSeconds ?? 3600, opts.offline ?? false, opts.enabled ?? true);
    this.timeout = opts.timeout ?? 15000;
    this.concurrency = opts.concurrency ?? 8;
    this.maxRetries = opts.maxRetries ?? 5;
    this.offline = opts.offline ?? false;
  }

  async fetchOne(name: string): Promise<PackageMeta | null> {
    const seg = cacheSegments(name);
    const cached = this.cache.read<PackageMeta>(seg);
    if (cached) return cached;
    if (this.offline) {
      if (!this.offlineMisses.includes(name)) this.offlineMisses.push(name);
      return null;
    }
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
    return requestJson(url, { headers: { accept: "application/json" } }, {
      maxRetries: this.maxRetries,
      timeout: this.timeout,
      label: `registry ${url}`,
    });
  }
}
