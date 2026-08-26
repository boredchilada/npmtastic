// SPDX-License-Identifier: AGPL-3.0-or-later
import { info, warn } from "./logging.js";

const RETRY_STATUS = new Set([429, 500, 502, 503, 504]);
const MAX_BACKOFF = 30;
const MAX_RETRY_AFTER = 60;

export function backoff(attempt: number, baseDelay = 1): number {
  const delay = Math.min(MAX_BACKOFF, baseDelay * 2 ** attempt);
  return delay + Math.random() * baseDelay;
}

export function parseRetryAfter(value: string | null): number | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) return Math.min(MAX_RETRY_AFTER, Number(trimmed));
  const when = Date.parse(trimmed);
  if (Number.isNaN(when)) return null;
  const delta = (when - Date.now()) / 1000;
  if (delta <= 0) return 0;
  return Math.min(MAX_RETRY_AFTER, delta);
}

export interface RequestJsonOptions {
  maxRetries?: number;
  timeout?: number;
  baseDelay?: number;
  label?: string;
}

/** GET/POST JSON with exponential backoff + jitter on 429/5xx and network errors. */
export async function requestJson(
  url: string,
  init: RequestInit = {},
  opts: RequestJsonOptions = {},
): Promise<unknown | null> {
  const maxRetries = opts.maxRetries ?? 5;
  const timeout = opts.timeout ?? 15000;
  const baseDelay = opts.baseDelay ?? 1;
  const label = opts.label ?? url;
  let attempt = 0;
  while (true) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    try {
      const res = await fetch(url, { ...init, signal: ctrl.signal });
      if (res.ok) {
        try {
          return await res.json();
        } catch (e) {
          warn(`${label}: response is not valid JSON: ${(e as Error).message}`);
          return null;
        }
      }
      const retryAfter = parseRetryAfter(res.headers.get("Retry-After"));
      if (RETRY_STATUS.has(res.status) && attempt < maxRetries) {
        const delay = retryAfter ?? backoff(attempt, baseDelay);
        info(`${label}: HTTP ${res.status}; retry ${attempt + 1}/${maxRetries} in ${delay.toFixed(1)}s`);
        await new Promise<void>((resolve) => {
          setTimeout(resolve, delay * 1000);
        });
        attempt += 1;
        continue;
      }
      if (RETRY_STATUS.has(res.status)) {
        warn(`${label}: HTTP ${res.status} after ${maxRetries} retries`);
      } else {
        warn(`${label}: HTTP ${res.status}`);
      }
      return null;
    } catch (e) {
      const err = e as Error & { cause?: { message?: string; code?: string } };
      const msg = err.message ?? "";
      const blob = `${msg} ${err.cause?.message ?? ""} ${err.cause?.code ?? ""}`;
      if (blob.includes("certificate") || blob.includes("CERT_") || blob.includes("UNABLE_TO_VERIFY") || blob.includes("SSL")) {
        throw new Error(`TLS certificate verification failed for ${url}: ${err.cause?.message ?? msg}`);
      }
      if (attempt < maxRetries) {
        const delay = backoff(attempt, baseDelay);
        info(`${label}: ${msg}; retry ${attempt + 1}/${maxRetries} in ${delay.toFixed(1)}s`);
        await new Promise<void>((resolve) => {
          setTimeout(resolve, delay * 1000);
        });
        attempt += 1;
        continue;
      }
      warn(`${label}: ${msg} after ${maxRetries} retries`);
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
}
