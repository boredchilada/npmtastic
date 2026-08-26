// SPDX-License-Identifier: AGPL-3.0-or-later
import { existsSync } from "node:fs";
import { join } from "node:path";
import { readText } from "./fsutil.js";
import { warn, info } from "./logging.js";

export const CONFIG_NAMES = ["npmtastic.toml", ".npmtastic.toml"] as const;

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export interface Policy {
  fail_on_drift?: string;
  fail_on_vuln?: string;
  fail_on_age?: number;
  fail_on_days_behind?: number;
  fail_on_deprecated?: boolean;
  fail_on_license?: string[];
  allow_license?: string[];
  fail_on_integrity?: boolean;

  gate_scope?: "direct" | "all";
}

export interface Config {
  readonly policy: Policy;
  readonly exclude: string[];
  readonly include: string[];
  readonly view?: string;
  readonly concurrency?: number;
  readonly cacheTtl?: number;
  readonly source?: string;
}

type SchemaKind = "bool" | "positive_int" | "str_list" | "level" | "enum" | "vuln";

const POLICY_SCHEMA: Record<string, { kind: SchemaKind; allowed?: readonly string[] }> = {
  fail_on_drift: { kind: "level", allowed: ["patch", "minor", "major", "prerelease"] },
  fail_on_vuln: { kind: "vuln" },
  fail_on_age: { kind: "positive_int" },
  fail_on_days_behind: { kind: "positive_int" },
  fail_on_deprecated: { kind: "bool" },
  fail_on_license: { kind: "str_list" },
  allow_license: { kind: "str_list" },
  fail_on_integrity: { kind: "bool" },

  gate_scope: { kind: "enum", allowed: ["direct", "all"] },
};

const GENERAL_SCHEMA: Record<string, { kind: SchemaKind; allowed?: readonly string[] }> = {
  exclude: { kind: "str_list" },
  include: { kind: "str_list" },
  view: { kind: "enum", allowed: ["report", "tree", "table", "summary"] },
  concurrency: { kind: "positive_int" },
  cache_ttl: { kind: "positive_int" },
};

const ALIASES: Record<string, string> = {
  "fail-on-drift": "fail_on_drift",
  "fail-on-vuln": "fail_on_vuln",
  "fail-on-age": "fail_on_age",
  "fail-on-days-behind": "fail_on_days_behind",
  "fail-on-deprecated": "fail_on_deprecated",
  "fail-on-license": "fail_on_license",
  "allow-license": "allow_license",
  "fail-on-integrity": "fail_on_integrity",

  "gate-scope": "gate_scope",
  "cache-ttl": "cache_ttl",
};

function validate(key: string, value: unknown, kind: SchemaKind, allowed: readonly string[] | undefined, source: string): unknown {
  const where = `${key} in ${source}`;
  if (kind === "bool") {
    if (typeof value !== "boolean") throw new ConfigError(`${where}: expected true or false, got ${JSON.stringify(value)}`);
    return value;
  }
  if (kind === "positive_int") {
    if (typeof value !== "number" || !Number.isInteger(value)) {
      throw new ConfigError(`${where}: expected an integer, got ${JSON.stringify(value)}`);
    }
    if (value < 0) throw new ConfigError(`${where}: expected a non-negative integer, got ${value}`);
    return value;
  }
  if (kind === "str_list") {
    if (typeof value === "string") return [value];
    if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
      throw new ConfigError(`${where}: expected a list of strings, got ${JSON.stringify(value)}`);
    }
    return [...value];
  }
  if (kind === "level" || kind === "enum") {
    if (typeof value !== "string") {
      throw new ConfigError(`${where}: expected one of ${allowed!.join(", ")}, got ${JSON.stringify(value)}`);
    }
    if (!allowed!.includes(value.toLowerCase())) {
      throw new ConfigError(`${where}: ${JSON.stringify(value)} is not valid; expected one of ${allowed!.join(", ")}`);
    }
    return value.toLowerCase();
  }
  if (kind === "vuln") {
    if (typeof value === "boolean") {
      throw new ConfigError(`${where}: expected 'any' or a number, got ${JSON.stringify(value)}`);
    }
    if (typeof value === "number" && Number.isInteger(value)) return String(value);
    if (typeof value === "string" && (value.toLowerCase() === "any" || /^\d+$/.test(value))) return value;
    throw new ConfigError(`${where}: expected 'any' or a number, got ${JSON.stringify(value)}`);
  }
  throw new ConfigError(`${where}: unsupported value kind ${kind}`);
}

function findUnquoted(line: string, ch: string): number {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (quote) {
      if (c === "\\" && quote === "\"") {
        i++;
        continue;
      }
      if (c === quote) quote = null;
      continue;
    }
    if (c === "\"" || c === "'") {
      quote = c;
      continue;
    }
    if (c === ch) return i;
  }
  return -1;
}

function parseTomlString(raw: string, source: string, lineNo: number): string {
  const quote = raw[0];
  if ((quote !== "\"" && quote !== "'") || raw[raw.length - 1] !== quote || raw.length < 2) {
    throw new ConfigError(`cannot parse ${source}: invalid string on line ${lineNo}`);
  }
  const inner = raw.slice(1, -1);
  if (quote === "'") return inner;
  return inner.replace(/\\([\\nrt"])/g, (_, c: string) => {
    if (c === "n") return "\n";
    if (c === "r") return "\r";
    if (c === "t") return "\t";
    return c;
  });
}

function parseTomlValue(raw: string, source: string, lineNo: number): unknown {
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (/^-?\d+$/.test(raw)) return Number.parseInt(raw, 10);
  if (raw.startsWith("\"") || raw.startsWith("'")) return parseTomlString(raw, source, lineNo);
  if (raw.startsWith("[")) {
    if (!raw.endsWith("]")) {
      throw new ConfigError(`cannot parse ${source}: unterminated array on line ${lineNo}`);
    }
    const inner = raw.slice(1, -1).trim();
    if (inner === "") return [];
    const items: unknown[] = [];
    let buf = "";
    let quote: string | null = null;
    for (let i = 0; i < inner.length; i++) {
      const c = inner[i]!;
      if (quote) {
        buf += c;
        if (c === "\\" && quote === "\"") {
          i++;
          if (i < inner.length) buf += inner[i]!;
          continue;
        }
        if (c === quote) quote = null;
        continue;
      }
      if (c === "\"" || c === "'") {
        quote = c;
        buf += c;
        continue;
      }
      if (c === ",") {
        items.push(parseTomlValue(buf.trim(), source, lineNo));
        buf = "";
        continue;
      }
      buf += c;
    }
    if (buf.trim() !== "") items.push(parseTomlValue(buf.trim(), source, lineNo));
    return items;
  }
  throw new ConfigError(`cannot parse ${source}: unsupported value on line ${lineNo}`);
}

function ensureTable(root: Record<string, unknown>, parts: string[], source: string, lineNo: number): Record<string, unknown> {
  let node: Record<string, unknown> = root;
  for (const part of parts) {
    const existing = node[part];
    if (existing === undefined) {
      const next: Record<string, unknown> = {};
      node[part] = next;
      node = next;
      continue;
    }
    if (!existing || typeof existing !== "object" || Array.isArray(existing)) {
      throw new ConfigError(`cannot parse ${source}: ${part} is not a table on line ${lineNo}`);
    }
    node = existing as Record<string, unknown>;
  }
  return node;
}

export function parseToml(text: string, source: string): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  let current = root;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i]!;
    const hash = findUnquoted(line, "#");
    if (hash !== -1) line = line.slice(0, hash);
    line = line.trim();
    if (line === "") continue;
    if (line.startsWith("[")) {
      if (!line.endsWith("]")) {
        throw new ConfigError(`cannot parse ${source}: invalid table header on line ${i + 1}`);
      }
      const name = line.slice(1, -1).trim();
      if (name === "") throw new ConfigError(`cannot parse ${source}: empty table name on line ${i + 1}`);
      current = ensureTable(root, name.split("."), source, i + 1);
      continue;
    }
    const eq = findUnquoted(line, "=");
    if (eq === -1) throw new ConfigError(`cannot parse ${source}: expected key = value on line ${i + 1}`);
    const key = line.slice(0, eq).trim();
    if (key === "") throw new ConfigError(`cannot parse ${source}: missing key on line ${i + 1}`);
    const rawVal = line.slice(eq + 1).trim();
    if (rawVal === "") throw new ConfigError(`cannot parse ${source}: missing value on line ${i + 1}`);
    const parts = key.split(".");
    const leaf = parts.pop()!;
    const table = parts.length > 0 ? ensureTable(current, parts, source, i + 1) : current;
    table[leaf] = parseTomlValue(rawVal, source, i + 1);
  }
  return root;
}

function readJsonObject(path: string): Record<string, unknown> {
  let text: string;
  try {
    text = readText(path);
  } catch (e) {
    throw new ConfigError(`cannot read ${path}: ${(e as Error).message}`);
  }
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    throw new ConfigError(`cannot parse ${path}: ${(e as Error).message}`);
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    throw new ConfigError(`cannot parse ${path}: expected a JSON object`);
  }
  return doc as Record<string, unknown>;
}

function readTomlObject(path: string): Record<string, unknown> {
  let text: string;
  try {
    text = readText(path);
  } catch (e) {
    throw new ConfigError(`cannot read ${path}: ${(e as Error).message}`);
  }
  return parseToml(text, path);
}

function* candidates(startDir: string): Generator<[string, Record<string, unknown>]> {
  for (const name of CONFIG_NAMES) {
    const path = join(startDir, name);
    if (!existsSync(path)) continue;
    const doc = readTomlObject(path);
    const table = doc["npmtastic"] && typeof doc["npmtastic"] === "object" && !Array.isArray(doc["npmtastic"])
      ? (doc["npmtastic"] as Record<string, unknown>)
      : doc;
    yield [path, table];
  }
  const manifest = join(startDir, "package.json");
  if (existsSync(manifest)) {
    const doc = readJsonObject(manifest);
    const cfg = doc["npmtastic"];
    if (cfg && typeof cfg === "object" && !Array.isArray(cfg)) {
      yield [manifest, cfg as Record<string, unknown>];
    }
  }
}

export function loadConfig(startDir: string): Config {
  for (const [path, table] of candidates(startDir)) {
    const policyTable =
      table["policy"] && typeof table["policy"] === "object" && !Array.isArray(table["policy"])
        ? (table["policy"] as Record<string, unknown>)
        : {};
    const policy: Record<string, unknown> = {};
    const general: Record<string, unknown> = {};

    for (const [rawKey, value] of Object.entries(policyTable)) {
      const key = ALIASES[rawKey] ?? rawKey;
      if (key in POLICY_SCHEMA) {
        const spec = POLICY_SCHEMA[key]!;
        policy[key] = validate(key, value, spec.kind, spec.allowed, path);
      } else if (key in GENERAL_SCHEMA) {
        const spec = GENERAL_SCHEMA[key]!;
        general[key] = validate(key, value, spec.kind, spec.allowed, path);
      } else {
        warn(`ignoring unknown policy key '${rawKey}' in ${path}`);
      }
    }

    for (const [rawKey, value] of Object.entries(table)) {
      if (rawKey === "policy" || rawKey === "suppressions") continue;
      const key = ALIASES[rawKey] ?? rawKey;
      if (key in GENERAL_SCHEMA) {
        const spec = GENERAL_SCHEMA[key]!;
        general[key] = validate(key, value, spec.kind, spec.allowed, path);
      } else if (key in POLICY_SCHEMA) {
        const spec = POLICY_SCHEMA[key]!;
        policy[key] = validate(key, value, spec.kind, spec.allowed, path);
      } else {
        warn(`ignoring unknown config key '${rawKey}' in ${path}`);
      }
    }

    if (Object.keys(policy).length === 0 && Object.keys(general).length === 0) continue;
    info(`loaded policy from ${path}`);
    const cfg: Config = {
      policy: policy as Policy,
      exclude: (general["exclude"] as string[] | undefined) ?? [],
      include: (general["include"] as string[] | undefined) ?? [],
      ...(typeof general["view"] === "string" ? { view: general["view"] as string } : {}),
      ...(typeof general["concurrency"] === "number" ? { concurrency: general["concurrency"] as number } : {}),
      ...(typeof general["cache_ttl"] === "number" ? { cacheTtl: general["cache_ttl"] as number } : {}),
      source: path,
    };
    return cfg;
  }
  return { policy: {}, exclude: [], include: [] };
}

export function resolve<T>(cliValue: T, configValue: T | undefined, fallback: T): T {
  if (cliValue !== fallback) return cliValue;
  if (configValue !== undefined) return configValue;
  return fallback;
}

export function emptyConfig(): Config {
  return { policy: {}, exclude: [], include: [] };
}
