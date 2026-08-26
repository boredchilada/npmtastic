// SPDX-License-Identifier: AGPL-3.0-or-later
import { writeFileSync } from "node:fs";
import { readText } from "./fsutil.js";
import type { ProjectAudit, Vulnerability } from "./models.js";

export const SCHEMA_VERSION = 1;

export class BaselineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BaselineError";
  }
}

export interface Finding {
  readonly project: string;
  readonly package: string;
  readonly key: string;
}

export interface Diff {
  readonly new: Finding[];
  readonly unchanged: Finding[];
  readonly fixed: Finding[];
}

function canonicalKey(advisory: Vulnerability): string {
  return [advisory.id, ...advisory.aliases].reduce((a, b) => (a < b ? a : b));
}

function findingId(f: Finding): string {
  return `${f.project}\0${f.package}\0${f.key}`;
}

function compareFindings(a: Finding, b: Finding): number {
  return a.project.localeCompare(b.project) || a.package.localeCompare(b.package) || a.key.localeCompare(b.key);
}

export function findings(audits: readonly ProjectAudit[]): Finding[] {
  const out = new Map<string, Finding>();
  for (const project of audits) {
    const name = project.project.name;
    for (const dep of project.deps) {
      for (const advisory of dep.vulnerabilities) {
        const f: Finding = { project: name, package: dep.dep.name, key: canonicalKey(advisory) };
        out.set(findingId(f), f);
      }
      if (dep.deprecated !== null) {
        const f: Finding = { project: name, package: dep.dep.name, key: "deprecated" };
        out.set(findingId(f), f);
      }
    }
  }
  return [...out.values()].sort(compareFindings);
}

export function write(path: string, audits: readonly ProjectAudit[]): void {
  const payload = {
    kind: "baseline",
    schema_version: SCHEMA_VERSION,
    generated: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    findings: findings(audits).map((f) => ({ project: f.project, package: f.package, key: f.key })),
  };
  try {
    writeFileSync(path, JSON.stringify(payload, null, 2) + "\n", "utf8");
  } catch (e) {
    throw new BaselineError(`cannot write baseline ${path}: ${(e as Error).message}`);
  }
}

export function load(path: string): Finding[] {
  let raw: string;
  try {
    raw = readText(path);
  } catch (e) {
    throw new BaselineError(`cannot read baseline ${path}: ${(e as Error).message}`);
  }
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch (e) {
    throw new BaselineError(`baseline ${path} is not valid JSON: ${(e as Error).message}`);
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    throw new BaselineError(`baseline ${path}: expected a JSON object`);
  }
  const obj = doc as Record<string, unknown>;
  if (obj["kind"] !== "baseline") {
    throw new BaselineError(`baseline ${path}: expected kind 'baseline', got ${JSON.stringify(obj["kind"])}`);
  }
  if (obj["schema_version"] !== SCHEMA_VERSION) {
    throw new BaselineError(
      `baseline ${path}: unsupported schema_version ${JSON.stringify(obj["schema_version"])} (this build understands ${SCHEMA_VERSION})`,
    );
  }
  const nodes = obj["findings"];
  if (!Array.isArray(nodes)) {
    throw new BaselineError(`baseline ${path}: findings must be an array`);
  }
  const out = new Map<string, Finding>();
  for (let index = 0; index < nodes.length; index++) {
    const node = nodes[index];
    if (!node || typeof node !== "object" || Array.isArray(node)) {
      throw new BaselineError(`baseline ${path}: finding ${index} must be an object`);
    }
    const rec = node as Record<string, unknown>;
    const missing = (["project", "package", "key"] as const).filter((field) => typeof rec[field] !== "string");
    if (missing.length > 0) {
      throw new BaselineError(`baseline ${path}: finding ${index} is missing ${missing.join(", ")}`);
    }
    const f: Finding = {
      project: rec["project"] as string,
      package: rec["package"] as string,
      key: rec["key"] as string,
    };
    out.set(findingId(f), f);
  }
  return [...out.values()].sort(compareFindings);
}

export function diff(audits: readonly ProjectAudit[], baseline: readonly Finding[]): Diff {
  const current = new Map(findings(audits).map((f) => [findingId(f), f]));
  const known = new Map(baseline.map((f) => [findingId(f), f]));
  const next: Finding[] = [];
  const unchanged: Finding[] = [];
  const fixed: Finding[] = [];
  for (const [id, f] of current) {
    if (known.has(id)) unchanged.push(f);
    else next.push(f);
  }
  for (const [id, f] of known) {
    if (!current.has(id)) fixed.push(f);
  }
  return {
    new: next.sort(compareFindings),
    unchanged: unchanged.sort(compareFindings),
    fixed: fixed.sort(compareFindings),
  };
}
