// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ProjectAudit, DepAudit } from "../models.js";

export const SCHEMA_VERSION = 1;

function depToJson(a: DepAudit): unknown {
  return {
    name: a.dep.name,
    rawName: a.dep.rawName,
    range: a.dep.range,
    resolved: a.dep.resolved,
    direct: a.dep.direct,
    group: a.dep.source.group,
    url: a.dep.url,
    pinStatus: a.pinStatus,
    drift: a.drift,
    latest: a.latest,
    latestIncludingPrereleases: a.latestIncludingPrereleases,
    deprecated: a.deprecated,
    latestReleaseDate: a.latestReleaseDate,
    latestReleaseAgeDays: a.latestReleaseAgeDays,
    minSafeVersion: a.minSafeVersion,
    vulnerabilities: a.vulnerabilities.map((v) => ({
      id: v.id,
      aliases: v.aliases,
      summary: v.summary,
      fixedVersions: v.fixedVersions,
    })),
    warnings: a.warnings,
  };
}

function projectToJson(p: ProjectAudit): unknown {
  return {
    name: p.project.name,
    root: p.project.root,
    pinningScore: p.pinningScore,
    driftSummary: p.driftSummary,
    deprecatedCount: p.deprecatedCount,
    registryUnreachable: p.registryUnreachable,
    vulnCount: p.vulnCount,
    vulnUnreachable: p.vulnUnreachable,
    suppressedCount: p.suppressedCount,
    deps: p.deps.map(depToJson),
  };
}

export function renderAuditJson(audits: readonly ProjectAudit[]): string {
  return JSON.stringify({ kind: "audit", schemaVersion: SCHEMA_VERSION, projects: audits.map(projectToJson) }, null, 2);
}
