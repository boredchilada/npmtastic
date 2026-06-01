// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ProjectAudit, Vulnerability } from "../models.js";

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  helpUri?: string;
}

interface SarifResult {
  ruleId: string;
  level: "error";
  message: { text: string };
  locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
  suppressions?: Array<{ kind: "external" }>;
}

function toUri(path: string): string {
  return path.replace(/\\/g, "/");
}

function ruleFor(v: Vulnerability): SarifRule {
  const rule: SarifRule = { id: v.id, shortDescription: { text: v.summary ?? v.id } };
  if (v.id.startsWith("GHSA-")) rule.helpUri = `https://github.com/advisories/${v.id}`;
  return rule;
}

export function renderSarif(audits: readonly ProjectAudit[]): string {
  const rules = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const project of audits) {
    for (const dep of project.deps) {
      const uri = toUri(dep.dep.source.path);
      for (const v of dep.vulnerabilities) {
        if (!rules.has(v.id)) rules.set(v.id, ruleFor(v));
        const fix = dep.minSafeVersion ? ` (fixed in ${dep.minSafeVersion})` : "";
        results.push({
          ruleId: v.id,
          level: "error",
          message: { text: `${dep.dep.name}@${dep.dep.resolved ?? dep.dep.range}: ${v.summary ?? v.id}${fix}` },
          locations: [{ physicalLocation: { artifactLocation: { uri } } }],
        });
      }
      for (const v of dep.suppressedVulnerabilities ?? []) {
        if (!rules.has(v.id)) rules.set(v.id, ruleFor(v));
        results.push({
          ruleId: v.id,
          level: "error",
          message: { text: `${dep.dep.name}@${dep.dep.resolved ?? dep.dep.range}: ${v.summary ?? v.id} (suppressed)` },
          locations: [{ physicalLocation: { artifactLocation: { uri } } }],
          suppressions: [{ kind: "external" }],
        });
      }
    }
  }

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "npmtastic",
            informationUri: "https://github.com/boredchilada/npmtastic",
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
