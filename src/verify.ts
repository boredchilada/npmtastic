// SPDX-License-Identifier: AGPL-3.0-or-later
import type { IntegrityFinding, LockPackage, PackageMeta } from "./models.js";

const REGISTRY_HOSTS: Record<string, true> = { "registry.npmjs.org": true, "registry.npmjs.com": true };


export function isNpmRegistrySource(resolved: string | null, link = false): boolean {
  if (link) return false;
  if (!resolved) return true;
  if (/^(git\+|git:|github:|gitlab:|bitbucket:|file:|link:|workspace:)/i.test(resolved)) return false;
  try {
    const url = new URL(resolved);
    return (url.protocol === "https:" || url.protocol === "http:") && REGISTRY_HOSTS[url.hostname] === true;
  } catch {
    return false;
  }
}


function publishedIntegrity(meta: PackageMeta | undefined, version: string): string | null {
  if (!meta) return null;
  for (const release of meta.releases) {
    if (release.version === version) return release.integrity ?? null;
  }
  return null;
}

export function verifyLock(
  packages: readonly LockPackage[],
  metas: Map<string, PackageMeta>,
): IntegrityFinding[] {
  const findings: IntegrityFinding[] = [];
  for (const pkg of packages) {
    if (!isNpmRegistrySource(pkg.resolved, pkg.link)) {
      findings.push({
        name: pkg.name,
        version: pkg.version,
        kind: "unexpected-source",
        detail: pkg.link ? "link" : pkg.resolved || "unknown",
      });
      continue;
    }
    const expected = publishedIntegrity(metas.get(pkg.name), pkg.version);
    if (!pkg.integrity || !expected) {
      findings.push({
        name: pkg.name,
        version: pkg.version,
        kind: "unverifiable",
        detail: "no integrity available",
      });
    } else if (pkg.integrity !== expected) {
      findings.push({
        name: pkg.name,
        version: pkg.version,
        kind: "mismatch",
        detail: `lock=${pkg.integrity.slice(0, 20)} vs npm=${expected.slice(0, 20)}`,
      });
    }
  }
  return findings;
}
