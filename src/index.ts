// SPDX-License-Identifier: AGPL-3.0-or-later
export * from "./models.js";
export { discoverOne, discoverTree } from "./discovery.js";
export { collectDeps, parseSource, canonicalName, collectLockPackages, dependencyPaths } from "./parsing.js";
export { auditProject, classifyPinStatus, classifyDrift, pickLatest } from "./analysis.js";

export { RegistryClient } from "./registry.js";
export { VulnClient, computeMinSafeVersion, severityRank } from "./vulns.js";
export { renderAuditJson, SCHEMA_VERSION } from "./render/json.js";
export { renderSarif } from "./render/sarif.js";
export { renderTerminal } from "./render/terminal.js";
export { renderReport } from "./render/report.js";
export { renderMarkdown } from "./render/markdown.js";
export { renderAgent, renderAgentError, renderNdjson } from "./render/agent.js";
export { renderCycloneDx } from "./render/cyclonedx.js";
export { updateProject, selectTarget, resolveTarget } from "./update.js";

export { bootstrapProject } from "./bootstrap.js";
export { write as writeBaseline, load as loadBaseline, diff as diffBaseline, findings as baselineFindings, BaselineError } from "./baseline.js";
export { loadConfig, ConfigError, parseToml } from "./config.js";
export { buildStats, renderStats } from "./stats.js";
export { isRemote, acquire, splitRef } from "./sources.js";
export { verifyLock } from "./verify.js";

export { main } from "./cli.js";
