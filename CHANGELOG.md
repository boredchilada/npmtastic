# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0]

Initial version.

### Added
- `audit` command: discover Node projects in a directory tree and report, per
  dependency, pin posture, registry drift, and known CVEs.
- Parsers for `package.json` and `package-lock.json` / `npm-shrinkwrap.json`
  (v1/v2/v3), `pnpm-lock.yaml`, and `yarn.lock` (classic and berry).
- Pin-posture classification, semver drift against the npm registry, and
  latest-version selection (deprecation- and prerelease-aware).
- Vulnerability lookup via [OSV.dev](https://osv.dev), with an optional npm-audit
  cross-check (`--source osv|npm-audit|both`) and a minimum-safe-version
  recommendation.
- Output renderers: terminal (table / summary / tree), JSON (`schemaVersion` 1),
  and SARIF 2.1.0.
- CI gates (`--fail-on-drift`, `--fail-on-vuln`, `--fail-on-age`), display
  filters (`--vulnerable-only`, `--drift-min`), on-disk caching, and accepted-risk
  suppressions declared in `package.json` under `npmtastic.suppressions`.
- Graceful degradation: malformed or non-UTF-8 manifests/lockfiles, and registry
  or OSV failures, log a warning and are skipped rather than aborting the scan.
