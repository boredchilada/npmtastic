<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# npmtastic

A Node.js dependency auditor that reports pin posture, registry drift, and known CVEs.

It is the npm-side counterpart to [piptastic](https://github.com/boredchilada/piptastic)
(the Python dependency auditor) and follows the same design and conventions.

## What it does

`npmtastic` walks a directory tree, finds Node projects (any directory with a
`package.json`), parses the manifest and lockfiles, and reports, per dependency:

- **Pin posture**: `pinned` / `compatible` / `range` / `floor` / `unpinned` / `url`,
  read from the shape of the declared range (so `1.2.3` is pinned, `^1.2.3` and `~1.2.3`
  are compatible, `>=1.2.3` is a floor).
- **Drift** against the npm registry: `none` / `prerelease` / `patch` / `minor` /
  `major`, or `unknown` when the registry can't be reached or the version isn't pinned.
- **Known CVEs** from the [OSV.dev](https://osv.dev) database (optionally cross-checked
  against the npm registry's audit endpoint), plus the **minimum safe version** that
  fixes them.

`audit` is **read-only**: it reads your manifests and lockfiles, queries public APIs, and
never writes to the projects it scans. Two opt-in write commands round it out:
**`update`** pins and upgrades dependencies (with a backup, an isolated test install, and
rollback), and **`bootstrap`** reconstructs a `package.json` from a lockfile or
`node_modules`. One broken project won't abort a scan: if a file fails to parse or a
request fails, npmtastic logs a warning to stderr and moves on, marking that dependency or
project unreachable.

Supported inputs: `package.json` (dependencies / devDependencies / peerDependencies /
optionalDependencies) and `package-lock.json` / `npm-shrinkwrap.json` (v1, v2, v3),
`pnpm-lock.yaml`, and `yarn.lock` (classic v1 and berry). When a lockfile is present it
provides the resolved graph; direct dependencies keep their declared range from
`package.json`.

## Requirements

- Node.js **>= 20** (uses the built-in `fetch` and `util.parseArgs`).

## Install

Not yet published to npm. From source:

```sh
git clone https://github.com/boredchilada/npmtastic
cd npmtastic
npm install
npm run build
node dist/bin.js --help
```

Once published it will be available as `npmtastic` / `ntc` (and via `npx npmtastic`).

## Usage

```sh
npmtastic audit <path> [options]
```

Examples:

```sh
# Audit the current project (table view)
npmtastic audit .

# Scan a whole tree, one row per project
npmtastic audit ~/code --view summary

# Show only vulnerable dependencies
npmtastic audit . --vulnerable-only

# CI gate: fail (exit 3) if any known CVE is present
npmtastic audit . --fail-on-vuln any

# Machine-readable output
npmtastic audit . --json
npmtastic audit . --sarif > npmtastic.sarif
```

## Options

**Output**

| Flag | Description |
| --- | --- |
| `--json` | Machine-readable JSON (`schemaVersion` 1). |
| `--sarif` | SARIF 2.1.0 (GitHub Code Scanning). Mutually exclusive with `--json`. |
| `--view tree\|table\|summary` | Terminal layout. Default: `table` for a single project, `tree` for a tree scan. |
| `--no-color` | Strip ANSI color. (`NO_COLOR` is also honored.) |

**Vulnerability source**

| Flag | Description |
| --- | --- |
| `--source osv\|npm-audit\|both` | CVE source. Default `osv`. `both` unions OSV with the npm registry audit endpoint (deduped by advisory id). |

**Filters** (these change what's displayed, not what the gates evaluate)

| Flag | Description |
| --- | --- |
| `--vulnerable-only` | Show only dependencies with known CVEs. |
| `--drift-min LEVEL` | Show only dependencies drifted at least `LEVEL` (`patch`/`minor`/`major`). |

**Gates** (evaluated on the unfiltered results; trip → exit code 3)

| Flag | Description |
| --- | --- |
| `--fail-on-drift LEVEL` | Fail if any dep has drifted at least `LEVEL`. |
| `--fail-on-vuln any\|N` | Fail if the total CVE count is at least `N` (`any` = 1). |
| `--fail-on-age DAYS` | Fail if any dep's latest release is older than `DAYS` (strict `>`). |

**Discovery / cache**

| Flag | Description |
| --- | --- |
| `--exclude GLOB` | Prune directories by basename (repeatable). |
| `--include-prereleases` | Treat the latest prerelease as the effective latest. |
| `--no-cache` / `--refresh-cache` | Bypass the on-disk cache (TTL 0). |
| `--cache-ttl S` | Cache TTL in seconds (default 3600). |
| `--concurrency N` | Max concurrent registry/OSV requests (default 8). |
| `--quiet` | Suppress warnings on stderr. |

`-h`/`--help`, `-v`/`--version`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | OK. |
| `1` | Operational error (bad arguments, path not found, `--json`+`--sarif`). |
| `2` | `update` rolled back: a test install failed and the changes were reverted. |
| `3` | A policy gate tripped (`--fail-on-*`). |

## `update` (pin and upgrade)

Rewrites dependency versions in `package.json`, with a backup, an isolated test install,
and rollback on failure. Two modes:

- Default: bump dependencies that are already pinned exact to the latest stable version,
  raising to the minimum safe version when the current one has a known CVE.
- `--pin`: convert loose ranges on direct dependencies (`^1.3.0`) to the exact resolved
  version, again raising past any CVE.

```sh
npmtastic update <path> [options]
```

| Flag | Description |
| --- | --- |
| `--pin` | Convert direct-dep ranges to the exact resolved version. |
| `--packages a,b,c` | Limit to these dependencies. |
| `--dry-run` | Show the changes, write nothing. |
| `--no-test` | Skip the isolated install check (and its rollback). |
| `--exclude GLOB` | Prune directories by basename when scanning a tree. |
| `--source`, cache flags, `--quiet` | Same as `audit`. |

It changes only the version strings, leaving the rest of your `package.json` byte-for-byte
intact, and refuses to touch a manifest it can't parse. Before writing it copies the
original to `.npmtastic_backups/`; after writing it validates the result with an install
in a throwaway temp directory (your real `node_modules` is never touched) and restores the
backup if that install fails (exit code `2`). Accepted-risk CVEs (see Suppressions) never
drive a bump.

## `bootstrap` (reconstruct a package.json)

Rebuilds a `package.json` when it is missing, empty, or unparseable but the project is
installed. Prints to stdout by default. Local-only; no network.

```sh
npmtastic bootstrap <path> [options]
```

By default it reconstructs from the lockfile's root entry (`package-lock.json`'s
`packages[""]`, or `pnpm-lock.yaml`'s `importers["."]`), recovering the real direct
dependencies, their groups, and their declared ranges. Non-installable specifiers
(`workspace:`, `link:`, and the like) are skipped with a warning. With no usable lockfile
(yarn, npm lockfileVersion 1, or none), it falls back to freezing `node_modules`.

| Flag | Description |
| --- | --- |
| `--from-node-modules` | Freeze installed top-level `node_modules` at exact versions instead. Includes hoisted transitive deps, so review before keeping. |
| `--write` | Write `package.json` (refuses to overwrite an existing one without `--force`). |
| `--force` | Overwrite an existing `package.json` (it is backed up to `.npmtastic_backups/` first). |
| `--quiet` | Suppress warnings on stderr. |

## Suppressions

Accepted-risk advisories are declared in the project's `package.json`:

```json
{
  "npmtastic": {
    "suppressions": [
      { "id": "GHSA-vj76-c3g6-qr5v", "package": "tar-fs", "reason": "not reachable in our usage" },
      { "package": "left-pad", "reason": "deprecated but harmless" }
    ]
  }
}
```

A rule matches by advisory `id` (or one of its aliases) and/or `package` name. When both
are given, both must match. Suppressed advisories are **excluded** from `vulnCount`, the
`--fail-on-vuln` gate, and the minimum-safe-version calculation. They are still
reported, though: in JSON under `suppressedVulnerabilities`, and in SARIF as results
carrying `suppressions: [{ "kind": "external" }]`.

## JSON output

`schemaVersion` is `1`. Top-level shape:

```json
{
  "kind": "audit",
  "schemaVersion": 1,
  "projects": [
    {
      "name": "...", "root": "...",
      "pinningScore": 1.0,
      "driftSummary": { "none": 10, "patch": 1, "minor": 2, "major": 1, "unknown": 0 },
      "deprecatedCount": 0, "registryUnreachable": 0,
      "vulnCount": 1, "vulnUnreachable": 0, "suppressedCount": 0,
      "deps": [
        {
          "name": "...", "range": "^1.0.0", "resolved": "1.3.0", "direct": true, "group": "default",
          "pinStatus": "compatible", "drift": "major",
          "latest": "2.0.0", "latestReleaseDate": "...", "latestReleaseAgeDays": 120,
          "minSafeVersion": null,
          "vulnerabilities": [ { "id": "GHSA-...", "aliases": ["CVE-..."], "summary": "...", "fixedVersions": ["..."] } ],
          "suppressedVulnerabilities": []
        }
      ]
    }
  ]
}
```

`pinningScore` is the fraction of non-`url` **direct** dependencies that are `pinned` or
`compatible` (`null` when there are none).

## Caching

Registry and OSV responses are cached on disk (default TTL 1 hour). The cache root is
`$NPMTASTIC_CACHE_DIR`, else `$XDG_CACHE_HOME/npmtastic`, else `~/.cache/npmtastic`.

## Development

```sh
npm test          # vitest
npm run build     # tsc -> dist/
npm run dev -- audit .   # tsx, no build step
```

## License

AGPL-3.0-or-later.
