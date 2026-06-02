# Security Policy

## Supported versions

npmtastic is pre-1.0. Only the latest released version receives security fixes.

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue.

Email **security@cyfar.ca** with the details. You may also use GitHub's private
vulnerability reporting (the **"Report a vulnerability"** button under this
repository's **Security** tab). Reports are acknowledged as soon as practical.

## Scope

npmtastic is read-only: it reads `package.json` and lockfiles and queries public
APIs (the npm registry and [OSV.dev](https://osv.dev)). It does not modify the
projects it audits, run package scripts, or execute installed code. Reports that
demonstrate a way to make it write, execute, or exfiltrate data — including via
crafted/untrusted `package.json` or lockfile input — are in scope and welcome.
