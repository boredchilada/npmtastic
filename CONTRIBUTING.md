# Contributing

Thanks for your interest in npmtastic.

## Development

- Node.js >= 20.
- `npm install`
- `npm test` — run the vitest suite. All tests must pass.
- `npm run build` — compile with `tsc` to `dist/`.
- `npm run dev -- audit .` — run from source via `tsx`, no build step.

## Conventions

- TypeScript, ESM (`NodeNext`). Relative imports use the `.js` extension even
  though the files are `.ts`.
- Every source file under `src/` starts with
  `// SPDX-License-Identifier: AGPL-3.0-or-later`.
- Tests mirror sources under `test/`; fixtures are real directory trees under
  `test/fixtures/`. New behavior needs a test that would fail without the change.
- Network and subprocess clients degrade gracefully — a parse or fetch failure
  logs a warning and is skipped, it never crashes a scan.
- Conventional commit subjects (`feat:`, `fix:`, `docs:`, `chore:`, `test:`,
  `refactor:`). Explain the *why* in the body. No attribution trailers.

## Pull requests

- Keep changes focused. Ensure `npm test` and `npm run build` pass.
- Describe what changed and why.
