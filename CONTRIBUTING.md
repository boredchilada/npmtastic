# Contributing

Thanks for your interest in npmtastic.

## Development

You'll need Node.js 20 or newer. Then:

- `npm install` to get the dev dependencies.
- `npm test` runs the vitest suite. Everything should be green before you commit.
- `npm run build` compiles with `tsc` into `dist/`.
- `npm run dev -- audit .` runs straight from source with `tsx`, no build step.

## Conventions

- TypeScript, ESM (`NodeNext`). Relative imports use the `.js` extension even
  though the files are `.ts`.
- Every source file under `src/` starts with
  `// SPDX-License-Identifier: AGPL-3.0-or-later`.
- Tests mirror sources under `test/`; fixtures are real directory trees under
  `test/fixtures/`. New behavior needs a test that would fail without the change.
- Network and parsing code degrades gracefully. When a file won't parse or a
  request fails, log a warning and skip it. Never let it crash a scan.
- Conventional commit subjects (`feat:`, `fix:`, `docs:`, `chore:`, `test:`,
  `refactor:`). Explain the *why* in the body. No attribution trailers.

## Pull requests

- Keep changes focused. Ensure `npm test` and `npm run build` pass.
- Describe what changed and why.
