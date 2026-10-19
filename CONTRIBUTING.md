# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Before you start

- For anything bigger than a small fix, open an issue first so we can agree on the approach.
- Security problems go to [SECURITY.md](SECURITY.md), not to public issues.

## Working on it

```sh
npm install
npm test
npm run typecheck
```

Node 22.18 or later runs the TypeScript tests directly. No build step is needed.

## What we look for

- **A test for every behaviour change.** Tests live in `test/` and run against an in-memory D1 stand-in. Security
  changes need a test showing what's now refused.
- **No new runtime dependencies** without a strong reason. The kit stays small enough to read in one sitting.
- **Comments that say why.** Each file opens with a short note on what it does. Keep those notes accurate.
- **The safety model stays as it is.** Read is the default, write is opt-in, and approvals, payments and access
  changes stay out of tools. Pull requests that weaken it won't be merged.

## Licence

By contributing, you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).
