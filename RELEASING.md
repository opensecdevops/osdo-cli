# Releasing the OSDO CLI (npm)

The package is published by `.github/workflows/npm-release.yml`. It runs only
from `workflow_dispatch`, and nothing is published unless the `dry-run` input
is set to `false`.

## Workflow structure

- `build` (read-only token, no OIDC): `npm ci --ignore-scripts`, build, test,
  `npm pack --ignore-scripts`, upload the tarball as an artifact.
- `publish` (environment `npm-release`, `id-token: write`): runs only when
  `build` succeeds, the ref is `main` or a `v*` tag, and `dry-run` is false. It
  downloads the tarball and runs
  `npm publish <tarball> --provenance --access public --ignore-scripts`. It does
  not install project dependencies or run lifecycle scripts.

## Founder setup (required before the first real publish)

1. **Environment `npm-release`** (Settings, then Environments):
   - Required reviewer: at least one maintainer other than the person
     dispatching the run.
   - Deployment branches and tags: restrict to `main` and `v*`. Without this
     rule, any branch can request a deployment to the environment.
2. **npm trusted publisher**: on npmjs.com, bind the package to this
   repository (`opensecdevops/osdo-cli`), the workflow file
   `npm-release.yml`, and the environment `npm-release`. Publishing fails if
   any of the three does not match. No npm token is stored in GitHub.
3. **Package name**: confirm the scope. The package is currently `@osdo/cli`.
   Proposal: `@opensecdevops/cli`. Both names are unregistered today
   (2026-11-25), and the scope owner must be verified before the first publish.

## Cutting a release

1. Bump `version` in `package.json` on `main`. npm rejects a version that is
   already published.
2. Run "npm release (manual)" from `main` with `dry-run` set to `true`. Check
   the artifact contents.
3. Run it again with `dry-run` set to `false`, and approve the environment
   deployment.
4. Verify provenance on npmjs.com (the "Provenance" badge on the version page).

## Known gaps

- `prepack` requires the `oclif` CLI, which is not a devDependency. The
  tarball is therefore packed with `--ignore-scripts` and does not include
  `oclif.manifest.json`. oclif falls back to runtime discovery. Adding `oclif`
  as a devDependency is a separate change.
- `npm test` fails at mocha startup on Node 26 (yargs ESM error). CI pins
  Node 22, but this has not been verified there.
- Action references are pinned by full SHA, with the tag in a comment. Keep
  them current with Dependabot or Renovate.
