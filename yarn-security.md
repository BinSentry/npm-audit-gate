# Yarn 4 Security Guide

This document highlights some of the features of Yarn 4 that we use, with a particular emphasis on configuring and resolving vulnerabilities.

## New Guardrails

These live in each repo's `.yarnrc.yml`.

### Minimum release age — `npmMinimalAgeGate: "1w"`

Packages published less than a week ago are refused. This is intended to protect us from compromised releases,
as most are caught and unpublished within days.

If you need a newer package urgently, possibly to fix a critical vulnerability that's failing a build,
you can add it to `npmPreapprovedPackages` in `.yarnrc.yml`:

```yaml
npmPreapprovedPackages:
  - "@types/node@24.12.4"
```

Note that bypassing this restriction is not the safe default. You are choosing between two risks:

- accepting a package that hasn't been public long enough for a bad release to be caught
- accepting the known vulnerability for a few days, and adding it to `.audit-allowlist.jsonc` so the build passes in the meantime

Generally speaking, if the vulnerability does not affect any code that we ship, waiting is usually preferable.
If it does, updating sooner may be worth the exposure. This decision is left to the discretion of the developer.

See the [`@binsentry/npm-audit-gate` README](https://www.npmjs.com/package/@binsentry/npm-audit-gate) for how to allowlist an advisory, as well as how to give it an expiry date,
if you're only waiting out the age gate.

### Git dependency allowlist — `approvedGitRepositories`

Only BinSentry repositories may be pulled as git dependencies. Anything else fails with:

```
YN0080: Request to 'ssh://git@github.com/someone/thing' has been blocked because it doesn't
match any of the patterns in 'approvedGitRepositories'
```

### Install scripts disabled — `enableScripts: false`

Dependencies' `install` and `postinstall` scripts no longer run, as they can run arbitrary code
on your machine, and are typically not needed.

You may need one when a package compiles native code or downloads a binary, in which case,
you can allow it by naming that package in `package.json`:

```json
"dependenciesMeta": {
  "some-native-package": { "built": true }
}
```

## Auditing Packages

If an advisory is released for a package we are using, at or above the severity level that repo gates on,
any CI pipeline that currently has an auditing step (currently only API)
will flag this, and the build will fail. This is handled by the `@binsentry/npm-audit-gate` package.

If you believe that this package is needed or that we are not vulnerable to the security vulnerability,
you can create an exception for this advisory. See the package's README for how to run the gate
locally and how to add an allowlist entry:

https://www.npmjs.com/package/@binsentry/npm-audit-gate
