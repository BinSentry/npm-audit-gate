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

See [Adding an allowlist entry](#adding-an-allowlist-entry) for how to allowlist an advisory, as well as how to give it an expiry date,
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
will flag this, and the build will fail. This is handled by `check-audit.js`.

If you believe that this package is needed or that we are not vulnerable to the security vulnerability,
you can create an exception for this advisory.

Each exception is scoped to one advisory arriving via one exact dependency path, so an advisory
accepted because it arrives through a build-time tool will still fail the build if it later
arrives through a runtime dependency.

### Running the audit script locally

In order to run `check-audit.js` locally, run the following command from the repo you want to check:

```
node /srv/binsentry/npm-audit-gate/check-audit.js
```

This requires the `npm-audit-gate` repo to have been cloned.

`Exit 0` means no unallowlisted advisories.

### Adding an allowlist entry

When the `audit` step in the CI pipeline fails, it prints everything you need:

```
❌ minimist GHSA-xvch-5gv4-984h (critical): Prototype Pollution in minimist
   https://github.com/advisories/GHSA-xvch-5gv4-984h
   path: ndarray-unpack>cwise>static-module>quote-stream>minimist
```

Copy the `ghsa` and the `path` into `.audit-allowlist.jsonc` at the repo root, with a comment
saying why the risk is acceptable and what would change that:

```jsonc
{
  "severity": "critical",
  "allowlist": [
    // ndarray hasn't been updated in 12 years, so there is no upgrade path available.
    // Needs to be dealt with in the bin-3d-feed-volume package.
    { "ghsa": "GHSA-xvch-5gv4-984h", "path": "ndarray-unpack>cwise>static-module>quote-stream>minimist" }
  ]
}
```

A package reached more than one way produces one failure per path, and each needs its own entry.

`severity` sets the threshold for the whole repo and defaults to `critical` if omitted. It is a
floor, so `high` also reports anything critical. The file itself is optional: a repo with no
exceptions doesn't need one.

An entry may also set `"expires": "2027-01-01"`, after which it stops matching and the build fails
again. Set one whenever the exception is meant to be temporary (i.e. waiting out the minimum release
age on a fix) so the entry can't outlive the reason for it.

An entry that matches nothing is reported as unused — either the advisory was fixed, the path
changed, or it expired. Remove it.
