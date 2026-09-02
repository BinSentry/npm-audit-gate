# npm-audit-gate

CI gate that fails builds on npm vulnerabilities, with exceptions scoped by advisory and exact
dependency path. Yarn 4 only.

`yarn npm audit` reports which packages are vulnerable, and `yarn info` provides the resolved
dependency graph, which gives every full path by which those packages are reached. The gate fails
if any of those paths is not covered by the consuming repo's `.audit-allowlist.jsonc`.

## Usage

Run the gate from the root of the repo you want to check:

```
npx @binsentry/npm-audit-gate
```

`Exit 0` means no unallowlisted advisories.

Each exception is scoped to one advisory arriving via one exact dependency path, so an advisory
accepted because it arrives through a build-time tool will still fail the build if it later
arrives through a runtime dependency.

## Adding an allowlist entry

When the gate fails, it prints everything you need:

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
    { "ghsa": "GHSA-xvch-5gv4-984h", "path": "ndarray-unpack>cwise>static-module>quote-stream>minimist" }
  ]
}
```

A package reached more than one way produces one failure per path, and each needs its own entry.

`severity` sets the threshold for the whole repo and defaults to `critical` if omitted. It is a
floor, so `high` also reports anything critical. The file itself is optional: a repo with no
exceptions doesn't need one.

An entry may also set `"expires": "2027-01-01"`, after which it stops matching and the build fails
again. Set one whenever the exception is meant to be temporary (i.e. waiting out a fix that is not
available yet) so the entry can't outlive the reason for it.

An entry that matches nothing is reported as unused — either the advisory was fixed, the path
changed, or it expired. Remove it.
