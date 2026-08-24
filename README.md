# npm-audit-gate

CI gate that fails builds on npm vulnerabilities, with exceptions scoped by advisory and exact
dependency path. Yarn 4 only.

`yarn npm audit` reports which packages are vulnerable, and `yarn info` provides the resolved
dependency graph, which gives every full path by which those packages are reached. The gate fails
if any of those paths is not covered by the consuming repo's `.audit-allowlist.jsonc`.