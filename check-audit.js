/* eslint-disable no-console */
/**
 * Audit gate, replacing audit-ci (which does not support yarn 4).
 *
 * `yarn npm audit` reports which packages are vulnerable, and `yarn info` provides the resolved
 * dependency graph, which tells us every full path by which those packages are reached. The gate
 * fails if any path to a vulnerable package is not covered by .audit-allowlist.jsonc:
 *
 *   {
 *     "severity": "critical",
 *     "allowlist": [
 *       // Why this is acceptable for now
 *       { "ghsa": "GHSA-mp2f-45pm-3cg9", "path": "serverless>@serverless/utils>decompress" }
 *     ]
 *   }
 *
 * Each entry is scoped to a single advisory arriving via a single exact path, so exceptions stay
 * as narrow as possible. An entry may also set `"expires": "2027-01-01"`: once that date passes,
 * the entry stops matching.
 */
const { spawnSync } = require('child_process');
const fs = require('fs');

const CONFIG_PATH = '.audit-allowlist.jsonc';
const DOCS_URL = 'https://github.com/BinSentry/npm-audit-gate/blob/master/yarn.md';

// Runs a yarn command with --json and parses the NDJSON output (one JSON object per line).
// `yarn npm audit` exits 1 when it finds advisories, so callers list the exit codes
// under which the output is still valid.
function runYarnJson(args, validExitCodes) {
  const jsonArgs = [...args, '--json'];
  const command = spawnSync('yarn', jsonArgs, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

  if (command.error || !validExitCodes.includes(command.status)) {
    console.error(command.stderr || `${command.error}`);
    console.error(`❌ yarn ${jsonArgs.join(' ')} failed`);
    process.exit(1);
  }

  return command.stdout
    .split('\n')
    .filter((line) => line !== '')
    .map((line) => JSON.parse(line));
}

// `yarn npm audit` and `yarn info`, with the flags this script passes, require yarn 4.
// Checking upfront turns the cryptic errors of older yarns into a clear message.
function requireYarn4() {
  const command = spawnSync('yarn', ['--version'], { encoding: 'utf8' });

  if (command.error || command.status !== 0) {
    console.error(`❌ This audit gate requires yarn 4, but "yarn --version" failed: ${command.stderr || command.error}`);
    process.exit(1);
  }

  const version = command.stdout.trim();

  if (Number(version.split('.')[0]) < 4) {
    console.error(`❌ This audit gate requires yarn 4, but this project uses yarn ${version}.`);
    process.exit(1);
  }
}

// Yarn identifies each resolved package by a "locator" such as "@scope/name@npm:1.2.3".
// The name is everything before the first "@" past the (optional) scope.
function packageName(locator) {
  return locator.slice(0, locator.indexOf('@', 1));
}

// A package with peer dependencies gets a distinct "virtual" locator per consumer, e.g.
// "pkg@virtual:abc123#npm:1.2.3". Consumers point at the virtual locators, while the package's
// own record and dependencies live under the underlying locator ("pkg@npm:1.2.3"), so virtuals
// must be collapsed onto it to keep the graph connected.
function devirtualize(locator) {
  return locator.replace(/@virtual:[^#]+#/, '@');
}

// The resolved dependency graph, indexed the two ways we need it: by package name, to jump
// straight from an advisory to the packages it names; and inverted (package -> dependents),
// to walk from any package up to the workspace.
function loadDependencyGraph() {
  const packagesByName = new Map(); // "@scope/name" -> [{ locator, version }]
  const dependents = new Map(); // locator -> the locators that depend on it

  // Adds a value to the array stored under `key`, creating the array on first use.
  function appendTo(map, key, value) {
    if (!map.has(key)) {
      map.set(key, []);
    }
    map.get(key).push(value);
  }

  for (const record of runYarnJson(['info', '--all', '--recursive'], [0])) {
    const locator = record.value;
    appendTo(packagesByName, packageName(locator), { locator, version: record.children.Version });

    for (const dependency of record.children.Dependencies ?? []) {
      appendTo(dependents, devirtualize(dependency.locator), locator);
    }
  }

  return { packagesByName, dependents };
}

// Every chain of package names leading from a direct dependency of the workspace down to
// `locator`, e.g. ["serverless", "@serverless/utils", "decompress"]. Recursively walks up
// the inverted graph; `visited` breaks dependency cycles.
function dependencyPathsTo(locator, graph, visited = new Set([locator])) {
  if (locator.includes('@workspace:')) {
    return [[]]; // reached the top: one empty path, since the workspace itself is left out
  }

  const paths = [];

  for (const dependent of graph.dependents.get(locator) ?? []) {
    if (visited.has(dependent)) {
      continue;
    }

    const pathsToDependent = dependencyPathsTo(dependent, graph, new Set(visited).add(dependent));

    for (const path of pathsToDependent) {
      paths.push([...path, packageName(locator)]);
    }
  }

  return paths;
}

function runAudit(severity) {
  const args = [
    'npm', 'audit',
    '--all', // audit every workspace
    '--recursive', // include transitive dependencies
    '--environment', 'all', // include devDependencies
    '--no-deprecations', // deprecation warnings are not vulnerabilities
    '--severity', severity,
  ];

  return runYarnJson(args, [0, 1]).map((record) => ({
    packageName: record.value,
    issue: record.children.Issue,
    severity: record.children.Severity,
    url: record.children.URL,
    ghsa: record.children.URL.split('/').pop(),
    vulnerableVersions: record.children['Tree Versions'],
  }));
}

// The audit reports which versions of the vulnerable package appear in our tree. Look those
// packages up in the graph, then collect every path that pulls them in.
function vulnerablePathsFor(advisory, graph) {
  const paths = new Set();
  const packages = graph.packagesByName.get(advisory.packageName) ?? [];

  for (const { locator, version } of packages) {
    if (advisory.vulnerableVersions.includes(version)) {
      for (const path of dependencyPathsTo(locator, graph)) {
        paths.add(path.join('>'));
      }
    }
  }

  return [...paths];
}

// JSONC is JSON with comments. Match every string first, so that comment markers inside
// strings are kept, then strip the actual // and /* */ comments.
function parseJsonc(text) {
  const stringOrComment = /"(?:\\.|[^"\\])*"|\/\/.*|\/\*[\s\S]*?\*\//g;

  return JSON.parse(text.replace(stringOrComment, (match) => (match.startsWith('"') ? match : ' ')));
}

function loadConfig() {
  if (!fs.existsSync(CONFIG_PATH)) {
    return { severity: 'critical', allowlist: [] };
  }

  const config = parseJsonc(fs.readFileSync(CONFIG_PATH, 'utf8'));

  return {
    severity: config.severity ?? 'critical',
    allowlist: config.allowlist ?? [],
  };
}

function findAllowlistEntry(allowlist, advisory, path) {
  const today = new Date().toISOString().slice(0, 10);

  return allowlist.find((entry) => entry.ghsa === advisory.ghsa
    && entry.path === path
    && (!entry.expires || entry.expires > today));
}

function run() {
  requireYarn4();

  const { severity, allowlist } = loadConfig();
  const graph = loadDependencyGraph();
  const usedEntries = new Set();
  let failures = 0;

  for (const advisory of runAudit(severity)) {
    for (const path of vulnerablePathsFor(advisory, graph)) {
      const entry = findAllowlistEntry(allowlist, advisory, path);

      if (entry) {
        usedEntries.add(entry);
        continue;
      }

      console.error(`❌ ${advisory.packageName} ${advisory.ghsa} (${advisory.severity}): ${advisory.issue}`);
      console.error(`   ${advisory.url}`);
      console.error(`   path: ${path}\n`);
      failures++;
    }
  }

  for (const entry of allowlist) {
    if (!usedEntries.has(entry)) {
      console.warn(`⚠️  Unused allowlist entry (advisory fixed, expired, or path changed): ${entry.ghsa} ${entry.path}`);
    }
  }

  if (failures > 0) {
    console.error(`\nAudit failed: ${failures} vulnerable dependency path(s) not in ${CONFIG_PATH}.`);
    console.error(`How to fix, allowlist, or reproduce this locally: ${DOCS_URL}`);
    process.exit(1);
  }

  console.log(`✅ Audit passed: no ${severity}+ advisories outside the allowlist.`);
}

run();
