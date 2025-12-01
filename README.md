# 🔍 dependency-scanner

A CLI tool to scan dependency manifests and lockfiles for known vulnerabilities.

## Tool overview

- Parses dependency file (lockfile preferred, manifest as fallback)
- Builds a dependency graph (direct and transitive where available)
- Queries vulnerability databases (selectable via `--database-source` flag):
  - [Open Source Vulnerabilities](https://osv.dev/list) (OSV.dev)
  - [GitHub Security Advisories](https://github.com/advisories) (GHSA)
- Prints the summary of findings to console and generates a `report.json` file

## Supported filetypes

| Ecosystem | Filename | Type | Notes |
|-----------|----------|------|-------|
| **Node.js** | `package-lock.json` | Lockfile | v2 and v3 format (npm v7+) |
| **Node.js** | `yarn.lock` | Lockfile | v1 (classic) and v2+ (Berry) |
| **Node.js** | `package.json` | Manifest | Direct dependencies only |
| **Python** | `poetry.lock` | Lockfile | Full dependency tree |
| **Python** | `Pipfile.lock` | Lockfile | Full dependency tree |
| **Python** | `requirements.txt` | Manifest | Direct dependencies only |

### Known limitations

#### Filetype differences

- Lockfiles (`package-lock.json`, `yarn.lock`, `poetry.lock`, `Pipfile.lock`) contain the full resolved dependency tree, including transitive dependencies
- Manifest files (`package.json`, `requirements.txt`) only list direct dependencies, as there's no way to discover transitive deps without a package manager

> 💡 When scanning a manifest file, **only direct dependencies are checked and a warning is printed to the console**. Future versions may auto-detect the appropriate lockfile in the target project, or optionally invoke package managers for full resolution.

#### Ecosystem constraints

- `package-lock.json` v1 format is not currently supported (npm v6 and earlier)
- `requirements.txt` files containing version ranges (eg., `requests>=2.0`) may not match exact vulnerability ranges

## Getting started

### Prerequisites

[Node.js](https://node.jsorg) v18+ is required. The tool was tested and developed with [v24.9.0](https://nodejs.org/en/blog/release/v24.9.0).

```bash
npm install   # Install node dependencies
npm run build # Build dependency-scanner tool

npx dependency-scanner # Run the built CLI tool
```

#### GitHub Token

While a GitHub [personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) (PAT) is not required to query GHSA, the API [rate limits queries](https://docs.github.com/en/graphql/overview/rate-limits-and-node-limits-for-the-graphql-api) to 60 reqs/hr without authentication. With a valid PAT, the rate limit increases to 5000 reqs/hr. 

> 💡 Create a new fine-grained personal access token on GitHub [here](https://github.com/settings/personal-access-tokens/new).

```bash
# Option 1: Export as environment variable
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx

# Option 2: Pass as CLI flag
npx dependency-scanner --database-source ghsa --github-token ghp_xxxxxxxxxxxx
```

### CLI config

| Option | Default | Description |
|--------|---------|-------------|
| `[file]` | `./package-lock.json` | Path to lockfile or manifest to scan |
| `--database-source` | `osv` | Vulnerability database to query: `osv` or `ghsa` |
| `--github-token` | `$GITHUB_TOKEN` | GitHub PAT for GHSA queries (increases rate limit) |

### CLI examples

```bash
# Default: Scan ./package-lock.json with OSV
npx dependency-scanner

# Scan with GHSA instead of OSV
npx dependency-scanner --database-source ghsa

# Scan with GHSA using personal access token
npx dependency-scanner --database-source ghsa --github-token ghp_xxxx

# Scan a Python manifest
npx dependency-scanner /path/to/requirements.txt

# Scan a Yarn lockfile
npx dependency-scanner /path/to/yarn.lock
```

### Sample output

```
Scanning: /path/to/project/package-lock.json
Found 45 dependencies (5 direct)
Checking OSV.dev for known vulnerabilities...

──────────────────────────────────────────────────
Total Dependencies: 45  |  Vulnerable: 2 (4.4%)
──────────────────────────────────────────────────

⚠️ Vulnerable packages:

  lodash@4.17.20 (transitive)
    └─ 1 vuln(s): GHSA-jf85-cpcp-j695

  minimist@1.2.5 (direct)
    └─ 1 vuln(s): GHSA-xvch-5gv4-984h

Full report: /path/to/project/report.json
```

A detailed `report.json` file is generated with full vulnerability information for each dependency.

## Developing

```bash
npm install  # Install dependencies
npm run test # Run unit tests (see below)

npm run dev                   # Scan default package-lock.json
npm run dev -- /path/to/file  # Scan specific file
```

## Testing

Usage: `npm run test`

Unit tests currently cover filetype parsers and database clients using fixture files.

Test coverage could be expanded with additional unit tests for the CLI, report generation and graph traversal. Integration tests could make API client testing more robust by introducing live network calls.

### Test fixtures

Sample files for unit testing and general development reference:

```bash
tests/fixtures/
├── npm/        # Node.js lockfile & manifest samples
├── pypi/       # Python lockfile & manifest samples
├── osv/        # OSV.dev API response samples
├── ghsa/       # GHSA GraphQL response samples
└── malformed/  # Edge cases for error handling
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `DEBUG=1` | Show full stack traces on errors |
| `GITHUB_TOKEN` | GitHub personal access token for GHSA queries |

## License

[MIT](LICENSE)
