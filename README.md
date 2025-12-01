# 🔍 dependency-scanner

A CLI tool to scan dependency manifests and lockfiles for known vulnerabilities.

## Tool overview

- Parses dependency file (lockfile preferred, manifest as fallback)
- Builds a dependency graph (direct and transitive where available)
- Queries vulnerability databases (both by default, or single via `--database-source`):
  - [Open Source Vulnerabilities](https://osv.dev/list) (OSV.dev)
  - [GitHub Security Advisories](https://github.com/advisories) (GHSA)
- Merges and deduplicates results when querying both databases
- Prints the summary of findings to console and generates a `report.json` file

### Supported filetypes

| Ecosystem | Filename | Type | Notes |
|-----------|----------|------|-------|
| **Node.js** | `package-lock.json` | Lockfile | v1, v2, and v3 formats |
| **Node.js** | `yarn.lock` | Lockfile | v1 (classic) and v2+ (Berry) |
| **Node.js** | `package.json` | Manifest | Direct dependencies only |
| **Python** | `poetry.lock` | Lockfile | Full dependency tree |
| **Python** | `Pipfile.lock` | Lockfile | Full dependency tree |
| **Python** | `requirements.txt` | Manifest | Direct dependencies only |

### Merge strategy

When querying both vulnerability databases, results are merged using the following strategy:

| Field | Strategy |
|-------|----------|
| Severity | Highest (most conservative) |
| Summary | Longer description preferred |
| References | Union (combine both, dedupe by URL) |
| Fix version | Prefer explicit over missing |

### Known limitations

#### Filetype differences

- Lockfiles (`package-lock.json`, `yarn.lock`, `poetry.lock`, `Pipfile.lock`) contain the full resolved dependency tree, including transitive dependencies
- Manifest files (`package.json`, `requirements.txt`) only list direct dependencies, as there's no way to discover transitive deps without a package manager
  - `requirements.txt` files containing version ranges (eg., `requests>=2.0`) may not match exact vulnerability ranges

> 💡 When scanning a manifest file, **only direct dependencies are checked and a warning is printed to the console**. Future versions may auto-detect the appropriate lockfile in the target project, or optionally invoke package managers for full resolution.

## Getting started

### Prerequisites

[Node.js](https://node.jsorg) v18+ is required. The tool was tested and developed with [v24.9.0](https://nodejs.org/en/blog/release/v24.9.0).

```bash
npm install   # Install dependencies
npm run build # Build the tool
npx .         # Run the CLI (see options below)
```

#### GitHub Token

A GitHub [personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) (PAT) is required to query GHSA using GraphQL. When running in default mode, the tool will fall back to only querying OSV if no token is provided. However, when using the `--database-source ghsa` CLI flag, the token is required and will error without one.

> 💡 Create a fine-grained PAT [here](https://github.com/settings/personal-access-tokens/new). No special scopes are needed for public advisory data.

```bash
# Option 1: Environment variable
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx

# Option 2: CLI flag
npx . --github-token ghp_xxxxxxxxxxxx
```

### CLI config

| Option | Default | Description |
|--------|---------|-------------|
| `[file]` | `./package-lock.json` | Path to lockfile or manifest to scan |
| `--database-source` | both | Query single DB only: `osv` or `ghsa` |
| `--github-token` | `$GITHUB_TOKEN` | GitHub PAT for GHSA queries |
| `--ignore-file` | `.scanignore` | Path to custom ignore file |

### Ignoring vulnerabilities

Create a `.scanignore` file to suppress specific advisories by ID:

```bash
# .scanignore - one ID per line
# Comments start with #

GHSA-jf85-cpcp-j695   # Known issue, mitigated
CVE-2021-23337        # False positive for our use case
```

**Lookup order:** `--ignore-file` flag → scanned file's directory → current working directory.

```bash
# Use default .scanignore
npx .

# Specify custom ignore file
npx . --ignore-file /path/to/.ci-ignore
```

> 💡 In the CLI output, "Ignored" counts individual vulnerability instances, while "Vulnerable" counts packages with at least one remaining vulnerability. A package only drops from the vulnerable count when *all* of its vulnerabilities are ignored.

### CLI examples

```bash
npx .                                       # Scan with both OSV + GHSA
npx . --database-source osv                 # OSV only
npx . --database-source ghsa                # GHSA only (requires token)
npx . /path/to/requirements.txt             # Scan a Python manifest
npx . --help                                # Show help
```

### Sample output

```
Scanning: /path/to/project/package-lock.json
📦 Found 45 dependencies (5 direct, 40 transitive)

🔍 Checking OSV.dev 🤝 GitHub Security Advisories for known vulnerabilities...
📋 Loaded 4 ignored advisory ID(s) from .scanignore

────────────────────────────────────────────────────────────────────────────────
Total Dependencies: 55  |  Vulnerable: 11 (20.0%)  |  Vulnerabilities Ignored: 4
────────────────────────────────────────────────────────────────────────────────

⚠️  Vulnerable packages:

  minimist@1.2.5 (direct)
    └─ 1 vuln(s): GHSA-xvch-5gv4-984h (CVE-2021-44906)

Full report: /path/to/project/report.json

⏱️  Completed in 0.58s
```

> 💡 For CI purposes, the tool exits 1 if vulnerabilities are found, otherwise exits 0.

A detailed `report.json` file is generated with full vulnerability information for each dependency.

## Developing

```bash
npm run dev   # Run CLI via ts-node (no build needed)
npm run build # Compile TypeScript
npm run test  # Run unit tests
npm run clean # Deletes dist/ (for fresh build)
```

### Testing

```bash
npm run test # Run unit tests
npm test     # Shorthand method
```

Unit tests currently cover filetype parsers and database clients using fixture files.

> 💡 Test coverage could be expanded with additional unit tests for the CLI and graph traversal. Integration tests could make API client testing more robust by introducing live network calls.

#### Test fixtures

Sample files for unit testing and general development reference:

```bash
tests/fixtures/
├── npm/         # Node.js lockfile & manifest samples
├── pypi/        # Python lockfile & manifest samples
├── osv/         # OSV.dev API response samples
├── ghsa/        # GHSA GraphQL response samples
├── reports/     # Sample report.json outputs
├── scanignore/  # Sample .scanignore files
└── malformed/   # Edge cases for error handling
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `DEBUG=1` | Show full stack traces on errors |
| `GITHUB_TOKEN` | GitHub personal access token for GHSA queries |

## License

[MIT](LICENSE)
