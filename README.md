# 🔍 dependency-scanner

A CLI tool to scan dependency manifests and lockfiles for known vulnerabilities.

## Tool overview

- Parses dependency file (lockfile preferred, manifest as fallback)
- Builds a dependency graph (direct and transitive where available)
- Queries [OSV.dev](https://osv.dev) for known vulnerabilities ([GHSA](https://github.com/advisories) support TBA)
- Prints the summary to console and generates a `report.json` file

## Supported files

| Ecosystem | Filename | Notes |
|-----------|------|-------|
| **NPM** | `package-lock.json` | v2/v3 format (NPM v7+) |
| **NPM** | `package.json` | Direct deps only, no transitives |
| **NPM** | `yarn.lock` | v1 (classic) and v2+ (Berry) |
| **PyPI** | `requirements.txt` | Pinned versions only |
| **PyPI** | `poetry.lock` | Full dependency tree |
| **PyPI** | `Pipfile.lock` | Full dependency tree |

### Known limitations

- `package-lock.json` v1 format is not supported (npm v6 and earlier)
- `package.json` and `requirements.txt` can only show direct dependencies
- `requirements.txt` with unpinned deps (e.g., `requests>=2.0`) uses range as-is, may not match exact vulnerability ranges

## Getting started

### Prerequisites

- [Node.js](https://nodejs.org) v18+ (tested with [v24.9.0](https://nodejs.org/en/blog/release/v24.9.0))

### Usage

```bash
npm install # Install project dependencies

npm run build # Build dependency-scanner tool

npx dependency-scanner # Scan default package-lock.json file
npx dependency-scanner /path/to/package-lock.json # Scan specific package-lock.json file
npx dependency-scanner /path/to/requirements.txt # Scan specific requirements.txt file
```

### Developing

```bash
npm install # Install project dependencies

npm run dev # Scan default package-lock.json file
npm run dev -- /path/to/file # Scan specific package manifest file

npm run test # Run unit tests using Node test runner
```

## License

[MIT](LICENSE)
