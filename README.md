# dependency-scanner

A tool to scan dependency manifest files and report known vulnerabilities.

## Overview

1. Parses `package-lock.json` (`npm` v7+ format)
1. Builds a dependency graph (direct + transitive)
1. Queries [OSV](https://osv.dev) API for known vulnerabilities
1. Outputs summary to console + `report.json` file

## Limitations

- Only supports `package-lock.json` (v2/v3 format)
- Only queries [OSV](https://osv.dev) (GHSA support TBA)
- No ability to suppress/ignore specific advisories

## Requirements

- [Node.js](https://nodejs.org) v18+ (tested on Node v24.9.0)

## Setup

```bash
npm install # Install dependencies
npm run build # Build the project

npx dependency-scanner # Scan ./package-lock by default
npx dependency-scanner /path/to/lockfile # Scan specific lockfile
```

## Developing

```bash
npm install # Install dependencies

npm run dev # Scan ./package-lock.json by default
npm run dev -- /path/to/lockfile # Scan specific lockfile
```

## Testing

TBD

## License

[MIT](LICENSE)
