# dependency-scanner

A tool to scan dependency manifest files and report known vulnerabilities.

## Current limitations

- Only supports `package-lock.json` (v2/v3 format)
- Only queries [OSV](https://osv.dev) (GHSA support TBA)
- Outputs results to console (JSON file format TBA)
