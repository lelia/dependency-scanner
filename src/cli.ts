#!/usr/bin/env node
/**
 * CLI entrypoint for the dependency-scanner tool.
 *
 * Basic flow:
 * 1. Parse lockfile
 * 2. Query OSV API
 * 3. Build report
 * 4. Generate output
 *
 * TODO:
 * - Add proper graph traversal
 * - Improve console output formatting
 * - Add JSON file output to report
 */

import { parseLockfile } from "./lockfile";
import { queryOsv } from "./osv";
import { buildReport } from "./report";

async function main() {
  const lockfilePath = process.argv[2] ?? "./package-lock.json";

  console.log(`Scanning: ${lockfilePath}`);

  const graph = parseLockfile(lockfilePath);
  console.log(`Found ${graph.nodes.size} packages`);

  const vulnMap = await queryOsv([...graph.nodes.values()]);
  const report = buildReport(graph, vulnMap);

  console.log(`\nTotal: ${report.summary.totalDependencies}`);
  console.log(`Vulnerable: ${report.summary.vulnerableDependencies}`);
}

main().catch((err) => {
  console.error("Failed:", err.message);
  process.exit(1);
});
