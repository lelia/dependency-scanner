#!/usr/bin/env node
/**
 * CLI entrypoint for the dependency-scanner tool.
 *
 * Usage: npx dependency-scanner <lockfile-path>
 * Default: package-lock.json in the current working directory
 */

import fs from "node:fs";
import path from "node:path";
import { parseLockfile } from "./lockfile";
import { getAllDependencies } from "./traverse";
import { checkVulnerabilities } from "./osv";
import { generateReport, Report } from "./report";

async function main() {
  const lockfilePath = process.argv[2] ?? path.join(process.cwd(), "package-lock.json");

  console.log(`Scanning: ${lockfilePath}`);

  const graph = parseLockfile(lockfilePath);
  const deps = getAllDependencies(graph);
  console.log(`Found ${deps.length} dependencies (${graph.roots.length} direct)`);

  console.log("Checking for known vulnerabilities...");
  const vulns = await checkVulnerabilities(deps);

  const report = generateReport(graph, vulns);
  printSummary(report);

  const outputPath = path.join(process.cwd(), "report.json");
  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
  console.log(`\nFull report: ${outputPath}`);
}

/**
 * Print summary of the report to the console.
 */
function printSummary(report: Report) {
  const { summary, findings } = report;
  // Calculate % of vulnerable packages in manifest
  const percent = summary.totalDependencies > 0
    ? ((summary.vulnerableDependencies / summary.totalDependencies) * 100).toFixed(1)
    : "0.0";

  console.log("\n" + "─".repeat(50));
  console.log(`Dependencies: ${summary.totalDependencies}  |  Vulnerable: ${summary.vulnerableDependencies} (${percent}%)`);
  console.log("─".repeat(50));

  const vulnerable = findings.filter((f) => f.vulnerabilities.length > 0);

  if (vulnerable.length === 0) {
    console.log("\n✓ No known vulnerabilities found");
    return;
  }

  console.log("\nVulnerable packages:\n");
  for (const finding of vulnerable) {
    const vulnIds = finding.vulnerabilities.map((v) => v.id).join(", ");
    console.log(`  ${finding.name}@${finding.version} (${finding.dependencyType})`);
    console.log(`    └─ ${finding.vulnerabilities.length} vuln(s): ${vulnIds}`);
  }
}

main().catch((err) => {
  console.error("\n✗ Scan failed:", err.message);
  if (process.env.DEBUG) console.error(err.stack);
  process.exit(1);
});
