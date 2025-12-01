#!/usr/bin/env node
/**
 * CLI entrypoint for the dependency-scanner tool.
 *
 * Usage:
 *   npx . [options] [file]
 *
 * Options:
 *   --database-source <osv|ghsa>  Vulnerability database (default: osv)
 *   --github-token <token>        GitHub token (required for GHSA GraphQL API)
 *   --help                        Show help message
 *
 * Examples:
 *   npx .                           # Scan ./package-lock.json with OSV
 *   npx . --database-source ghsa    # Scan with GitHub Security Advisories
 *   npx . /path/to/requirements.txt
 *
 * For development: use `npm run dev` (no build needed).
 */

import fs from "node:fs";
import path from "node:path";
import { parse } from "./parsers";
import { getAllDependencies } from "./traverse";
import { checkOsvVulnerabilities } from "./clients/osv";
import { checkGhsaVulnerabilities } from "./clients/ghsa";
import { generateReport, Report } from "./report";
import { Vulnerability } from "./clients/types";
import { DependencyNode, DatabaseSource } from "./types";

interface CliOptions {
  filePath: string;
  source: DatabaseSource;
  githubToken?: string;
}

function printHelp() {
  console.log(`
Usage: npx . [options] [file]

Options:
  --database-source <osv|ghsa>  Vulnerability database (default: osv)
  --github-token <token>        GitHub token for GHSA (or set GITHUB_TOKEN)
  --help                        Show this help message

Examples:
  npx .                           Scan ./package-lock.json with OSV
  npx . --database-source ghsa    Scan with GitHub Security Advisories
  npx . /path/to/yarn.lock        Scan specific file
`);
  process.exit(0);
}

function parseArgs(): CliOptions {
  const args = process.argv.slice(2);
  let filePath = path.join(process.cwd(), "package-lock.json");
  let source: DatabaseSource = "osv";
  let githubToken: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === "--help" || arg === "-h") {
      printHelp();
    } else if (arg === "--database-source") {
      const value = args[++i];
      if (value !== "osv" && value !== "ghsa") {
        console.error(`Invalid --database-source value: ${value}. Must be 'osv' or 'ghsa'.`);
        process.exit(1);
      }
      source = value;
    } else if (arg === "--github-token") {
      githubToken = args[++i];
    } else if (!arg.startsWith("-")) {
      filePath = arg;
    }
  }

  return { filePath, source, githubToken };
}

async function checkVulnerabilities(
  deps: DependencyNode[],
  source: DatabaseSource,
  githubToken?: string,
): Promise<Map<string, Vulnerability[]>> {
  switch (source) {
    case "osv":
      return checkOsvVulnerabilities(deps);
    case "ghsa":
      return checkGhsaVulnerabilities(deps, githubToken);
  }
}

async function main() {
  const startTime = Date.now();
  const { filePath, source, githubToken } = parseArgs();

  console.log(`Scanning: ${filePath}`);

  const graph = parse(filePath);
  const deps = getAllDependencies(graph);
  const transitive = deps.length - graph.roots.length;
  console.log(`📦 Found ${deps.length} dependencies (${graph.roots.length} direct, ${transitive} transitive)`);

  const sourceLabel = source === "osv" ? "OSV.dev" : "GitHub Security Advisories";
  console.log(`\n🔍 Checking ${sourceLabel} for known vulnerabilities...`);
  const vulns = await checkVulnerabilities(deps, source, githubToken);

  const durationMs = Date.now() - startTime;
  const report = generateReport(graph, vulns, {
    scannedFile: filePath,
    sources: [source],
    timestamp: new Date().toISOString(),
    durationMs,
  });
  printSummary(report);

  const outputPath = path.join(process.cwd(), "report.json");
  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));

  const elapsed = (durationMs / 1000).toFixed(2);
  console.log(`\nFull report: ${outputPath}`);
  console.log(`⏱️  Completed in ${elapsed} seconds`);

  // Exit with code 1 if vulnerabilities are found
  if (report.summary.vulnerableDependencies > 0) {
    process.exit(1);
  }
}

/**
 * Print summary of the report to the console.
 */
function printSummary(report: Report) {
  const { summary, findings } = report;
  const percent = summary.totalDependencies > 0
    ? ((summary.vulnerableDependencies / summary.totalDependencies) * 100).toFixed(1)
    : "0.0";

  console.log("\n" + "─".repeat(50));
  console.log(`Total Dependencies: ${summary.totalDependencies}  |  Vulnerable: ${summary.vulnerableDependencies} (${percent}%)`);
  console.log("─".repeat(50));

  const vulnerable = findings.filter((f) => f.vulnerabilities.length > 0);

  if (vulnerable.length === 0) {
    console.log("\n✅ No known vulnerabilities found 🎉");
    return;
  }

  console.log("\n⚠️ Vulnerable packages:\n");
  for (const finding of vulnerable) {
    const vulnIds = finding.vulnerabilities.map((v) => v.id).join(", ");
    console.log(`  ${finding.name}@${finding.version} (${finding.dependencyType})`);
    console.log(`    └─ ${finding.vulnerabilities.length} vuln(s): ${vulnIds}`);
  }
}

main().catch((err) => {
  console.error("\n🚨 Scan failed:", err.message);
  if (process.env.DEBUG) console.error(err.stack);
  process.exit(1);
});
