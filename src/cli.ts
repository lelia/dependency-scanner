#!/usr/bin/env node
/**
 * CLI entrypoint for the dependency-scanner tool.
 *
 * Usage:
 *   npx dependency-scanner [options] [file]
 *
 * Options:
 *   --database-source <osv|ghsa>  Vulnerability database to query (default: OSV.dev)
 *   --github-token <pat>          GitHub token for GHSA queries (or set GITHUB_TOKEN env var)
 *
 * Examples:
 *   npx dependency-scanner                                  # Scan ./package-lock.json with OSV
 *   npx dependency-scanner --database-source ghsa           # Scan with GitHub Security Advisories
 *   npx dependency-scanner /path/to/requirements.txt        # Scan specific file
 */

import fs from "node:fs";
import path from "node:path";
import { parse } from "./parsers";
import { getAllDependencies } from "./traverse";
import { checkOsvVulnerabilities } from "./clients/osv";
import { checkGhsaVulnerabilities } from "./clients/ghsa";
import { generateReport, Report } from "./report";
import { Vulnerability } from "./clients/types";
import { DependencyNode } from "./types";

type VulnSource = "osv" | "ghsa";

interface CliOptions {
  filePath: string;
  source: VulnSource;
  githubToken?: string;
}

function parseArgs(): CliOptions {
  const args = process.argv.slice(2);
  let filePath = path.join(process.cwd(), "package-lock.json");
  let source: VulnSource = "osv";
  let githubToken: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === "--database-source") {
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
  source: VulnSource,
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
  const { filePath, source, githubToken } = parseArgs();

  console.log(`Scanning: ${filePath}`);

  const graph = parse(filePath);
  const deps = getAllDependencies(graph);
  console.log(`Found ${deps.length} dependencies (${graph.roots.length} direct)`);

  const sourceLabel = source === "osv" ? "OSV.dev" : "GitHub Security Advisories";
  console.log(`Checking ${sourceLabel} for known vulnerabilities...`);
  const vulns = await checkVulnerabilities(deps, source, githubToken);

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
