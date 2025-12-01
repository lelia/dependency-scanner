#!/usr/bin/env node
/**
 * CLI entrypoint for the dependency-scanner tool.
 *
 * Usage:
 *   npx . [options] [file]
 *
 * Options:
 *   --database-source <osv|ghsa>  Query single DB (default: both)
 *   --github-token <token>        GitHub token (required for GHSA)
 *   --help                        Show help message
 *
 * Ignore file:
 *   Create a .scanignore file with vulnerability IDs (one per line) to suppress.
 *
 * For development: use `npm run dev` (no build needed).
 */

import fs from "node:fs";
import path from "node:path";
import { parse } from "./parsers";
import { getAllDependencies } from "./traverse";
import { checkOsvVulnerabilities } from "./clients/osv";
import { checkGhsaVulnerabilities } from "./clients/ghsa";
import { mergeVulnMaps } from "./clients/merge";
import { loadIgnoreList, filterIgnored } from "./ignore";
import { generateReport, Report } from "./report";
import { Vulnerability } from "./clients/types";
import { DependencyNode, DatabaseSource } from "./types";

interface CliOptions {
  filePath: string;
  source?: DatabaseSource;
  githubToken?: string;
  ignoreFile?: string;
}

function printHelp() {
  console.log(`
Usage: npx . [options] [file]

Options:
  --database-source <osv|ghsa>  Query single DB only (default: both)
  --github-token <token>        GitHub token for GHSA (or set GITHUB_TOKEN)
  --ignore-file <path>          Path to ignore file (default: .scanignore)
  --help                        Show this help message

Examples:
  npx .                           Scan with both OSV + GHSA (merged)
  npx . --database-source osv     OSV only
  npx . --database-source ghsa    GHSA only (requires token)
  npx . /path/to/yarn.lock        Scan specific file
  npx . --ignore-file .ci-ignore  Use custom ignore file
`);
  process.exit(0);
}

function parseArgs(): CliOptions {
  const args = process.argv.slice(2);
  let filePath = path.join(process.cwd(), "package-lock.json");
  let source: DatabaseSource | undefined;
  let githubToken: string | undefined;
  let ignoreFile: string | undefined;

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
    } else if (arg === "--ignore-file") {
      ignoreFile = args[++i];
    } else if (!arg.startsWith("-")) {
      filePath = arg;
    }
  }

  return { filePath, source, githubToken, ignoreFile };
}

async function checkVulnerabilities(
  deps: DependencyNode[],
  source: DatabaseSource | undefined,
  githubToken?: string,
): Promise<{ vulns: Map<string, Vulnerability[]>; sources: DatabaseSource[] }> {
  // Single source: OSV (no auth needed)
  if (source === "osv") {
    return { vulns: await checkOsvVulnerabilities(deps), sources: ["osv"] };
  }

  // Single source: GHSA (requires token)
  if (source === "ghsa") {
    return { vulns: await checkGhsaVulnerabilities(deps, githubToken), sources: ["ghsa"] };
  }

  // Default: both sources (fall back to OSV if no token provided)
  const authToken = githubToken || process.env.GITHUB_TOKEN;

  if (!authToken) {
    return { vulns: await checkOsvVulnerabilities(deps), sources: ["osv"] };
  }

  // Query both in parallel, then merge
  const [osvResults, ghsaResults] = await Promise.all([
    checkOsvVulnerabilities(deps),
    checkGhsaVulnerabilities(deps, githubToken),
  ]);

  return {
    vulns: mergeVulnMaps([osvResults, ghsaResults]),
    sources: ["osv", "ghsa"],
  };
}

async function main() {
  const startTime = Date.now();
  const { filePath, source, githubToken, ignoreFile } = parseArgs();

  console.log(`Scanning: ${filePath}`);

  const graph = parse(filePath);
  const deps = getAllDependencies(graph);
  const transitive = deps.length - graph.roots.length;
  console.log(`📦 Found ${deps.length} dependencies (${graph.roots.length} direct, ${transitive} transitive)`);

  // Determine which sources to query
  const authToken = githubToken || process.env.GITHUB_TOKEN;
  const willQueryBoth = !source && authToken;
  const sourceLabel = source
    ? (source === "osv" ? "OSV.dev" : "GitHub Security Advisories")
    : (willQueryBoth ? "OSV.dev 🤝 GitHub Security Advisories" : "OSV.dev");

  console.log(`\n🔍 Checking ${sourceLabel} for known vulnerabilities...`);

  const { vulns, sources } = await checkVulnerabilities(deps, source, githubToken);

  // Apply ignore list (from .scanignore or --ignore-file)
  const ignoreList = loadIgnoreList(filePath, ignoreFile);
  const { filtered: filteredVulns, ignoredCount } = filterIgnored(vulns, ignoreList);

  const durationMs = Date.now() - startTime;
  const report = generateReport(graph, filteredVulns, {
    scannedFile: filePath,
    sources,
    timestamp: new Date().toISOString(),
    durationMs,
    ignoredCount,
  });
  printSummary(report, ignoredCount);

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
function printSummary(report: Report, ignoredCount: number) {
  const { summary, findings } = report;
  const percent = summary.totalDependencies > 0
    ? ((summary.vulnerableDependencies / summary.totalDependencies) * 100).toFixed(1)
    : "0.0";

  const lineWidth = ignoredCount > 0 ? 80 : 50;
  console.log("\n" + "─".repeat(lineWidth));
  let summaryLine = `Total Dependencies: ${summary.totalDependencies}  |  Vulnerable: ${summary.vulnerableDependencies} (${percent}%)`;
  if (ignoredCount > 0) {
    summaryLine += `  |  Vulnerabilities Ignored: ${ignoredCount}`;
  }
  console.log(summaryLine);
  console.log("─".repeat(lineWidth));

  const vulnerable = findings.filter((f) => f.vulnerabilities.length > 0);

  if (vulnerable.length === 0) {
    console.log("\n✅ No known vulnerabilities found 🎉");
    return;
  }

  console.log("\n⚠️ Vulnerable packages:\n");
  for (const finding of vulnerable) {
    const vulnIds = finding.vulnerabilities.map((v) => {
      // Show CVE alias in parentheses if available
      const cve = v.aliases?.find((a) => a.startsWith("CVE-"));
      return cve ? `${v.id} (${cve})` : v.id;
    }).join(", ");
    console.log(`  ${finding.name}@${finding.version} (${finding.dependencyType})`);
    console.log(`    └─ ${finding.vulnerabilities.length} vuln(s): ${vulnIds}`);
  }
}

main().catch((err) => {
  console.error("\n🚨 Scan failed:", err.message);
  if (process.env.DEBUG) console.error(err.stack);
  process.exit(1);
});
