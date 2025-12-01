/**
 * Support for .scanignore files to suppress specific advisories.
 *
 * Format: One vulnerability ID per line (GHSA-xxxx, CVE-xxxx, PYSEC-xxxx, etc.)
 * 
 * Lines starting with # are considered comments and will be ignored.
 * Blank lines or any text following # on the same line will be ignored.
 *
 * Example .scanignore:
 *   PYSEC-2022-9
 *   # Not relevant to this project
 *   GHSA-1234-5678-abcd
 *   CVE-2024-12345 # False positive
 */

import fs from "node:fs";
import path from "node:path";

const IGNORE_FILENAME = ".scanignore";

/**
 * Load suppressed vulnerability IDs from .scanignore file.
 * Priority: explicit path (--ignore-file) > scanned file dir > cwd
 */
export function loadIgnoreList(scannedFilePath: string, explicitPath?: string): Set<string> {
  const ignored = new Set<string>();

  // Priority 1: Explicit path from CLI
  if (explicitPath) {
    if (!fs.existsSync(explicitPath)) {
      console.error(`❌ Ignore file not found: ${explicitPath}`);
      process.exit(1);
    }
    return parseIgnoreFile(explicitPath, ignored);
  }

  // Priority 2: Directory of scanned file
  const scannedDir = path.dirname(scannedFilePath);
  const ignoreInDir = path.join(scannedDir, IGNORE_FILENAME);

  // Priority 3: Current working directory
  const ignoreInCwd = path.join(process.cwd(), IGNORE_FILENAME);

  const ignorePath = fs.existsSync(ignoreInDir)
    ? ignoreInDir
    : fs.existsSync(ignoreInCwd)
      ? ignoreInCwd
      : null;

  if (!ignorePath) {
    return ignored;
  }

  return parseIgnoreFile(ignorePath, ignored);
}

function parseIgnoreFile(ignorePath: string, ignored: Set<string>): Set<string> {
  const content = fs.readFileSync(ignorePath, "utf-8");

  for (const line of content.split("\n")) {
    const withoutComment = line.split("#")[0].trim();

    if (!withoutComment) continue;

    ignored.add(withoutComment);
  }

  if (ignored.size > 0) {
    console.log(`📋 Loaded ${ignored.size} ignored advisory ID(s) from ${path.basename(ignorePath)}`);
  }

  return ignored;
}

/**
 * Filter vulnerabilities, removing any with IDs in the ignore list.
 * Also checks aliases (CVE IDs) for matches.
 */
export function filterIgnored(
  vulns: Map<string, import("./clients/types").Vulnerability[]>,
  ignored: Set<string>,
): { filtered: Map<string, import("./clients/types").Vulnerability[]>; ignoredCount: number } {
  if (ignored.size === 0) {
    return { filtered: vulns, ignoredCount: 0 };
  }

  let ignoredCount = 0;
  const filtered = new Map<string, import("./clients/types").Vulnerability[]>();

  for (const [depId, depVulns] of vulns) {
    const kept = depVulns.filter((v) => {
      // Check if the primary ID is ignored
      if (ignored.has(v.id)) {
        ignoredCount++;
        return false;
      }

      // Check if any alias (CVE ID) is ignored
      if (v.aliases?.some((alias) => ignored.has(alias))) {
        ignoredCount++;
        return false;
      }

      return true;
    });

    filtered.set(depId, kept);
  }

  return { filtered, ignoredCount };
}

