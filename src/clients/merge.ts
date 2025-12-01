/**
 * Merge vulnerability results from multiple database sources.
 * 
 * Merge strategy:
 * - Dedupe by vulnerability ID
 * - Severity: take highest (conservative approach)
 * - References: union (combine, dedupe by URL)
 * - Summary: prefer longer description
 * - fixedIn: prefer explicit version
 */

import { Vulnerability } from "./types";

/**
 * Merge two vulnerability arrays, deduping by ID.
 */
export function mergeVulnerabilities(
  a: Vulnerability[],
  b: Vulnerability[],
): Vulnerability[] {
  const merged = new Map<string, Vulnerability>();

  // Add everything from first source
  for (const vuln of a) {
    merged.set(vuln.id, vuln);
  }

  // Merge in the second source
  for (const vuln of b) {
    const existing = merged.get(vuln.id);
    if (existing) {
      merged.set(vuln.id, mergeVuln(existing, vuln));
    } else {
      merged.set(vuln.id, vuln);
    }
  }

  return [...merged.values()];
}

/**
 * Merge two vulnerability objects with the same ID.
 */
function mergeVuln(a: Vulnerability, b: Vulnerability): Vulnerability {
  return {
    id: a.id,
    summary: pickLonger(a.summary, b.summary),
    severity: pickHigherSeverity(a.severity, b.severity),
    references: mergeRefs(a.references, b.references),
    fixedIn: a.fixedIn || b.fixedIn,
  };
}

function pickLonger(a?: string, b?: string): string | undefined {
  if (!a) return b;
  if (!b) return a;
  return a.length >= b.length ? a : b;
}

function pickHigherSeverity(
  a?: Array<{ type: string; score: string }>,
  b?: Array<{ type: string; score: string }>,
): Array<{ type: string; score: string }> | undefined {
  if (!a?.length) return b;
  if (!b?.length) return a;
  
  // Severity heuristic: CRITICAL > HIGH > MODERATE > LOW
  const rank = (sev: Array<{ type: string; score: string }>) => {
    const score = sev[0]?.score?.toUpperCase() || "";
    if (score.includes("CRITICAL")) return 4;
    if (score.includes("HIGH")) return 3;
    if (score.includes("MODERATE") || score.includes("MEDIUM")) return 2;
    if (score.includes("LOW")) return 1;
    return 0;
  };
  
  return rank(a) >= rank(b) ? a : b;
}

function mergeRefs(
  a?: Array<{ type: string; url: string }>,
  b?: Array<{ type: string; url: string }>,
): Array<{ type: string; url: string }> | undefined {
  if (!a?.length) return b;
  if (!b?.length) return a;
  
  const seen = new Set<string>();
  const merged: Array<{ type: string; url: string }> = [];
  
  for (const ref of [...a, ...b]) {
    if (!seen.has(ref.url)) {
      seen.add(ref.url);
      merged.push(ref);
    }
  }
  
  return merged;
}

/**
 * Merge vulnerability maps from multiple sources.
 */
export function mergeVulnMaps(
  maps: Map<string, Vulnerability[]>[],
): Map<string, Vulnerability[]> {
  const result = new Map<string, Vulnerability[]>();

  for (const map of maps) {
    for (const [depId, vulns] of map) {
      const existing = result.get(depId) || [];
      result.set(depId, mergeVulnerabilities(existing, vulns));
    }
  }

  return result;
}

