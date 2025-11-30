/**
 * API Client for OSV (Open Source Vulnerability) database.
 * 
 * Refs:
 * - https://google.github.io/osv.dev/api/
 * - https://google.github.io/osv.dev/post-v1-querybatch/
 * 
 * TODO:
 * - Add deduplication before querying
 * - Handle batch size limits (1000 max)
 * - Better error handling
 */

import { DependencyNode } from "./types";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";

export interface OsvVulnerability {
  id: string;
  summary?: string;
}

export async function queryOsv(
  nodes: DependencyNode[],
): Promise<Map<string, OsvVulnerability[]>> {
  // Build queries for each package
  const queries = nodes.map((node) => ({
    package: { ecosystem: "npm", name: node.name },
    version: node.version,
  }));

  const response = await fetch(OSV_BATCH_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ queries }),
  });

  if (!response.ok) {
    throw new Error(`OSV error: ${response.status}`);
  }

  const data = await response.json();

  // Map results back to node IDs
  const results = new Map<string, OsvVulnerability[]>();
  data.results.forEach((entry: { vulns?: OsvVulnerability[] }, i: number) => {
    results.set(nodes[i].id, entry.vulns ?? []);
  });

  return results;
}

