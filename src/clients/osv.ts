/**
 * API Client for OSV (Open Source Vulnerability) database.
 * 
 * Ref: https://google.github.io/osv.dev/post-v1-querybatch/
 */

import fetch from "node-fetch";
import { DependencyNode } from "./types";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";

export interface Vulnerability {
  id: string;
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  references?: Array<{ type: string; url: string }>;
}

interface OsvQuery {
  package: { ecosystem: string; name: string };
  version: string;
}

interface OsvResponse {
  results: Array<{ vulns?: Vulnerability[] }>;
}

/**
 * Check given deps for known vulnerabilities.
 * Dedupes and maps results back to node IDs.
 */
export async function checkVulnerabilities(
  deps: DependencyNode[],
): Promise<Map<string, Vulnerability[]>> {
  const unique = new Map<string, { nodeId: string; query: OsvQuery }>();

  for (const dep of deps) {
    const key = `npm:${dep.name}@${dep.version}`;
    if (!unique.has(key)) {
      unique.set(key, {
        nodeId: dep.id,
        query: { package: { ecosystem: "npm", name: dep.name }, version: dep.version },
      });
    }
  }

  const queries = [...unique.values()].map((u) => u.query);

  const response = await fetch(OSV_BATCH_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ queries }),
  });

  if (!response.ok) {
    throw new Error(`Vulnerability check failed: ${response.status} ${response.statusText}`);
  }

  const data = (await response.json()) as OsvResponse;

  const results = new Map<string, Vulnerability[]>();
  data.results.forEach((entry, i) => {
    const query = queries[i];
    const key = `npm:${query.package.name}@${query.version}`;
    const info = unique.get(key);
    if (info) {
      results.set(info.nodeId, entry.vulns ?? []);
    }
  });

  return results;
}
