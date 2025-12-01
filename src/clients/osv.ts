/**
 * Client for OSV.dev (Open Source Vulnerability) database.
 * 
 * Uses batch query REST API to send all packages in one request and get back matching vulns.
 * No auth required, aggregates from multiple sources (including GHSA) and matches versions server-side.
 *
 * Ref: https://google.github.io/osv.dev/post-v1-querybatch/
 */

import fetch from "node-fetch";
import { DependencyNode, PackageRegistry } from "../types";
import { Vulnerability } from "./types";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";

// Map package registry name to OSV ecosystem string.
function toOsvEcosystem(registry: PackageRegistry): string {
  switch (registry) {
    case "npm": return "npm";
    case "pypi": return "PyPI";
  }
}

interface OsvQuery {
  package: { ecosystem: string; name: string };
  version: string;
}

interface OsvResponse {
  results: Array<{ vulns?: Vulnerability[] }>;
}

/**
 * Check dependencies for vulnerabilities in OSV.dev database using query batching.
 * Deduplicates and maps results back to dependency node IDs.
 */
export async function checkOsvVulnerabilities(
  deps: DependencyNode[],
): Promise<Map<string, Vulnerability[]>> {
  const unique = new Map<string, { nodeId: string; query: OsvQuery }>();

  for (const dep of deps) {
    const ecosystem = toOsvEcosystem(dep.registry);
    const key = `${ecosystem}:${dep.name}@${dep.version}`;
    if (!unique.has(key)) {
      unique.set(key, {
        nodeId: dep.id,
        query: { package: { ecosystem, name: dep.name }, version: dep.version },
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
    const key = `${query.package.ecosystem}:${query.package.name}@${query.version}`;
    const info = unique.get(key);
    if (info) {
      results.set(info.nodeId, entry.vulns ?? []);
    }
  });

  return results;
}
