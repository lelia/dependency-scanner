/**
 * Basic report generator, limited to console output.
 * 
 * TODO:
 * - Add graph traversal to collect all nodes
 * - Include direct/transitive info in output
 * - Implement JSON file output formatting
 */

import { DependencyGraph } from "./types";
import { OsvVulnerability } from "./osv";

export interface ScanReport {
  summary: {
    totalDependencies: number;
    vulnerableDependencies: number;
  };
  findings: Array<{
    id: string;
    name: string;
    version: string;
    vulnerabilities: OsvVulnerability[];
  }>;
}

export function buildReport(
  graph: DependencyGraph,
  vulnMap: Map<string, OsvVulnerability[]>,
): ScanReport {
  const findings = [...graph.nodes.values()].map((node) => ({
    id: node.id,
    name: node.name,
    version: node.version,
    vulnerabilities: vulnMap.get(node.id) ?? [],
  }));

  const vulnerableDependencies = findings.filter(
    (f) => f.vulnerabilities.length > 0
  ).length;

  return {
    summary: {
      totalDependencies: findings.length,
      vulnerableDependencies,
    },
    findings,
  };
}

