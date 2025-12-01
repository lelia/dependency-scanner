/**
 * Generate report to summarize dependency and vulnerability findings.
 */

import { DependencyGraph, DependencyType, DatabaseSource } from "./types";
import { Vulnerability } from "./clients/types";
import { getAllDependencies } from "./traverse";

export interface ReportMetadata {
  scannedFile: string;
  sources: DatabaseSource[];
  timestamp: string;
  durationMs: number;
}

export interface Finding {
  id: string;
  name: string;
  version: string;
  dependencyType: DependencyType;
  vulnerabilities: Vulnerability[];
}

export interface Report {
  metadata: ReportMetadata;
  summary: {
    totalDependencies: number;
    directDependencies: number;
    transitiveDependencies: number;
    vulnerableDependencies: number;
    vulnerablePercentage: number;
  };
  findings: Finding[];
}

export function generateReport(
  graph: DependencyGraph,
  vulns: Map<string, Vulnerability[]>,
  metadata: ReportMetadata,
): Report {
  const deps = getAllDependencies(graph);

  const findings: Finding[] = deps.map((dep) => ({
    id: dep.id,
    name: dep.name,
    version: dep.version,
    dependencyType: dep.dependencyType,
    vulnerabilities: vulns.get(dep.id) ?? [],
  }));

  const vulnerableDependencies = findings.filter((f) => f.vulnerabilities.length > 0).length;
  const directDependencies = graph.roots.length;
  const transitiveDependencies = findings.length - directDependencies;
  const vulnerablePercentage = findings.length > 0
    ? Math.round((vulnerableDependencies / findings.length) * 1000) / 10
    : 0;

  return {
    metadata,
    summary: {
      totalDependencies: findings.length,
      directDependencies,
      transitiveDependencies,
      vulnerableDependencies,
      vulnerablePercentage,
    },
    findings,
  };
}
