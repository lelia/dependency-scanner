/**
 * Generate report to summarize dependency and vulnerability findings.
 */

import { DependencyGraph, DependencyType } from "./types";
import { Vulnerability } from "./osv";
import { getAllDependencies } from "./traverse";

export interface Finding {
  id: string;
  name: string;
  version: string;
  dependencyType: DependencyType;
  vulnerabilities: Vulnerability[];
}

export interface Report {
  summary: {
    totalDependencies: number;
    vulnerableDependencies: number;
  };
  findings: Finding[];
}

export function generateReport(
  graph: DependencyGraph,
  vulns: Map<string, Vulnerability[]>,
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

  return {
    summary: { totalDependencies: findings.length, vulnerableDependencies },
    findings,
  };
}
