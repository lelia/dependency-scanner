/**
 * Types for the dependency-scanner tool.
 */

export type DependencyType = "direct" | "transitive";
export type Ecosystem = "npm" | "pypi";

export interface DependencyNode {
  id: string;
  name: string;
  version: string;
  ecosystem: Ecosystem;
  dependencyType: DependencyType;
  dependencies: string[];
}

export interface DependencyGraph {
  nodes: Map<string, DependencyNode>;
  roots: string[];
}
