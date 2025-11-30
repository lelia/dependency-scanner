/**
 * Types for the dependency-scanner tool.
 */

export type DependencyType = "direct" | "transitive";

export interface DependencyNode {
  id: string;
  name: string;
  version: string;
  dependencyType: DependencyType;
  dependencies: string[];
}

export interface DependencyGraph {
  nodes: Map<string, DependencyNode>;
  roots: string[];
}
