/**
 * Shared types for the dependency-scanner tool.
 */

export type DependencyType = "direct" | "transitive";
export type PackageRegistry = "npm" | "pypi";

export interface DependencyNode {
  id: string;
  name: string;
  version: string;
  registry: PackageRegistry;
  dependencyType: DependencyType;
  dependencies: string[];
}

export interface DependencyGraph {
  nodes: Map<string, DependencyNode>;
  roots: string[];
}
