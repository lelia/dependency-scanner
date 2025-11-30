/**
 * Get all dependencies reachable from the graph's roots using depth-first search.
 */

import { DependencyGraph, DependencyNode } from "./types";

export function getAllDependencies(graph: DependencyGraph): DependencyNode[] {
  const visited = new Set<string>();
  const result: DependencyNode[] = [];

  function visit(nodeId: string) {
    if (visited.has(nodeId)) return;
    visited.add(nodeId);

    const node = graph.nodes.get(nodeId);
    if (!node) return; // Dangling reference (e.g., optional dep not installed)

    result.push(node);
    for (const childId of node.dependencies) {
      visit(childId);
    }
  }

  for (const rootId of graph.roots) {
    visit(rootId);
  }

  return result;
}
