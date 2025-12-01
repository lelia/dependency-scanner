/**
 * Common utilities for dependency parsers.
 */

import fs from "node:fs";
import { DependencyGraph, DependencyNode, PackageRegistry } from "../types";

/**
 * Create a standardized node ID: "registry:name@version"
 */
export function makeNodeId(registry: PackageRegistry, name: string, version: string): string {
  return `${registry}:${name}@${version}`;
}

/**
 * Read and parse a JSON file.
 */
export function readJsonFile<T>(filePath: string): T {
  const content = fs.readFileSync(filePath, "utf-8");
  return JSON.parse(content) as T;
}

/**
 * Read a text file.
 */
export function readTextFile(filePath: string): string {
  return fs.readFileSync(filePath, "utf-8");
}

/**
 * Create an empty dependency graph structure.
 */
export function createEmptyGraph(): DependencyGraph {
  return {
    nodes: new Map<string, DependencyNode>(),
    roots: [],
  };
}

/**
 * Create a dependency node with standard structure.
 */
export function createNode(
  registry: PackageRegistry,
  name: string,
  version: string,
  dependencyType: "direct" | "transitive",
): DependencyNode {
  return {
    id: makeNodeId(registry, name, version),
    name,
    version,
    registry,
    dependencyType,
    dependencies: [],
  };
}

