/**
 * Basic file parser, limited to package-lock.json
 * 
 * TODO: 
 * - Add support for other lockfile formats
 * - Proper dependency edge resolution
 * - Better error handling
 */

import fs from "node:fs";
import { DependencyGraph, DependencyNode } from "./types";

interface PackageLock {
  packages: Record<string, { version?: string }>;
}

export function parseLockfile(lockfilePath: string): DependencyGraph {
  const raw = fs.readFileSync(lockfilePath, "utf-8");
  const lockfile = JSON.parse(raw) as PackageLock;

  const nodes = new Map<string, DependencyNode>();
  const roots: string[] = [];

  // TODO: Determine direct vs transitive from root package
  // TODO: Wire up dependency edges between nodes

  for (const [path, entry] of Object.entries(lockfile.packages)) {
    if (path === "" || !entry.version) continue;

    // Basic name extraction - doesn't handle scoped packages yet
    const name = path.replace("node_modules/", "");
    const id = `npm:${name}@${entry.version}`;

    nodes.set(id, {
      id,
      name,
      version: entry.version,
      dependencyType: "transitive", // TODO: detect direct deps
      dependencies: [], // TODO: resolve and populate
    });
  }

  return { nodes, roots };
}

