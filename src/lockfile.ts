/**
 * Basic file parser, limited to package-lock.json (v2/v3 format).
 * 
 * TODO:
 * - Add support for npm package.json
 * - Add support for lockfile formats (eg. yarn.lock)
 * - Add support for python requirements.txt
 */

import fs from "node:fs";
import { DependencyGraph, DependencyNode } from "./types";

interface PackageLock {
  lockfileVersion?: number;
  packages: Record<string, PackageEntry>;
}

interface PackageEntry {
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

function makeNodeId(name: string, version: string): string {
  return `npm:${name}@${version}`;
}

function extractPackageName(path: string): string | null {
  const match = path.match(/node_modules\/(@[^/]+\/[^/]+|[^/]+)$/);
  return match ? match[1] : null;
}

/**
 * Resolve dependency by checking nested node_modules first, then walk up the tree.
 */
function resolvePackage(
  packages: Record<string, PackageEntry>,
  fromPath: string,
  depName: string,
): PackageEntry | null {
  const nestedPath = `${fromPath}/node_modules/${depName}`;
  if (packages[nestedPath]) return packages[nestedPath];

  let current = fromPath;
  while (current.includes("node_modules/")) {
    const lastNM = current.lastIndexOf("/node_modules/");
    if (lastNM === -1) break;
    current = current.substring(0, lastNM);

    const checkPath = current === ""
      ? `node_modules/${depName}`
      : `${current}/node_modules/${depName}`;
    if (packages[checkPath]) return packages[checkPath];
  }

  return packages[`node_modules/${depName}`] ?? null;
}

export function parseLockfile(lockfilePath: string): DependencyGraph {
  const raw = fs.readFileSync(lockfilePath, "utf-8");
  const lockfile = JSON.parse(raw) as PackageLock;

  if (!lockfile.packages) {
    throw new Error(
      `Missing "packages" field. This parser requires lockfileVersion 2+ (npm 7+).`,
    );
  }

  const nodes = new Map<string, DependencyNode>();
  const roots: string[] = [];

  const rootPkg = lockfile.packages[""] ?? {};
  const directDeps = new Set([
    ...Object.keys(rootPkg.dependencies ?? {}),
    ...Object.keys(rootPkg.devDependencies ?? {}),
  ]);

  for (const [path, entry] of Object.entries(lockfile.packages)) {
    if (path === "" || !entry.version) continue;

    const name = extractPackageName(path);
    if (!name) continue;

    const id = makeNodeId(name, entry.version);
    if (nodes.has(id)) continue; // Dedupe (eg. hoisting creates multiple paths to the same package)

    const isDirect = directDeps.has(name);
    nodes.set(id, {
      id,
      name,
      version: entry.version,
      dependencyType: isDirect ? "direct" : "transitive",
      dependencies: [],
    });

    if (isDirect) roots.push(id);
  }

  for (const [path, entry] of Object.entries(lockfile.packages)) {
    if (path === "" || !entry.version) continue;

    const name = extractPackageName(path);
    if (!name) continue;

    const parentNode = nodes.get(makeNodeId(name, entry.version));
    if (!parentNode) continue;

    const depNames = [
      ...Object.keys(entry.dependencies ?? {}),
      ...Object.keys(entry.peerDependencies ?? {}),
      ...Object.keys(entry.optionalDependencies ?? {}),
    ];

    for (const depName of depNames) {
      const resolved = resolvePackage(lockfile.packages, path, depName);
      if (!resolved?.version) continue;

      const childId = makeNodeId(depName, resolved.version);
      if (nodes.has(childId) && !parentNode.dependencies.includes(childId)) {
        parentNode.dependencies.push(childId);
      }
    }
  }

  return { nodes, roots };
}

