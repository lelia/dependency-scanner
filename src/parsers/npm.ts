/**
 * Parsers for npm ecosystem files:
 * - package-lock.json (v2/v3 format, npm v7+)
 * - package.json (direct deps only, fallback)
 * - yarn.lock (v1 classic, v2+ berry format)
 */

import fs from "node:fs";
import { DependencyGraph, DependencyNode } from "../types";

function makeNodeId(name: string, version: string): string {
  return `npm:${name}@${version}`;
}

// package-lock.json
interface PackageLockEntry {
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

function extractPackageName(path: string): string | null {
  const match = path.match(/node_modules\/(@[^/]+\/[^/]+|[^/]+)$/);
  return match ? match[1] : null;
}

function resolvePackage(
  packages: Record<string, PackageLockEntry>,
  fromPath: string,
  depName: string,
): PackageLockEntry | null {
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

export function parsePackageLock(filePath: string): DependencyGraph {
  const raw = fs.readFileSync(filePath, "utf-8");
  const lockfile = JSON.parse(raw) as {
    lockfileVersion?: number;
    packages: Record<string, PackageLockEntry>;
  };

  if (!lockfile.packages) {
    throw new Error(
      `Missing "packages" field. This parser requires lockfileVersion 2+ (npm 7+).`
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
    if (nodes.has(id)) continue;

    const isDirect = directDeps.has(name);
    nodes.set(id, {
      id,
      name,
      version: entry.version,
      registry: "npm",
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

// package.json
export function parsePackageJson(filePath: string): DependencyGraph {
  const raw = fs.readFileSync(filePath, "utf-8");
  const pkg = JSON.parse(raw) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };

  const nodes = new Map<string, DependencyNode>();
  const roots: string[] = [];

  const allDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
  };

  for (const [name, version] of Object.entries(allDeps)) {
    const id = makeNodeId(name, version);

    nodes.set(id, {
      id,
      name,
      version,
      registry: "npm",
      dependencyType: "direct",
      dependencies: [],
    });

    roots.push(id);
  }

  return { nodes, roots };
}

// yarn.lock
interface YarnEntry {
  version: string;
  resolved?: string;
  dependencies?: Record<string, string>;
}

function parseYarnV1(content: string): DependencyGraph {
  const nodes = new Map<string, DependencyNode>();
  const roots: string[] = [];
  const lines = content.split("\n");

  let currentNames: string[] = [];
  let currentEntry: Partial<YarnEntry> = {};
  let inDeps = false;

  const saveEntry = () => {
    if (currentNames.length && currentEntry.version) {
      for (const descriptor of currentNames) {
        const atIndex = descriptor.lastIndexOf("@");
        if (atIndex <= 0) continue;
        const name = descriptor.substring(0, atIndex);
        const id = makeNodeId(name, currentEntry.version!);

        if (!nodes.has(id)) {
          nodes.set(id, {
            id,
            name,
            version: currentEntry.version!,
            registry: "npm",
            dependencyType: "transitive",
            dependencies: [],
          });
        }
      }
    }
  };

  for (const line of lines) {
    if (line.startsWith("#") || line.trim() === "") continue;

    if (!line.startsWith(" ")) {
      saveEntry();
      currentEntry = {};
      inDeps = false;

      const match = line.match(/^(.+):$/);
      if (match) {
        currentNames = match[1]
          .split(",")
          .map((s) => s.trim().replace(/^"|"$/g, ""));
      }
      continue;
    }

    const trimmed = line.trim();

    if (trimmed.startsWith("version ")) {
      currentEntry.version = trimmed.replace(/^version\s+"?|"$/g, "");
      inDeps = false;
    } else if (trimmed === "dependencies:") {
      inDeps = true;
      currentEntry.dependencies = {};
    } else if (inDeps && trimmed.includes(" ")) {
      const depMatch = trimmed.match(/^"?([^"]+)"?\s+"?([^"]+)"?$/);
      if (depMatch && currentEntry.dependencies) {
        currentEntry.dependencies[depMatch[1]] = depMatch[2];
      }
    } else {
      inDeps = false;
    }
  }
  saveEntry();

  // Identify direct deps (eg. packages without dependents)
  const hasDependents = new Set<string>();
  for (const node of nodes.values()) {
    for (const depId of node.dependencies) {
      hasDependents.add(depId);
    }
  }
  for (const [id, node] of nodes) {
    if (!hasDependents.has(id)) {
      node.dependencyType = "direct";
      roots.push(id);
    }
  }

  return { nodes, roots };
}

function parseYarnV2(content: string): DependencyGraph {
  const nodes = new Map<string, DependencyNode>();
  const roots: string[] = [];
  const lines = content.split("\n");

  let currentKey: string | null = null;
  let currentVersion: string | null = null;
  let inDeps = false;

  const extractName = (descriptor: string): string | null => {
    const match = descriptor.match(/^(@?[^@]+)@/);
    return match ? match[1] : null;
  };

  for (const line of lines) {
    if (line.startsWith("#") || line.trim() === "") continue;
    if (line.startsWith("__metadata:")) continue;

    if (!line.startsWith(" ") && line.includes(":")) {
      if (currentKey && currentVersion) {
        const name = extractName(currentKey);
        if (name) {
          const id = makeNodeId(name, currentVersion);
          if (!nodes.has(id)) {
            nodes.set(id, {
              id,
              name,
              version: currentVersion,
              registry: "npm",
              dependencyType: "transitive",
              dependencies: [],
            });
          }
        }
      }

      const keyMatch = line.match(/^"?([^":]+)"?:/);
      currentKey = keyMatch ? keyMatch[1].split(",")[0].trim() : null;
      currentVersion = null;
      inDeps = false;
      continue;
    }

    const trimmed = line.trim();

    if (trimmed.startsWith("version:")) {
      currentVersion = trimmed.replace("version:", "").trim().replace(/"/g, "");
      inDeps = false;
    } else if (trimmed === "dependencies:") {
      inDeps = true;
    } else if (!trimmed.startsWith("  ") && trimmed !== "") {
      inDeps = false;
    }
  }

  if (currentKey && currentVersion) {
    const name = extractName(currentKey);
    if (name) {
      const id = makeNodeId(name, currentVersion);
      if (!nodes.has(id)) {
        nodes.set(id, {
          id,
          name,
          version: currentVersion,
          registry: "npm",
          dependencyType: "transitive",
          dependencies: [],
        });
      }
    }
  }

  // Identify direct deps (eg. packages without dependents)
  const hasDependents = new Set<string>();
  for (const node of nodes.values()) {
    for (const depId of node.dependencies) {
      hasDependents.add(depId);
    }
  }
  for (const [id, node] of nodes) {
    if (!hasDependents.has(id)) {
      node.dependencyType = "direct";
      roots.push(id);
    }
  }

  return { nodes, roots };
}

export function parseYarnLock(filePath: string): DependencyGraph {
  const content = fs.readFileSync(filePath, "utf-8");

  // Check for unique yarn v2+ metadata header
  if (content.includes("__metadata:")) {
    return parseYarnV2(content);
  }

  return parseYarnV1(content);
}

