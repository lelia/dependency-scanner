/**
 * Parsers for pypi ecosystem files:
 * - requirements.txt (direct deps only)
 * - poetry.lock (full dependency tree)
 * - Pipfile.lock (full dependency tree)
 */

import fs from "node:fs";
import { DependencyGraph, DependencyNode } from "../types";

function makeNodeId(name: string, version: string): string {
  return `pypi:${name}@${version}`;
}

function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[_.-]+/g, "-");
}

// requirements.txt
export function parseRequirements(filePath: string): DependencyGraph {
  const content = fs.readFileSync(filePath, "utf-8");
  const lines = content.split("\n");

  const nodes = new Map<string, DependencyNode>();
  const roots: string[] = [];

  for (const line of lines) {
    const trimmed = line.trim();

    if (!trimmed) continue;
    if (trimmed.startsWith("#")) continue;
    if (trimmed.startsWith("-")) continue;
    if (trimmed.includes("://")) continue;

    const exactMatch = trimmed.match(/^([a-zA-Z0-9_.-]+)==([^\s;#]+)/);
    if (exactMatch) {
      const [, rawName, version] = exactMatch;
      const name = normalizeName(rawName);
      const id = makeNodeId(name, version);

      if (!nodes.has(id)) {
        nodes.set(id, {
          id,
          name,
          version,
          ecosystem: "pypi",
          dependencyType: "direct",
          dependencies: [],
        });
        roots.push(id);
      }
      continue;
    }

    const rangeMatch = trimmed.match(/^([a-zA-Z0-9_.-]+)[>~]=([^\s,;#]+)/);
    if (rangeMatch) {
      const [, rawName, version] = rangeMatch;
      const name = normalizeName(rawName);
      const id = makeNodeId(name, `>=${version}`);

      if (!nodes.has(id)) {
        nodes.set(id, {
          id,
          name,
          version: `>=${version}`,
          ecosystem: "pypi",
          dependencyType: "direct",
          dependencies: [],
        });
        roots.push(id);
      }
      continue;
    }

    // Skip if there is a bare package without version
    const bareMatch = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*$/);
    if (bareMatch) {
      console.warn(`Skipping ${bareMatch[1]}: no version specified`);
    }
  }

  return { nodes, roots };
}

// poetry.lock
interface PoetryPackage {
  name: string;
  version: string;
  category?: string;
  dependencies: Record<string, unknown>;
}

function parsePoetryPackages(content: string): PoetryPackage[] {
  const packages: PoetryPackage[] = [];
  const lines = content.split("\n");

  let current: Partial<PoetryPackage> | null = null;
  let inDeps = false;
  let deps: Record<string, unknown> = {};

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed === "[[package]]") {
      if (current?.name && current?.version) {
        current.dependencies = deps;
        packages.push(current as PoetryPackage);
      }
      current = {};
      deps = {};
      inDeps = false;
      continue;
    }

    if (trimmed === "[package.dependencies]") {
      inDeps = true;
      continue;
    }

    if (trimmed.startsWith("[")) {
      inDeps = false;
      continue;
    }

    if (!current) continue;

    // Match key = "value" pair to extract package info
    const kvMatch = trimmed.match(/^(\w+)\s*=\s*"([^"]+)"$/);
    if (kvMatch) {
      const [, key, value] = kvMatch;
      if (key === "name") current.name = value;
      else if (key === "version") current.version = value;
      else if (key === "category") current.category = value;
      else if (inDeps) deps[key] = value;
      continue;
    }

    if (inDeps) {
      const depMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=/);
      if (depMatch) deps[depMatch[1]] = true;
    }
  }

  if (current?.name && current?.version) {
    current.dependencies = deps;
    packages.push(current as PoetryPackage);
  }

  return packages;
}

export function parsePoetryLock(filePath: string): DependencyGraph {
  const content = fs.readFileSync(filePath, "utf-8");

  if (!content.includes("[[package]]")) {
    throw new Error("Invalid poetry.lock: missing [[package]] sections");
  }

  const packages = parsePoetryPackages(content);
  const nodes = new Map<string, DependencyNode>();
  const roots: string[] = [];

  const versionMap = new Map<string, string>();
  for (const pkg of packages) {
    versionMap.set(normalizeName(pkg.name), pkg.version);
  }

  // Create nodes for each package
  for (const pkg of packages) {
    const name = normalizeName(pkg.name);
    const id = makeNodeId(name, pkg.version);
    const isDirect = pkg.category !== "dev";

    nodes.set(id, {
      id,
      name,
      version: pkg.version,
      ecosystem: "pypi",
      dependencyType: isDirect ? "direct" : "transitive",
      dependencies: [],
    });

    if (isDirect) roots.push(id);
  }

  // Link dependencies between packages
  for (const pkg of packages) {
    const name = normalizeName(pkg.name);
    const parentId = makeNodeId(name, pkg.version);
    const parent = nodes.get(parentId);
    if (!parent) continue;

    for (const depName of Object.keys(pkg.dependencies)) {
      const normalDep = normalizeName(depName);
      const depVersion = versionMap.get(normalDep);
      if (!depVersion) continue;

      const childId = makeNodeId(normalDep, depVersion);
      if (nodes.has(childId) && !parent.dependencies.includes(childId)) {
        parent.dependencies.push(childId);
      }
    }
  }

  return { nodes, roots };
}

// Pipfile.lock
interface PipfileLockData {
  default?: Record<string, { version: string }>;
  develop?: Record<string, { version: string }>;
}

export function parsePipfileLock(filePath: string): DependencyGraph {
  const content = fs.readFileSync(filePath, "utf-8");
  const lockfile = JSON.parse(content) as PipfileLockData;

  if (!lockfile.default && !lockfile.develop) {
    throw new Error("Invalid Pipfile.lock: missing 'default' or 'develop' sections");
  }

  const nodes = new Map<string, DependencyNode>();
  const roots: string[] = [];

  // Production deps
  for (const [rawName, pkg] of Object.entries(lockfile.default || {})) {
    const name = normalizeName(rawName);
    const version = pkg.version.replace(/^==/, "");
    const id = makeNodeId(name, version);

    nodes.set(id, {
      id,
      name,
      version,
      ecosystem: "pypi",
      dependencyType: "direct",
      dependencies: [],
    });

    roots.push(id);
  }

  // Development deps
  for (const [rawName, pkg] of Object.entries(lockfile.develop || {})) {
    const name = normalizeName(rawName);
    const version = pkg.version.replace(/^==/, "");
    const id = makeNodeId(name, version);

    if (nodes.has(id)) continue;

    nodes.set(id, {
      id,
      name,
      version,
      ecosystem: "pypi",
      dependencyType: "transitive",
      dependencies: [],
    });
  }

  return { nodes, roots };
}

