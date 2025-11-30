/**
 * Routes to parser based on package manifest and lockfile (if any).
 *
 * Ecosystems supported: npm (Node.js), pypi (Python)
 * Filetypes supported: package.json, package-lock.json (v2/v3), yarn.lock (v1/v2)
 */

import { DependencyGraph } from "../types";
import { parsePackageLock, parsePackageJson, parseYarnLock } from "./npm";

const SUPPORTED_FILES = [
  "package-lock.json",
  "package.json",
  "yarn.lock",
];

export function parse(filePath: string): DependencyGraph {
  // Route to npm ecosystem parsers
  if (filePath.endsWith("package-lock.json")) {
    return parsePackageLock(filePath);
  }
  if (filePath.endsWith("package.json")) {
    return parsePackageJson(filePath);
  }
  if (filePath.endsWith("yarn.lock")) {
    return parseYarnLock(filePath);
  }

  throw new Error(
    `Unsupported file: ${filePath}\n` +
    `Supported: ${SUPPORTED_FILES.join(", ")}`
  );
}
