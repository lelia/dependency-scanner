/**
 * Routes to parser based on package manifest and lockfile type.
 *
 * Current ecosystems supported: 
 * - NPM (Node.js)
 * - PyPI (Python)
 */

import { DependencyGraph } from "../types";
import { parsePackageLock, parsePackageJson, parseYarnLock } from "./npm";
import { parseRequirements, parsePoetryLock, parsePipfileLock } from "./pypi";

const SUPPORTED_FILES = [
  // npm filetypes
  "package-lock.json",
  "package.json",
  "yarn.lock",
  // pypi filetypes
  "requirements.txt",
  "poetry.lock",
  "Pipfile.lock",
];

export function parse(filePath: string): DependencyGraph {
  // npm ecosystem
  if (filePath.endsWith("package-lock.json")) {
    return parsePackageLock(filePath);
  }
  if (filePath.endsWith("package.json")) {
    return parsePackageJson(filePath);
  }
  if (filePath.endsWith("yarn.lock")) {
    return parseYarnLock(filePath);
  }

  // pypi ecosystem
  if (filePath.endsWith("requirements.txt")) {
    return parseRequirements(filePath);
  }
  if (filePath.endsWith("poetry.lock")) {
    return parsePoetryLock(filePath);
  }
  if (filePath.endsWith("Pipfile.lock")) {
    return parsePipfileLock(filePath);
  }

  throw new Error(
    `Unsupported file: ${filePath}\n` +
    `Supported: ${SUPPORTED_FILES.join(", ")}`
  );
}
