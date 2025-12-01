/**
 * Parsers for dependency manifests and lockfiles.
 *
 * Supported ecosystems:
 * - Node.js ("package-lock.json", "package.json", "yarn.lock")
 * - Python ("requirements.txt", "poetry.lock", "Pipfile.lock")
 */

import { DependencyGraph } from "../types";
import { parsePackageLock, parsePackageJson, parseYarnLock } from "./npm";
import { parseRequirements, parsePoetryLock, parsePipfileLock } from "./pypi";

const SUPPORTED_FILES = [
  "package-lock.json",
  "package.json",
  "yarn.lock",
  "requirements.txt",
  "poetry.lock",
  "Pipfile.lock",
];

// TODO: Consider reworking as filetypes continue to grow (factory pattern?)
export function parse(filePath: string): DependencyGraph {
  if (filePath.endsWith("package-lock.json")) {
    return parsePackageLock(filePath);
  }
  if (filePath.endsWith("package.json")) {
    return parsePackageJson(filePath);
  }
  if (filePath.endsWith("yarn.lock")) {
    return parseYarnLock(filePath);
  }

  if (filePath.endsWith("requirements.txt")) {
    return parseRequirements(filePath);
  }
  if (filePath.endsWith("poetry.lock")) {
    return parsePoetryLock(filePath);
  }
  if (filePath.toLowerCase().endsWith("pipfile.lock")) {
    return parsePipfileLock(filePath);
  }

  throw new Error(
    `Unsupported file: ${filePath}\n` +
    `Supported: ${SUPPORTED_FILES.join(", ")}`
  );
}
