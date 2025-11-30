/**
 * Router for various parsers based on filetype.
 */

import { DependencyGraph } from "../types";
import { parsePackageLock } from "./package-lock";

const SUPPORTED_FILES = [
  "package-lock.json",
];

export function parse(filePath: string): DependencyGraph {
  if (filePath.endsWith("package-lock.json")) {
    return parsePackageLock(filePath);
  }

  throw new Error(
    `Unsupported file type: ${filePath}\n` +
    `Supported formats: ${SUPPORTED_FILES.join(", ")}`
  );
}
