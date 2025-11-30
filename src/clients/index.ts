/**
 * Routes to API client based on request ecosystem.
 *
 * Current ecosystems supported: 
 * - OSV.dev (Open Source Vulnerability)
 * - GHSA (GitHub Security Advisory)
 */

import { Ecosystem } from "../types";
import { checkVulnerabilities } from "./osv";

// TODO: Implement stubbed out client for GHSA
export function getClient(ecosystem: Ecosystem): Client {
  if (ecosystem === "osv") {
    return checkVulnerabilities;
  }
  return null;
}
