/**
 * Vulnerability database clients.
 *
 * Supported databases:
 * - Open Source Vulnerabilities: https://osv.dev/list
 * - GitHub Security Advisories: https://github.com/advisories
 */

export { Vulnerability } from "./types";
export { checkOsvVulnerabilities } from "./osv";
export { checkGhsaVulnerabilities } from "./ghsa";
