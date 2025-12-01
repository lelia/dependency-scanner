/**
 * Shared types for vulnerability database clients.
 */

export interface Vulnerability {
  id: string;
  aliases?: string[];  // CVE IDs and other cross-references
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  references?: Array<{ type: string; url: string }>;
  fixedIn?: string;  // Version that fixes this vulnerability
}

