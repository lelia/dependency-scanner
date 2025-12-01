/**
 * Shared types for vulnerability database clients.
 */

export interface Vulnerability {
  id: string;
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  references?: Array<{ type: string; url: string }>;
  fixedIn?: string;  // Version that fixes this vulnerability
}

