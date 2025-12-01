/**
 * Unit tests for vulnerability merge logic.
 * 
 * Tests dedupe and conflict resolution when merging results from multiple databases. 
 * 
 * Usage: npm run test
 */

import { test, describe } from "node:test";
import assert from "node:assert";
import { mergeVulnerabilities, mergeVulnMaps } from "../src/clients/merge.js";
import { Vulnerability } from "../src/clients/types.js";

describe("mergeVulnerabilities", () => {
  test("deduplicates by vulnerability ID", () => {
    const a: Vulnerability[] = [
      { id: "GHSA-1234", summary: "Vuln A" },
    ];
    const b: Vulnerability[] = [
      { id: "GHSA-1234", summary: "Vuln A from B" },
      { id: "GHSA-5678", summary: "Vuln B only" },
    ];

    const merged = mergeVulnerabilities(a, b);
    
    assert.strictEqual(merged.length, 2);
    const ids = merged.map(v => v.id);
    assert.ok(ids.includes("GHSA-1234"));
    assert.ok(ids.includes("GHSA-5678"));
  });

  test("prefers longer summary when merging", () => {
    const a: Vulnerability[] = [
      { id: "GHSA-1234", summary: "Short" },
    ];
    const b: Vulnerability[] = [
      { id: "GHSA-1234", summary: "This is a much longer and more detailed summary" },
    ];

    const merged = mergeVulnerabilities(a, b);
    
    assert.strictEqual(merged.length, 1);
    assert.strictEqual(merged[0].summary, "This is a much longer and more detailed summary");
  });

  test("prefers higher severity when merging", () => {
    const a: Vulnerability[] = [
      { id: "GHSA-1234", severity: [{ type: "GHSA", score: "LOW" }] },
    ];
    const b: Vulnerability[] = [
      { id: "GHSA-1234", severity: [{ type: "GHSA", score: "CRITICAL" }] },
    ];

    const merged = mergeVulnerabilities(a, b);
    
    assert.strictEqual(merged.length, 1);
    assert.strictEqual(merged[0].severity?.[0].score, "CRITICAL");
  });

  test("unions references by URL", () => {
    const a: Vulnerability[] = [
      { 
        id: "GHSA-1234", 
        references: [{ type: "WEB", url: "https://example.com/a" }],
      },
    ];
    const b: Vulnerability[] = [
      { 
        id: "GHSA-1234", 
        references: [
          { type: "WEB", url: "https://example.com/a" },  // duplicate
          { type: "WEB", url: "https://example.com/b" },  // new
        ],
      },
    ];

    const merged = mergeVulnerabilities(a, b);
    
    assert.strictEqual(merged.length, 1);
    assert.strictEqual(merged[0].references?.length, 2);
  });

  test("prefers explicit fixedIn over missing", () => {
    const a: Vulnerability[] = [
      { id: "GHSA-1234" },  // no fixedIn
    ];
    const b: Vulnerability[] = [
      { id: "GHSA-1234", fixedIn: "1.2.3" },
    ];

    const merged = mergeVulnerabilities(a, b);
    
    assert.strictEqual(merged.length, 1);
    assert.strictEqual(merged[0].fixedIn, "1.2.3");
  });

  test("keeps fixedIn from first source if both have it", () => {
    const a: Vulnerability[] = [
      { id: "GHSA-1234", fixedIn: "1.0.0" },
    ];
    const b: Vulnerability[] = [
      { id: "GHSA-1234", fixedIn: "1.2.3" },
    ];

    const merged = mergeVulnerabilities(a, b);
    
    assert.strictEqual(merged.length, 1);
    assert.strictEqual(merged[0].fixedIn, "1.0.0");
  });
});

describe("mergeVulnMaps", () => {
  test("merges maps from multiple sources", () => {
    const map1 = new Map<string, Vulnerability[]>();
    map1.set("npm:lodash@4.17.20", [{ id: "GHSA-1234", summary: "Vuln 1" }]);

    const map2 = new Map<string, Vulnerability[]>();
    map2.set("npm:lodash@4.17.20", [{ id: "GHSA-5678", summary: "Vuln 2" }]);
    map2.set("npm:express@4.18.2", [{ id: "GHSA-9999", summary: "Express vuln" }]);

    const merged = mergeVulnMaps([map1, map2]);

    // lodash should have both vulns
    const lodashVulns = merged.get("npm:lodash@4.17.20");
    assert.ok(lodashVulns);
    assert.strictEqual(lodashVulns.length, 2);

    // express should have its vuln
    const expressVulns = merged.get("npm:express@4.18.2");
    assert.ok(expressVulns);
    assert.strictEqual(expressVulns.length, 1);
  });

  test("handles empty maps", () => {
    const map1 = new Map<string, Vulnerability[]>();
    const map2 = new Map<string, Vulnerability[]>();

    const merged = mergeVulnMaps([map1, map2]);

    assert.strictEqual(merged.size, 0);
  });

  test("dedupes same vulnerability across sources", () => {
    const map1 = new Map<string, Vulnerability[]>();
    map1.set("npm:lodash@4.17.20", [{ id: "GHSA-1234", summary: "Short" }]);

    const map2 = new Map<string, Vulnerability[]>();
    map2.set("npm:lodash@4.17.20", [{ id: "GHSA-1234", summary: "Longer description here" }]);

    const merged = mergeVulnMaps([map1, map2]);

    const lodashVulns = merged.get("npm:lodash@4.17.20");
    assert.ok(lodashVulns);
    assert.strictEqual(lodashVulns.length, 1);  // deduped
    assert.strictEqual(lodashVulns[0].summary, "Longer description here");
  });
});

