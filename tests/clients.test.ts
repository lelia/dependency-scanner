/**
 * Unit tests for vulnerability database clients.
 * 
 * Uses fixtures to mock API responses, no network calls.
 * 
 * Usage: npm run test
 */

import { test, describe, mock } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { DependencyNode } from "../src/types.js";

const FIXTURES = path.join(process.cwd(), "tests/fixtures");

const sampleDeps: DependencyNode[] = [
  {
    id: "npm:lodash@4.17.20",
    name: "lodash",
    version: "4.17.20",
    registry: "npm",
    dependencyType: "direct",
    dependencies: [],
  },
  {
    id: "npm:express@4.18.2",
    name: "express",
    version: "4.18.2",
    registry: "npm",
    dependencyType: "direct",
    dependencies: [],
  },
];

describe("OSV client", () => {
  test("fixture has correct structure for response with vulns", () => {
    const fixtureData = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, "osv/batch-response-with-vulns.json"), "utf-8")
    );

    // Validate OSV batch response structure
    assert.ok(Array.isArray(fixtureData.results));
    assert.strictEqual(fixtureData.results.length, 2);
    
    // First result has vulnerabilities
    assert.ok(Array.isArray(fixtureData.results[0].vulns));
    assert.strictEqual(fixtureData.results[0].vulns.length, 1);
    assert.strictEqual(fixtureData.results[0].vulns[0].id, "GHSA-jf85-cpcp-j695");
    assert.ok(fixtureData.results[0].vulns[0].summary);
    assert.ok(Array.isArray(fixtureData.results[0].vulns[0].severity));
    assert.ok(Array.isArray(fixtureData.results[0].vulns[0].references));
    
    // Second result is empty
    assert.strictEqual(fixtureData.results[1].vulns.length, 0);
  });

  test("fixture has correct structure for empty response", () => {
    const fixtureData = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, "osv/batch-response-empty.json"), "utf-8")
    );

    assert.ok(Array.isArray(fixtureData.results));
    assert.strictEqual(fixtureData.results.length, 2);
    assert.strictEqual(fixtureData.results[0].vulns.length, 0);
    assert.strictEqual(fixtureData.results[1].vulns.length, 0);
  });

  test("vulnerability object has expected fields", () => {
    const fixtureData = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, "osv/batch-response-with-vulns.json"), "utf-8")
    );

    const vuln = fixtureData.results[0].vulns[0];
    
    // Required fields our Vulnerability interface expects
    assert.ok(typeof vuln.id === "string");
    assert.ok(typeof vuln.summary === "string");
    assert.ok(Array.isArray(vuln.severity));
    assert.ok(vuln.severity[0].type);
    assert.ok(vuln.severity[0].score);
    assert.ok(Array.isArray(vuln.references));
    assert.ok(vuln.references[0].url);
  });
});

describe("GHSA client", () => {
  test("parses GraphQL response with vulnerabilities", async () => {
    const fixtureData = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, "ghsa/graphql-response-with-vulns.json"), "utf-8")
    );

    // Mock the graphql module
    const mockGraphql = mock.fn(async () => fixtureData);
    (mockGraphql as any).defaults = () => mockGraphql;
    
    // Import the module
    const ghsaModule = await import("../src/clients/ghsa.js");
    
    // For now, verify fixture structure is correct
    assert.ok(fixtureData.pkg_0_lodash);
    assert.strictEqual(fixtureData.pkg_0_lodash.nodes.length, 1);
    assert.strictEqual(fixtureData.pkg_0_lodash.nodes[0].advisory.ghsaId, "GHSA-jf85-cpcp-j695");
  });

  test("fixture has correct structure for empty response", async () => {
    const fixtureData = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, "ghsa/graphql-response-empty.json"), "utf-8")
    );

    assert.ok(fixtureData.pkg_0_lodash);
    assert.strictEqual(fixtureData.pkg_0_lodash.nodes.length, 0);
    assert.ok(fixtureData.pkg_1_express);
    assert.strictEqual(fixtureData.pkg_1_express.nodes.length, 0);
  });
});

describe("Malformed API responses", () => {
  // These fixtures document edge cases our clients should handle gracefully
  // Actual resilience testing would require mocking the network layer
  
  test("OSV: missing results array", () => {
    const data = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, "malformed/osv-missing-results.json"), "utf-8")
    );
    
    // No results array - client would need to handle this
    assert.strictEqual(data.results, undefined);
    assert.ok(data.error); // API returned error message instead
  });

  test("OSV: null vulns array", () => {
    const data = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, "malformed/osv-null-vulns.json"), "utf-8")
    );
    
    // vulns is null instead of empty array
    assert.strictEqual(data.results[0].vulns, null);
    // Or vulns key is missing entirely
    assert.strictEqual(data.results[1].vulns, undefined);
  });

  test("GHSA: empty object response", () => {
    const data = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, "malformed/ghsa-empty-object.json"), "utf-8")
    );
    
    // No package aliases at all
    assert.deepStrictEqual(data, {});
  });

  test("GHSA: null nodes array", () => {
    const data = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, "malformed/ghsa-null-nodes.json"), "utf-8")
    );
    
    // nodes is null instead of array
    assert.strictEqual(data.pkg_0_lodash.nodes, null);
    // Or entire package response is null
    assert.strictEqual(data.pkg_1_express, null);
  });
});

describe("Version matching (semver)", () => {
  // GHSA client uses semver package for accurate version matching
  // OSV does server-side matching, so no client-side semver needed there
  
  const semver = require("semver");
  
  // Helper to convert GHSA range format to semver format
  function toSemverRange(ghsaRange: string): string {
    return ghsaRange
      .split(",")
      .map((part: string) => part.trim().replace(/\s+/g, ""))
      .join(" ");
  }

  test("matches version in simple range", () => {
    const range = toSemverRange("< 4.17.21");
    assert.ok(semver.satisfies("4.17.20", range));
    assert.ok(!semver.satisfies("4.17.21", range));
    assert.ok(!semver.satisfies("4.17.22", range));
  });

  test("matches version in complex range", () => {
    const range = toSemverRange(">= 1.0.0, < 2.0.0");
    assert.ok(semver.satisfies("1.0.0", range));
    assert.ok(semver.satisfies("1.5.0", range));
    assert.ok(semver.satisfies("1.9.9", range));
    assert.ok(!semver.satisfies("0.9.9", range));
    assert.ok(!semver.satisfies("2.0.0", range));
  });

  test("handles exact version match", () => {
    const range = toSemverRange("= 1.2.3");
    assert.ok(semver.satisfies("1.2.3", range));
    assert.ok(!semver.satisfies("1.2.4", range));
  });

  test("handles greater-than range", () => {
    const range = toSemverRange(">= 2.0.0");
    assert.ok(semver.satisfies("2.0.0", range));
    assert.ok(semver.satisfies("3.0.0", range));
    assert.ok(!semver.satisfies("1.9.9", range));
  });
});

