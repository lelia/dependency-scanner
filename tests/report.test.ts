/**
 * Unit tests for report generation.
 * 
 * Tests the generateReport function and validates the report structure.
 * 
 * Usage: npm run test
 */

import { test, describe } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { generateReport, Report, Finding } from "../src/report.js";
import { DependencyGraph, DependencyNode } from "../src/types.js";
import { Vulnerability } from "../src/clients/types.js";

const FIXTURES = path.join(process.cwd(), "tests/fixtures");

// Sample graph with 5 dependencies (2 direct, 3 transitive)
function createTestGraph(): DependencyGraph {
  const nodes = new Map<string, DependencyNode>();
  
  nodes.set("npm:lodash@4.17.20", {
    id: "npm:lodash@4.17.20",
    name: "lodash",
    version: "4.17.20",
    registry: "npm",
    dependencyType: "direct",
    dependencies: ["npm:minimist@1.2.5"],  // lodash depends on minimist
  });
  
  nodes.set("npm:express@4.18.2", {
    id: "npm:express@4.18.2",
    name: "express",
    version: "4.18.2",
    registry: "npm",
    dependencyType: "direct",
    dependencies: ["npm:debug@4.3.4"],
  });
  
  nodes.set("npm:minimist@1.2.5", {
    id: "npm:minimist@1.2.5",
    name: "minimist",
    version: "1.2.5",
    registry: "npm",
    dependencyType: "transitive",
    dependencies: [],
  });
  
  nodes.set("npm:debug@4.3.4", {
    id: "npm:debug@4.3.4",
    name: "debug",
    version: "4.3.4",
    registry: "npm",
    dependencyType: "transitive",
    dependencies: ["npm:ms@2.1.3"],
  });
  
  nodes.set("npm:ms@2.1.3", {
    id: "npm:ms@2.1.3",
    name: "ms",
    version: "2.1.3",
    registry: "npm",
    dependencyType: "transitive",
    dependencies: [],
  });

  return {
    nodes,
    roots: ["npm:lodash@4.17.20", "npm:express@4.18.2"],
  };
}

// Sample vulnerabilities
function createTestVulns(): Map<string, Vulnerability[]> {
  const vulns = new Map<string, Vulnerability[]>();
  
  vulns.set("npm:lodash@4.17.20", [{
    id: "GHSA-jf85-cpcp-j695",
    aliases: ["CVE-2021-23337"],
    summary: "Prototype Pollution in lodash",
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H" }],
    references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-jf85-cpcp-j695" }],
    fixedIn: "4.17.21",
  }]);
  
  vulns.set("npm:minimist@1.2.5", [{
    id: "GHSA-xvch-5gv4-984h",
    aliases: ["CVE-2021-44906"],
    summary: "Prototype Pollution in minimist",
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" }],
    references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-xvch-5gv4-984h" }],
    fixedIn: "1.2.6",
  }]);
  
  return vulns;
}

const testMetadata = {
  scannedFile: "/path/to/project/package-lock.json",
  sources: ["osv" as const],
  timestamp: "2025-12-01T12:00:00.000Z",
  durationMs: 450,
};

describe("report fixtures", () => {
  test("sample-with-vulns.json has correct structure", () => {
    const report: Report = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, "reports/sample-with-vulns.json"), "utf-8")
    );

    // Metadata
    assert.ok(report.metadata.scannedFile);
    assert.ok(Array.isArray(report.metadata.sources));
    assert.ok(report.metadata.timestamp);
    assert.ok(typeof report.metadata.durationMs === "number");

    // Summary
    assert.strictEqual(report.summary.totalDependencies, 5);
    assert.strictEqual(report.summary.directDependencies, 2);
    assert.strictEqual(report.summary.transitiveDependencies, 3);
    assert.strictEqual(report.summary.vulnerableDependencies, 2);
    assert.strictEqual(report.summary.vulnerablePercentage, 40);

    // Findings with vulnerabilities
    const vulnFindings = report.findings.filter(f => f.vulnerabilities.length > 0);
    assert.strictEqual(vulnFindings.length, 2);
  });

  test("sample-with-vulns.json includes fixedIn for remediations", () => {
    const report: Report = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, "reports/sample-with-vulns.json"), "utf-8")
    );

    const lodash = report.findings.find(f => f.name === "lodash");
    assert.ok(lodash);
    assert.strictEqual(lodash.vulnerabilities[0].fixedIn, "4.17.21");

    const minimist = report.findings.find(f => f.name === "minimist");
    assert.ok(minimist);
    assert.strictEqual(minimist.vulnerabilities[0].fixedIn, "1.2.6");
  });

  test("sample-with-vulns.json includes aliases for CVE IDs", () => {
    const report: Report = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, "reports/sample-with-vulns.json"), "utf-8")
    );

    const lodash = report.findings.find(f => f.name === "lodash");
    assert.ok(lodash);
    assert.deepStrictEqual(lodash.vulnerabilities[0].aliases, ["CVE-2021-23337"]);

    const minimist = report.findings.find(f => f.name === "minimist");
    assert.ok(minimist);
    assert.deepStrictEqual(minimist.vulnerabilities[0].aliases, ["CVE-2021-44906"]);
  });

  test("sample-no-vulns.json has zero vulnerable", () => {
    const report: Report = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, "reports/sample-no-vulns.json"), "utf-8")
    );

    assert.strictEqual(report.summary.vulnerableDependencies, 0);
    assert.strictEqual(report.summary.vulnerablePercentage, 0);
    
    const vulnFindings = report.findings.filter(f => f.vulnerabilities.length > 0);
    assert.strictEqual(vulnFindings.length, 0);
  });
});

describe("generateReport", () => {
  test("calculates summary correctly with vulnerabilities", () => {
    const graph = createTestGraph();
    const vulns = createTestVulns();

    const report = generateReport(graph, vulns, testMetadata);

    assert.strictEqual(report.summary.totalDependencies, 5);
    assert.strictEqual(report.summary.directDependencies, 2);
    assert.strictEqual(report.summary.transitiveDependencies, 3);
    assert.strictEqual(report.summary.vulnerableDependencies, 2);
    assert.strictEqual(report.summary.vulnerablePercentage, 40);
  });

  test("calculates summary correctly with no vulnerabilities", () => {
    const graph = createTestGraph();
    const vulns = new Map<string, Vulnerability[]>();
    
    const report = generateReport(graph, vulns, testMetadata);

    assert.strictEqual(report.summary.vulnerableDependencies, 0);
    assert.strictEqual(report.summary.vulnerablePercentage, 0);
  });

  test("includes metadata in report", () => {
    const graph = createTestGraph();
    const vulns = new Map<string, Vulnerability[]>();
    
    const report = generateReport(graph, vulns, testMetadata);

    assert.strictEqual(report.metadata.scannedFile, testMetadata.scannedFile);
    assert.deepStrictEqual(report.metadata.sources, testMetadata.sources);
    assert.strictEqual(report.metadata.timestamp, testMetadata.timestamp);
    assert.strictEqual(report.metadata.durationMs, testMetadata.durationMs);
  });

  test("includes fixedIn in vulnerability findings", () => {
    const graph = createTestGraph();
    const vulns = createTestVulns();
    
    const report = generateReport(graph, vulns, testMetadata);

    const lodash = report.findings.find(f => f.name === "lodash");
    assert.ok(lodash);
    assert.strictEqual(lodash.vulnerabilities[0].fixedIn, "4.17.21");
  });

  test("includes aliases (CVE IDs) in vulnerability findings", () => {
    const graph = createTestGraph();
    const vulns = createTestVulns();
    
    const report = generateReport(graph, vulns, testMetadata);

    const lodash = report.findings.find(f => f.name === "lodash");
    assert.ok(lodash);
    assert.deepStrictEqual(lodash.vulnerabilities[0].aliases, ["CVE-2021-23337"]);
  });

  test("maps dependency types correctly", () => {
    const graph = createTestGraph();
    const vulns = new Map<string, Vulnerability[]>();
    
    const report = generateReport(graph, vulns, testMetadata);

    const directFindings = report.findings.filter(f => f.dependencyType === "direct");
    const transitiveFindings = report.findings.filter(f => f.dependencyType === "transitive");

    assert.strictEqual(directFindings.length, 2);
    assert.strictEqual(transitiveFindings.length, 3);
  });
});

