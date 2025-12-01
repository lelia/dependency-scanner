/**
 * Unit tests for filetype parsers and routing logic.
 * 
 * Uses fixtures to test the parsers with known-good and malformed inputs.
 *
 * Usage: npm run test
 */

import { test, describe } from "node:test";
import assert from "node:assert";
import path from "node:path";
import { parse } from "../src/parsers";
import {
  parsePackageLock,
  parsePackageJson,
  parseYarnLock,
} from "../src/parsers/npm";
import {
  parseRequirements,
  parsePoetryLock,
  parsePipfileLock,
} from "../src/parsers/pypi";

const FIXTURES = path.join(process.cwd(), "tests/fixtures");

// Parser router tests
describe("parse router", () => {
  test("routes package-lock.json to npm parser", () => {
    const graph = parse(path.join(FIXTURES, "npm/package-lock.json"));
    assert.ok(graph.nodes.size > 0);
  });

  test("throws on unsupported file type", () => {
    assert.throws(
      () => parse("/fake/path/unknown.xyz"),
      /Unsupported file/
    );
  });

  test("throws on missing file", () => {
    assert.throws(
      () => parse("/nonexistent/package-lock.json"),
      /ENOENT/
    );
  });
});

// npm registry tests
describe("parsePackageLock", () => {
  test("parses v2 lockfile", () => {
    const graph = parsePackageLock(path.join(FIXTURES, "npm/package-lock-v2.json"));
    assert.strictEqual(graph.nodes.size, 2);
    assert.strictEqual(graph.roots.length, 2);
    
    const lodash = graph.nodes.get("npm:lodash@4.17.21");
    assert.ok(lodash);
    assert.strictEqual(lodash.registry, "npm");
  });

  test("parses v3 lockfile", () => {
    const graph = parsePackageLock(path.join(FIXTURES, "npm/package-lock-v3.json"));
    assert.strictEqual(graph.nodes.size, 3);
    
    // Check scoped package is parsed correctly
    const scoped = graph.nodes.get("npm:@scope/utils@1.2.3");
    assert.ok(scoped, "should parse scoped package");
    assert.strictEqual(scoped.dependencyType, "direct");
  });

  test("throws on v1 lockfile (unsupported)", () => {
    assert.throws(
      () => parsePackageLock(path.join(FIXTURES, "npm/package-lock-v1.json")),
      /lockfileVersion 2\+/
    );
  });

  test("throws on empty object", () => {
    assert.throws(
      () => parsePackageLock(path.join(FIXTURES, "malformed/parser-empty-object.json")),
      /packages/
    );
  });
});

describe("parsePackageJson", () => {
  test("parses direct dependencies", () => {
    const graph = parsePackageJson(path.join(FIXTURES, "npm/package.json"));
    assert.strictEqual(graph.nodes.size, 3);
    assert.strictEqual(graph.roots.length, 3);
    
    // All should be marked as direct
    for (const node of graph.nodes.values()) {
      assert.strictEqual(node.dependencyType, "direct");
      assert.strictEqual(node.registry, "npm");
    }
  });
});

describe("parseYarnLock", () => {
  test("parses v1 (classic) format", () => {
    const graph = parseYarnLock(path.join(FIXTURES, "npm/yarn-v1.lock"));
    assert.ok(graph.nodes.size >= 3);
    
    const lodash = graph.nodes.get("npm:lodash@4.17.21");
    assert.ok(lodash, "should find lodash");
  });

  test("parses v2 (berry) format", () => {
    const graph = parseYarnLock(path.join(FIXTURES, "npm/yarn-v2.lock"));
    assert.ok(graph.nodes.size >= 3);
    
    const express = graph.nodes.get("npm:express@4.18.2");
    assert.ok(express, "should find express");
  });
});

// PyPI registry tests
describe("parseRequirements", () => {
  test("parses clean requirements file", () => {
    const graph = parseRequirements(path.join(FIXTURES, "pypi/requirements-clean.txt"));
    assert.strictEqual(graph.nodes.size, 4);
    
    const requests = graph.nodes.get("pypi:requests@2.31.0");
    assert.ok(requests);
    assert.strictEqual(requests.registry, "pypi");
  });

  test("handles messy requirements file", () => {
    const graph = parseRequirements(path.join(FIXTURES, "pypi/requirements-messy.txt"));
    
    // Should parse pinned versions
    assert.ok(graph.nodes.get("pypi:requests@2.31.0"));
    assert.ok(graph.nodes.get("pypi:flask@2.3.0")); // normalized from Flask
    
    // Should handle version ranges
    assert.ok(graph.nodes.get("pypi:pandas@>=2.0.0"));
    
    // Should normalize underscores/dots to hyphens (PEP 503)
    assert.ok(graph.nodes.get("pypi:some-package@1.0.0"));
    assert.ok(graph.nodes.get("pypi:some-other-package@2.0.0"));
  });
});

describe("parsePoetryLock", () => {
  test("parses poetry.lock with dependencies", () => {
    const graph = parsePoetryLock(path.join(FIXTURES, "pypi/poetry.lock"));
    
    // Should have all packages
    assert.ok(graph.nodes.get("pypi:requests@2.31.0"));
    assert.ok(graph.nodes.get("pypi:urllib3@2.0.4"));
    assert.ok(graph.nodes.get("pypi:certifi@2023.7.22"));
    
    // Should link dependencies
    const requests = graph.nodes.get("pypi:requests@2.31.0");
    assert.ok(requests);
    assert.ok(requests.dependencies.includes("pypi:urllib3@2.0.4"));
    assert.ok(requests.dependencies.includes("pypi:certifi@2023.7.22"));
    
    // Dev deps should be transitive
    const pytest = graph.nodes.get("pypi:pytest@7.4.0");
    assert.ok(pytest);
    assert.strictEqual(pytest.dependencyType, "transitive");
  });
});

describe("parsePipfileLock", () => {
  test("parses Pipfile.lock", () => {
    const graph = parsePipfileLock(path.join(FIXTURES, "pypi/Pipfile.lock"));
    
    // Default dependencies
    assert.ok(graph.nodes.get("pypi:requests@2.31.0"));
    assert.strictEqual(
      graph.nodes.get("pypi:requests@2.31.0")?.dependencyType,
      "direct"
    );
    
    // Develop dependencies
    assert.ok(graph.nodes.get("pypi:pytest@7.4.0"));
    assert.strictEqual(
      graph.nodes.get("pypi:pytest@7.4.0")?.dependencyType,
      "transitive"
    );
  });

  test("throws on invalid Pipfile.lock", () => {
    assert.throws(
      () => parsePipfileLock(path.join(FIXTURES, "malformed/parser-empty-object.json")),
      /default.*develop/
    );
  });
});

