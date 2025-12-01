/**
 * Unit tests for .scanignore functionality.
 *
 * Tests ignore file loading, parsing, and vulnerability filtering.
 */

import { test, describe } from "node:test";
import assert from "node:assert";
import path from "node:path";
import { loadIgnoreList, filterIgnored } from "../src/ignore.js";
import { Vulnerability } from "../src/clients/types.js";

const FIXTURES = path.join(process.cwd(), "tests/fixtures");

describe("loadIgnoreList", () => {
  test("loads IDs from explicit path", () => {
    const ignored = loadIgnoreList(
      "/fake/path/package-lock.json",
      path.join(FIXTURES, "scanignore/sample.scanignore")
    );

    assert.strictEqual(ignored.size, 3);
    assert.ok(ignored.has("GHSA-jf85-cpcp-j695"));
    assert.ok(ignored.has("CVE-2021-23337"));
    assert.ok(ignored.has("PYSEC-2021-76"));
  });

  test("strips inline comments", () => {
    const ignored = loadIgnoreList(
      "/fake/path/package-lock.json",
      path.join(FIXTURES, "scanignore/sample.scanignore")
    );

    // Should NOT have the comment text
    assert.ok(!ignored.has("PYSEC-2021-76   # Known false positive"));
    // Should have just the ID
    assert.ok(ignored.has("PYSEC-2021-76"));
  });

  test("falls back to cwd .scanignore when scanned file dir has none", () => {
    // When scanned file's dir has no .scanignore, falls back to cwd
    // Our cwd has a .scanignore, so it should load that
    const ignored = loadIgnoreList("/nonexistent/path/package-lock.json");
    assert.ok(ignored.size > 0, "Should fall back to cwd .scanignore");
  });
});

describe("filterIgnored", () => {
  const sampleVulns = (): Map<string, Vulnerability[]> => {
    const map = new Map<string, Vulnerability[]>();

    map.set("npm:lodash@4.17.20", [
      {
        id: "GHSA-jf85-cpcp-j695",
        aliases: ["CVE-2021-23337"],
        summary: "Prototype Pollution in lodash",
      },
      {
        id: "GHSA-other-vuln",
        summary: "Another vulnerability",
      },
    ]);

    map.set("npm:express@4.18.2", [
      {
        id: "GHSA-express-vuln",
        summary: "Express vulnerability",
      },
    ]);

    return map;
  };

  test("filters out vulnerabilities by primary ID", () => {
    const vulns = sampleVulns();
    const ignored = new Set(["GHSA-jf85-cpcp-j695"]);

    const { filtered, ignoredCount, ignoredIds } = filterIgnored(vulns, ignored);

    assert.strictEqual(ignoredCount, 1);
    assert.deepStrictEqual(ignoredIds, ["GHSA-jf85-cpcp-j695"]);
    const lodashVulns = filtered.get("npm:lodash@4.17.20");
    assert.strictEqual(lodashVulns?.length, 1);
    assert.strictEqual(lodashVulns?.[0].id, "GHSA-other-vuln");
  });

  test("filters out vulnerabilities by alias (CVE)", () => {
    const vulns = sampleVulns();
    const ignored = new Set(["CVE-2021-23337"]);

    const { filtered, ignoredCount, ignoredIds } = filterIgnored(vulns, ignored);

    assert.strictEqual(ignoredCount, 1);
    assert.deepStrictEqual(ignoredIds, ["CVE-2021-23337"]);
    const lodashVulns = filtered.get("npm:lodash@4.17.20");
    assert.strictEqual(lodashVulns?.length, 1);
  });

  test("returns original vulns when ignore set is empty", () => {
    const vulns = sampleVulns();
    const ignored = new Set<string>();

    const { filtered, ignoredCount, ignoredIds } = filterIgnored(vulns, ignored);

    assert.strictEqual(ignoredCount, 0);
    assert.deepStrictEqual(ignoredIds, []);
    assert.strictEqual(filtered.get("npm:lodash@4.17.20")?.length, 2);
  });

  test("removes package from vulnerable list when all vulns ignored", () => {
    const vulns = sampleVulns();
    const ignored = new Set(["GHSA-express-vuln"]);

    const { filtered, ignoredCount, ignoredIds } = filterIgnored(vulns, ignored);

    assert.strictEqual(ignoredCount, 1);
    assert.deepStrictEqual(ignoredIds, ["GHSA-express-vuln"]);
    const expressVulns = filtered.get("npm:express@4.18.2");
    assert.strictEqual(expressVulns?.length, 0);
  });
});

