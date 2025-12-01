/**
 * Client for GHSA (GitHub Security Advisory) database.
 *
 * Uses GraphQL API to query per-package vulnerabilities and matches versions client-side.
 * The REST API does not support batch queries, instead returning ALL advisories for an ecosystem.
 *
 * Note: GraphQL API requires authentication (REST allows unauthenticated access).
 * Export as environment variable (`GITHUB_TOKEN`) or pass as CLI flag (`--github-token`).
 *
 * Ref: https://docs.github.com/en/graphql/reference/objects#securityvulnerability
 */

import { graphql } from "@octokit/graphql";
import * as semver from "semver";
import { DependencyNode, PackageRegistry } from "../types";
import { Vulnerability } from "./types";

// GraphQL ecosystem enum values
type GhsaEcosystem = "NPM" | "PIP" | "RUBYGEMS" | "MAVEN" | "NUGET" | "COMPOSER" | "GO" | "RUST" | "ERLANG" | "ACTIONS" | "PUB" | "SWIFT";

function toGhsaEcosystem(registry: PackageRegistry): GhsaEcosystem {
    switch (registry) {
        case "npm": return "NPM";
        case "pypi": return "PIP";
    }
}

function toAlias(name: string, index: number): string {
    return `pkg_${index}_${name.replace(/[^a-zA-Z0-9]/g, "_")}`;
}

interface VulnerabilityNode {
    advisory: {
        ghsaId: string;
        summary: string;
        severity: string;
        identifiers: Array<{ type: string; value: string }>;
        references: Array<{ url: string }>;
    };
    vulnerableVersionRange: string;
    firstPatchedVersion: { identifier: string } | null;
}

interface GraphQLResponse {
    [alias: string]: {
        nodes: VulnerabilityNode[];
    };
}

/**
 * Check dependencies for vulnerabilities in GHSA database using GraphQL API.
 * Queries per-package using aliases, avoiding REST API's ecosystem-level filtering.
 */
export async function checkGhsaVulnerabilities(
    deps: DependencyNode[],
    token?: string,
): Promise<Map<string, Vulnerability[]>> {
    const results = new Map<string, Vulnerability[]>();
    const authToken = token || process.env.GITHUB_TOKEN;

    if (!authToken) {
        console.log("\n❌ GitHub GraphQL API requires authentication.");
        console.log("   Use --github-token <token> or set GITHUB_TOKEN env var.\n");
        for (const dep of deps) {
            results.set(dep.id, []);
        }
        return results;
    }

    const gql = graphql.defaults({
        headers: {
            authorization: `token ${authToken}`,
        },
    });

    const byRegistry = new Map<PackageRegistry, DependencyNode[]>();
    for (const dep of deps) {
        const list = byRegistry.get(dep.registry) || [];
        list.push(dep);
        byRegistry.set(dep.registry, list);
    }

    for (const [registry, registryDeps] of byRegistry) {
        const ecosystem = toGhsaEcosystem(registry);

        const uniquePackages = [...new Set(registryDeps.map(d => d.name))];

        if (uniquePackages.length === 0) continue;

        const queryParts = uniquePackages.map((pkg, i) => {
            const alias = toAlias(pkg, i);
            return `
        ${alias}: securityVulnerabilities(ecosystem: ${ecosystem}, package: "${pkg}", first: 100) {
          nodes {
            advisory {
              ghsaId
              summary
              severity
              identifiers { type value }
              references { url }
            }
            vulnerableVersionRange
            firstPatchedVersion { identifier }
          }
        }
      `;
        });

        const query = `query { ${queryParts.join("\n")} }`;

        try {
            const response = await gql<GraphQLResponse>(query);

            for (const dep of registryDeps) {
                const alias = toAlias(dep.name, uniquePackages.indexOf(dep.name));
                const vulnNodes = response[alias]?.nodes || [];

                const matching: Vulnerability[] = [];
                const seenIds = new Set<string>();

                for (const node of vulnNodes) {
                    if (seenIds.has(node.advisory.ghsaId)) continue;

                    if (isVersionAffected(dep.version, node.vulnerableVersionRange)) {
                        seenIds.add(node.advisory.ghsaId);
                        // Extract CVE and other aliases from identifiers
                        const aliases = node.advisory.identifiers
                            ?.filter(id => id.type !== "GHSA")
                            .map(id => id.value);
                        matching.push({
                            id: node.advisory.ghsaId,
                            aliases: aliases?.length ? aliases : undefined,
                            summary: node.advisory.summary,
                            severity: node.advisory.severity
                                ? [{ type: "GHSA", score: node.advisory.severity }]
                                : undefined,
                            references: node.advisory.references?.map(ref => ({
                                type: "WEB",
                                url: ref.url,
                            })),
                            fixedIn: node.firstPatchedVersion?.identifier,
                        });
                    }
                }

                results.set(dep.id, matching);
            }
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            console.warn(`⚠️ GHSA query failed for ${registry}: ${message}`);
            for (const dep of registryDeps) {
                results.set(dep.id, []);
            }
        }
    }

    return results;
}

// Convert GHSA version range to SemVer-compatible range.
function toSemverRange(ghsaRange: string): string {
    return ghsaRange
        .split(",")
        .map(part => part.trim().replace(/\s+/g, ""))
        .join(" ");
}

/**
 * Check if a version falls within the GHSA vulnerable range using proper SemVer.
 */
function isVersionAffected(version: string, range: string | null | undefined): boolean {
    if (!range) return false;

    const cleanVersion = semver.clean(version) || version;

    if (!semver.valid(cleanVersion)) return false;

    try {
        const semverRange = toSemverRange(range);
        return semver.satisfies(cleanVersion, semverRange);
    } catch {
        return range.includes(version);
    }
}
