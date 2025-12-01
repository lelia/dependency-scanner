/**
 * Client for GHSA (GitHub Security Advisory) database.
 *
 * Uses GraphQL instead of REST API to query per-package, similar to OSV.dev batch query endpoint.
 * The REST API returns *all* advisories for an ecosystem, and would require client-side filtering.
 *
 * GitHub token optional but recommended to increase rate limits from 60 reqs/hr to 5000 reqs/hr.
 * Usage: Export as environment variable (`GITHUB_TOKEN`) or pass as CLI flag (`--github-token`).
 *
 * Ref: https://docs.github.com/en/graphql/reference/objects#securityvulnerability
 */

import { graphql } from "@octokit/graphql";
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
    const authToken = token || process.env.GITHUB_TOKEN;

    if (!authToken) {
        console.warn("⚠️ No GitHub token provided. GHSA queries limited to 60 req/hr.");
        console.warn("Use --github-token or set GITHUB_TOKEN for higher rate limits.\n");
    }

    const gql = graphql.defaults({
        headers: {
            authorization: authToken ? `token ${authToken}` : "",
        },
    });

    const results = new Map<string, Vulnerability[]>();

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

                for (const node of vulnNodes) {
                    if (isVersionAffected(dep.version, node.vulnerableVersionRange)) {
                        matching.push({
                            id: node.advisory.ghsaId,
                            summary: node.advisory.summary,
                            severity: node.advisory.severity
                                ? [{ type: "GHSA", score: node.advisory.severity }]
                                : undefined,
                            references: node.advisory.references?.map(ref => ({
                                type: "WEB",
                                url: ref.url,
                            })),
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

/**
 * Basic check for whether a package version falls within the affected range.
 * 
 * TODO: Use proper SemVer library for more accurate matching.
 */
function isVersionAffected(version: string, range: string | null | undefined): boolean {
    if (!range) return false;

    if (range.includes(version)) return true;
    if (range === "< " + version) return false;

    return range.startsWith("<") || range.includes(", <");
}
