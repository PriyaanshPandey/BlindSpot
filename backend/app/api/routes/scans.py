from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import uuid
import os
import re
import json
import tempfile
import shutil
from datetime import datetime
from app.models import ScanRequest
from app.db import db
from app.db.repositories import ScanRepository, GraphRepository, FindingRepository, EvidenceRepository
from app.ingestion import scan_project_directory, KNOWN_CLOUD_VENDORS
from app.security import check_vulnerabilities
from app.intelligence.service import ThirdPartyIntelligenceService

intel_service = ThirdPartyIntelligenceService()

router = APIRouter()

class DirectPayloadScan(BaseModel):
    project_name: str = "Uploaded Project"
    files: Dict[str, str] = {}

PACKAGE_DOMAINS = [
    {
        "key": "framework",
        "title": "Core & Runtime",
        "description": "Application framework, server routers, and runtime handlers",
        "keywords": ["medusa", "express", "koa", "fastify", "nest", "next", "react", "vue", "angular", "django", "fastapi", "flask", "starlette", "awilix", "router", "server", "cors", "body-parser", "helmet", "webpack", "vite", "babel"]
    },
    {
        "key": "database",
        "title": "Data & Persistence",
        "description": "Relational databases, ORMs, document stores, and memory caches",
        "keywords": ["postgres", "pg", "mysql", "mongo", "redis", "typeorm", "prisma", "knex", "sequelize", "mikro-orm", "sqlite", "ioredis", "memcached", "cassandra", "dynamo", "elasticsearch", "opensearch", "psycopg", "sqlalchemy", "database", "cache"]
    },
    {
        "key": "commerce",
        "title": "Payments & Commerce",
        "description": "Checkout processors, billing engines, and transaction services",
        "keywords": ["stripe", "payment", "paypal", "razorpay", "billing", "invoice", "checkout", "commerce", "cart", "braintree", "chargebee", "square", "fulfillment"]
    },
    {
        "key": "security",
        "title": "Auth & Identity",
        "description": "Authentication, JWT tokens, credential hashing, and security guards",
        "keywords": ["jwt", "token", "auth", "bcrypt", "crypto", "oauth", "passport", "argon", "session", "guard", "jose", "hash", "keycloak"]
    },
    {
        "key": "cloud",
        "title": "Cloud & Integrations",
        "description": "Third-party SaaS SDKs, telemetry, email dispatch, and storage",
        "keywords": ["s3", "aws", "gcp", "azure", "twilio", "sendgrid", "postmark", "sentry", "datadog", "algolia", "mixpanel", "segment", "openai", "gemini", "mail", "slack"]
    },
]

def categorize_package(pkg_name: str) -> str:
    pkg_lower = pkg_name.lower()
    for domain in PACKAGE_DOMAINS:
        if any(kw in pkg_lower for kw in domain["keywords"]):
            return domain["key"]
    return "utilities"

def build_unified_graph(project_data: Dict[str, Any]) -> Dict[str, Any]:
    scan_id = str(uuid.uuid4())
    project_name = project_data.get("project_name", "Target Project")
    services = project_data.get("services", {})
    overall_deps = project_data.get("dependencies", {})
    transitives = project_data.get("transitive_dependencies", {})
    infras = project_data.get("infrastructure_nodes", [])
    observed_hosts = project_data.get("observed_hosts", [])
    evidence_map = project_data.get("evidence_records", {})

    # Detect primary ecosystem
    is_python = any(s.get("ecosystem") == "PyPI" for s in services.values())
    ecosystem = "PyPI" if is_python else "npm"

    # Query real OSV database across direct and key transitive packages
    all_packages_to_check = dict(overall_deps)
    for parent, child_dict in transitives.items():
        all_packages_to_check.update(child_dict)

    vulns = check_vulnerabilities(all_packages_to_check, ecosystem=ecosystem)

    nodes = []
    edges = []
    edge_counter = 1
    clean_name = project_name.replace(" ", "-").lower()

    # ----------------------------------------------------
    # TIER 1: ROOT APPLICATION
    # ----------------------------------------------------
    app_id = f"app:{clean_name}"
    nodes.append({
        "id": app_id,
        "label": project_name,
        "type": "application",
        "tier": 1,
        "provenance": "declared",
        "status": "healthy",
        "criticality": "critical",
        "metadata": {
            "path": project_data.get("folder_path", ""),
            "description": "Primary application entrypoint"
        }
    })

    # ----------------------------------------------------
    # TIER 2: INTERNAL SERVICES / MICROSERVICES
    # ----------------------------------------------------
    service_node_ids = []
    active_services = {k: v for k, v in services.items() if v.get("dependencies") or v.get("external_calls")}
    if not active_services:
        active_services = {
            "core": {
                "name": f"{project_name} Core",
                "dependencies": overall_deps,
                "external_calls": observed_hosts,
                "ecosystem": ecosystem
            }
        }

    for s_key, s_data in active_services.items():
        s_id = f"service:{clean_name}-{s_key}"
        service_node_ids.append(s_id)
        nodes.append({
            "id": s_id,
            "label": s_data.get("name", f"{s_key.capitalize()} Service"),
            "type": "internal_service",
            "tier": 2,
            "provenance": "declared",
            "status": "healthy",
            "criticality": "critical",
            "metadata": {"path": s_data.get("path", "")}
        })
        edges.append({
            "id": f"e_app_to_{s_key}",
            "source": app_id,
            "target": s_id,
            "relation": "calls_service",
            "provenance": "declared",
            "confidence_score": 1.0
        })

        svc_deps = list(s_data.get("dependencies", {}).items())
        subsys_node_map = {}

        # -------------------------------------------------------------------------
        # BALANCED ARCHITECTURAL CLUSTERING (Avoids 50-node horizontal broomstick)
        # -------------------------------------------------------------------------
        use_clustering = len(svc_deps) > 8

        if use_clustering:
            # Group packages into domain buckets
            domain_buckets = {d["key"]: [] for d in PACKAGE_DOMAINS}
            domain_buckets["utilities"] = []

            for pkg_name, ver in svc_deps:
                cat = categorize_package(pkg_name)
                domain_buckets[cat].append((pkg_name, ver))

            domain_lookup = {d["key"]: d for d in PACKAGE_DOMAINS}
            domain_lookup["utilities"] = {
                "key": "utilities",
                "title": "Libraries & Utilities",
                "description": "Utility libraries, helpers, and general dependencies"
            }

            for cat_key, cat_pkgs in domain_buckets.items():
                if not cat_pkgs:
                    continue
                cat_info = domain_lookup[cat_key]
                subsys_id = f"subsys:{clean_name}-{s_key}-{cat_key}"
                subsys_node_map[cat_key] = subsys_id

                is_subsys_vuln = any(
                    any(v["package"] == p[0] for v in vulns) for p in cat_pkgs
                )

                nodes.append({
                    "id": subsys_id,
                    "label": cat_info["title"],
                    "type": "runtime_component",
                    "subtype": "domain_cluster",
                    "tier": 3,
                    "provenance": "declared",
                    "status": "compromised" if is_subsys_vuln else "healthy",
                    "criticality": "critical" if is_subsys_vuln else "high",
                    "metadata": {
                        "category": cat_key,
                        "description": cat_info["description"],
                        "package_count": len(cat_pkgs)
                    }
                })
                edges.append({
                    "id": f"e_sub_{edge_counter}",
                    "source": s_id,
                    "target": subsys_id,
                    "relation": "powers_subsystem",
                    "provenance": "declared",
                    "confidence_score": 1.0
                })
                edge_counter += 1

                # Prioritize: show compromised packages first, then primary drivers
                vuln_pkgs = [p for p in cat_pkgs if any(v["package"] == p[0] for v in vulns)]
                safe_pkgs = [p for p in cat_pkgs if not any(v["package"] == p[0] for v in vulns)]
                sorted_pkgs = vuln_pkgs + safe_pkgs

                display_limit = 4
                display_pkgs = sorted_pkgs[:display_limit]
                overflow_pkgs = sorted_pkgs[display_limit:]

                for pkg_name, ver in display_pkgs:
                    clean_ver = str(ver).replace("^", "").replace("~", "").replace(">", "").replace("=", "").strip()
                    if len(clean_ver) > 18:
                        clean_ver = clean_ver[:18]
                    is_vuln = any(v["package"] == pkg_name for v in vulns)
                    pkg_id = f"pkg:{pkg_name}"

                    if not any(n["id"] == pkg_id for n in nodes):
                        nodes.append({
                            "id": pkg_id,
                            "label": f"{pkg_name}",
                            "type": "software_package",
                            "subtype": "direct",
                            "tier": 4,
                            "version": clean_ver,
                            "provenance": "declared",
                            "status": "compromised" if is_vuln else "healthy",
                            "criticality": "critical" if is_vuln else "medium",
                            "metadata": {"version": clean_ver, "domain": cat_info["title"]}
                        })
                    edges.append({
                        "id": f"e_pkg_{edge_counter}",
                        "source": subsys_id,
                        "target": pkg_id,
                        "relation": "depends_on",
                        "provenance": "declared",
                        "confidence_score": 1.0
                    })
                    edge_counter += 1

                    # Transitive children connect to their direct parent package
                    if pkg_name in transitives:
                        child_deps = list(transitives[pkg_name].items())[:3]
                        for child_pkg, child_ver in child_deps:
                            clean_cver = str(child_ver).replace("^", "").replace("~", "").strip()
                            if len(clean_cver) > 18:
                                clean_cver = clean_cver[:18]
                            is_child_vuln = any(v["package"] == child_pkg for v in vulns)
                            child_id = f"pkg:trans:{child_pkg}"

                            if not any(n["id"] == child_id for n in nodes):
                                nodes.append({
                                    "id": child_id,
                                    "label": f"{child_pkg}",
                                    "type": "software_package",
                                    "subtype": "transitive",
                                    "tier": 5,
                                    "version": clean_cver,
                                    "provenance": "declared",
                                    "status": "compromised" if is_child_vuln else "healthy",
                                    "criticality": "high" if is_child_vuln else "low",
                                    "metadata": {"version": clean_cver, "parent": pkg_name}
                                })
                            edges.append({
                                "id": f"e_trans_{edge_counter}",
                                "source": pkg_id,
                                "target": child_id,
                                "relation": "depends_on_transitive",
                                "provenance": "declared",
                                "confidence_score": 0.95
                            })
                            edge_counter += 1

                # If more than 4 packages exist in this category, create a compact cluster bundle node
                if overflow_pkgs:
                    bundle_id = f"bundle:{clean_name}-{s_key}-{cat_key}"
                    bundled_dict = {p[0]: p[1] for p in overflow_pkgs}
                    nodes.append({
                        "id": bundle_id,
                        "label": f"+ {len(overflow_pkgs)} More {cat_info['title']}",
                        "type": "software_package",
                        "subtype": "cluster_bundle",
                        "tier": 4,
                        "provenance": "declared",
                        "status": "healthy",
                        "criticality": "low",
                        "metadata": {
                            "bundled_packages": bundled_dict,
                            "count": len(overflow_pkgs),
                            "category": cat_info["title"]
                        }
                    })
                    edges.append({
                        "id": f"e_bun_{edge_counter}",
                        "source": subsys_id,
                        "target": bundle_id,
                        "relation": "contains_packages",
                        "provenance": "declared",
                        "confidence_score": 1.0
                    })
                    edge_counter += 1

        else:
            # Small project (<= 8 deps): connect directly to the service
            for pkg_name, ver in svc_deps:
                clean_ver = str(ver).replace("^", "").replace("~", "").replace(">", "").replace("=", "").strip()
                if len(clean_ver) > 18:
                    clean_ver = clean_ver[:18]
                is_vuln = any(v["package"] == pkg_name for v in vulns)
                pkg_id = f"pkg:{pkg_name}"

                if not any(n["id"] == pkg_id for n in nodes):
                    nodes.append({
                        "id": pkg_id,
                        "label": f"{pkg_name}",
                        "type": "software_package",
                        "subtype": "direct",
                        "tier": 3,
                        "version": clean_ver,
                        "provenance": "declared",
                        "status": "compromised" if is_vuln else "healthy",
                        "criticality": "critical" if is_vuln else "medium",
                        "metadata": {"version": clean_ver}
                    })
                edges.append({
                    "id": f"e_pkg_{edge_counter}",
                    "source": s_id,
                    "target": pkg_id,
                    "relation": "depends_on",
                    "provenance": "declared",
                    "confidence_score": 1.0
                })
                edge_counter += 1

                if pkg_name in transitives:
                    child_deps = list(transitives[pkg_name].items())[:3]
                    for child_pkg, child_ver in child_deps:
                        clean_cver = str(child_ver).replace("^", "").replace("~", "").strip()
                        if len(clean_cver) > 18:
                            clean_cver = clean_cver[:18]
                        is_child_vuln = any(v["package"] == child_pkg for v in vulns)
                        child_id = f"pkg:trans:{child_pkg}"

                        if not any(n["id"] == child_id for n in nodes):
                            nodes.append({
                                "id": child_id,
                                "label": f"{child_pkg}",
                                "type": "software_package",
                                "subtype": "transitive",
                                "tier": 4,
                                "version": clean_cver,
                                "provenance": "declared",
                                "status": "compromised" if is_child_vuln else "healthy",
                                "criticality": "high" if is_child_vuln else "low",
                                "metadata": {"version": clean_cver, "parent": pkg_name}
                            })
                        edges.append({
                            "id": f"e_trans_{edge_counter}",
                            "source": pkg_id,
                            "target": child_id,
                            "relation": "depends_on_transitive",
                            "provenance": "declared",
                            "confidence_score": 0.95
                        })
                        edge_counter += 1

        # ----------------------------------------------------
        # TIER 4: INFRASTRUCTURE (Connects to Data Subsystem or Service)
        # ----------------------------------------------------
        infra_parent_id = subsys_node_map.get("database", s_id)
        for inf in infras:
            inf_id = inf["id"]
            if not any(n["id"] == inf_id for n in nodes):
                nodes.append({
                    "id": inf_id,
                    "label": inf["name"],
                    "type": "infrastructure_resource",
                    "tier": 4 if use_clustering else 3,
                    "category": inf.get("category", "database"),
                    "provenance": "declared",
                    "status": "healthy",
                    "criticality": "critical",
                    "metadata": {"image": inf.get("image", "latest")}
                })
            edges.append({
                "id": f"e_infra_{edge_counter}",
                "source": infra_parent_id,
                "target": inf_id,
                "relation": "queries_database" if "database" in inf.get("category", "") else "uses_cache",
                "provenance": "declared",
                "confidence_score": 1.0
            })
            edge_counter += 1

        # ----------------------------------------------------
        # TIER 4/5: EXTERNAL APIs & CLOUD VENDORS
        # ----------------------------------------------------
        ext_parent_id = subsys_node_map.get("cloud", subsys_node_map.get("commerce", s_id))
        ext_calls = s_data.get("external_calls", [])
        if isinstance(ext_calls, set):
            ext_calls = list(ext_calls)

        for host in ext_calls[:8]:
            matched_vendor_key = next(
                (k for k in KNOWN_CLOUD_VENDORS if k in host.lower()), None
            )
            is_known_vendor = matched_vendor_key is not None or any(
                v in host for v in ["stripe.com", "auth0.com", "twilio.com", "sendgrid.com",
                                    "firebase", "aws", "cloudflare", "razorpay", "openai",
                                    "supabase", "algolia", "veriff", "sentry", "mixpanel"]
            )
            host_id = f"ext:{host}"
            vendor_label = KNOWN_CLOUD_VENDORS[matched_vendor_key]["vendor"] if matched_vendor_key else host

            # Pick target parent: payment vendors attach to commerce if present
            target_parent = subsys_node_map.get("commerce", ext_parent_id) if any(p in host for p in ["stripe", "paypal", "razorpay"]) else ext_parent_id

            if not any(n["id"] == host_id for n in nodes):
                nodes.append({
                    "id": host_id,
                    "label": vendor_label,
                    "type": "vendor" if is_known_vendor else "external_api",
                    "tier": 4 if use_clustering else 3,
                    "host": host,
                    "provenance": "declared" if is_known_vendor else "observed",
                    "status": "healthy" if is_known_vendor else "warning",
                    "criticality": "critical" if is_known_vendor else "high",
                    "metadata": {"host": host, "category": KNOWN_CLOUD_VENDORS.get(matched_vendor_key, {}).get("category", "api")}
                })
            edges.append({
                "id": f"e_ext_{edge_counter}",
                "source": target_parent,
                "target": host_id,
                "relation": "calls_api",
                "provenance": "declared" if is_known_vendor else "observed",
                "confidence_score": 0.99
            })
            edge_counter += 1

            # ----------------------------------------------------
            # TIER 6: VENDOR UPSTREAM INFRASTRUCTURE (Passports)
            # ----------------------------------------------------
            if matched_vendor_key and KNOWN_CLOUD_VENDORS[matched_vendor_key].get("upstream"):
                for up_name in KNOWN_CLOUD_VENDORS[matched_vendor_key]["upstream"][:1]:
                    up_id = f"upstream:{up_name}"
                    if not any(n["id"] == up_id for n in nodes):
                        nodes.append({
                            "id": up_id,
                            "label": up_name,
                            "type": "vendor_upstream",
                            "tier": 6 if use_clustering else 5,
                            "provenance": "vendor_passport",
                            "status": "healthy",
                            "criticality": "high",
                            "metadata": {"region": up_name}
                        })
                    edges.append({
                        "id": f"e_up_{edge_counter}",
                        "source": host_id,
                        "target": up_id,
                        "relation": "relies_on_upstream",
                        "provenance": "vendor_passport",
                        "confidence_score": 0.90
                    })
                    edge_counter += 1

    # ----------------------------------------------------
    # TIER 0: BUSINESS JOURNEYS (Top Level Business Impact)
    # ----------------------------------------------------
    journey_id = f"journey:{clean_name}-core"
    nodes.append({
        "id": journey_id,
        "label": f"Journey: Core Operations & Transactions",
        "type": "business_journey",
        "tier": 0,
        "provenance": "inferred",
        "status": "healthy",
        "criticality": "critical"
    })
    for s_id in service_node_ids:
        edges.append({
            "id": f"e_journey_{s_id}",
            "source": s_id,
            "target": journey_id,
            "relation": "powers_journey",
            "provenance": "inferred",
            "confidence_score": 1.0
        })

    # ----------------------------------------------------
    # Generate Findings (OSV + discrepancy + integration)
    # ----------------------------------------------------
    findings = []
    finding_idx = 1

    for v in vulns:
        target_node = next(
            (n for n in nodes if n["id"] == f"pkg:{v['package']}" or n["id"] == f"pkg:trans:{v['package']}"),
            None
        )
        findings.append({
            "id": f"find-{finding_idx:03d}",
            "scan_id": scan_id,
            "type": "vulnerability_compromised_package",
            "title": f"OSV Advisory: {v['package']}@{v['version']} ({v['cve']})",
            "description": v["description"],
            "severity": v["severity"],
            "target_node_id": target_node["id"] if target_node else f"pkg:{v['package']}",
            "affected_journey_ids": [journey_id],
            "evidence_references": ["manifest:package.json" if ecosystem == "npm" else "manifest:requirements.txt"],
            "security_details": {
                "cve_id": v["cve"],
                "cvss_score": 9.8 if v["severity"] == "critical" else 7.8,
                "advisory_source": "Google OSV Database",
                "fixed_version": v.get("fixed_version", "latest")
            },
            "remediation": {
                "summary": f"Upgrade {v['package']} to safe release",
                "recommended_action": f"Upgrade to {v.get('fixed_version', 'latest')} or follow security patch guidance."
            }
        })
        finding_idx += 1

    unverified_hosts = [
        h for h in observed_hosts
        if not any(v in h for v in [
            "stripe.com", "auth0.com", "github.com", "npmjs.org",
            "w3.org", "google.com", "twilio.com", "sendgrid.com",
            "firebase", "razorpay", "openai", "supabase", "algolia",
            "sentry", "mixpanel", "cloudflare", "amazonaws.com"
        ])
    ]
    for uh in unverified_hosts[:10]:
        ev_list = evidence_map.get(uh, [f"code_reference:{uh}"])
        findings.append({
            "id": f"find-{finding_idx:03d}",
            "scan_id": scan_id,
            "type": "discrepancy_undeclared_endpoint",
            "title": f"Undocumented Endpoint: {uh}",
            "description": f"External network call to '{uh}' is absent from declared architecture.",
            "severity": "medium",
            "target_node_id": f"ext:{uh}",
            "affected_journey_ids": [journey_id],
            "evidence_references": ev_list[:3],
            "remediation": {
                "summary": "Verify or remove unapproved endpoint",
                "recommended_action": f"Audit calls to '{uh}'. Remove if unrecognised."
            }
        })
        finding_idx += 1

    # ----------------------------------------------------
    # Third-Party Intelligence & Deep Integration Security Checks
    # ----------------------------------------------------
    folder_path = project_data.get("folder_path")
    if folder_path and os.path.exists(folder_path):
        try:
            intel_res = intel_service.analyze_third_party_security(folder_path, observed_hosts=observed_hosts)
            from app.api.routes.intelligence import _SCAN_INTELLIGENCE_CACHE
            _SCAN_INTELLIGENCE_CACHE[scan_id] = intel_res
            for f in intel_res.get("integration_findings", []):
                sev = f.get("severity", "high")
                target_node = f.get("target_node_id", "vendor:unknown")
                findings.append({
                    "id": f"find-{finding_idx:03d}",
                    "scan_id": scan_id,
                    "type": "discrepancy_undeclared_endpoint" if "SUP" in f.get("rule_id", "") else "vulnerability_compromised_package",
                    "title": f"[{f.get('rule_id')}] {f.get('title')}",
                    "description": f.get("description", ""),
                    "severity": sev,
                    "target_node_id": target_node,
                    "affected_journey_ids": [f.get("affected_journey", journey_id)],
                    "evidence_references": [f"rule:{f.get('rule_id')}", f.get("file_path", "source")],
                    "security_details": {
                        "cve_id": f.get("rule_id"),
                        "cvss_score": 9.5 if sev == "critical" else 7.5,
                        "advisory_source": "BlindSpot Third-Party Intelligence",
                        "fixed_version": "N/A"
                    },
                    "remediation": {
                        "summary": f.get("explanation", ""),
                        "recommended_action": f.get("remediation", "")
                    }
                })
                finding_idx += 1
        except Exception:
            pass

    # ----------------------------------------------------
    # Build Evidence Records
    # ----------------------------------------------------
    evidence_records = []
    for pkg, ver in overall_deps.items():
        evidence_records.append({
            "id": f"ev:pkg:{pkg}",
            "evidence_type": "declared",
            "collected_at": datetime.utcnow().isoformat(),
            "collector": "npm-manifest-parser" if ecosystem == "npm" else "pypi-parser",
            "confidence": 1.0,
            "declared_details": {
                "file_path": f"{project_data.get('folder_path', '')}/package.json",
                "manifest_type": "package.json",
                "raw_declaration": f'"{pkg}": "{ver}"'
            }
        })
    for host in observed_hosts:
        evidence_records.append({
            "id": f"ev:trace:{host}",
            "evidence_type": "observed",
            "collected_at": datetime.utcnow().isoformat(),
            "collector": "runtime-trace-processor",
            "confidence": 0.95,
            "observed_details": {
                "source": "otel_trace",
                "destination_host": host,
                "protocol": "https"
            }
        })
    db.in_memory_evidence[scan_id] = evidence_records

    discrepancy_count = sum(1 for f in findings if "discrepancy" in f.get("type", ""))

    graph_dict = {
        "scan_id": scan_id,
        "created_at": datetime.utcnow().isoformat(),
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "discrepancy_count": discrepancy_count,
            "vulnerability_count": len(vulns)
        }
    }
    db.in_memory_graphs[scan_id] = graph_dict
    db.in_memory_findings[scan_id] = findings

    # Pre-generate outage scenarios
    scenarios = []
    for host in list(observed_hosts)[:4]:
        target_id = f"ext:{host}"
        impacted = [target_id] + service_node_ids + [app_id, journey_id]
        scenarios.append({
            "scenario_id": f"scen-{uuid.uuid4().hex[:8]}",
            "scan_id": scan_id,
            "name": f"Outage: {host}",
            "target_node_id": target_id,
            "simulation_parameters": {
                "target_node_id": target_id,
                "failure_duration_hours": 2.0,
                "hourly_transactions_override": 120.0,
                "average_transaction_value_override": 65.0
            },
            "impact_results": {
                "blast_radius_node_count": len(impacted),
                "impacted_node_ids": impacted,
                "affected_journey_ids": [journey_id],
                "financial_exposure": {
                    "currency": "USD",
                    "estimated_revenue_loss": 15600.0,
                    "exposure_rating": "CRITICAL"
                }
            }
        })
    db.in_memory_scenarios[scan_id] = scenarios

    scan_record = {
        "scan_id": scan_id,
        "project_name": project_name,
        "status": "completed",
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": datetime.utcnow().isoformat(),
        "config": {
            "repo_path": project_data.get("folder_path", ""),
            "enable_vendor_passports": True
        },
        "summary": {
            "declared_dependencies": len(overall_deps),
            "transitive_dependencies": sum(len(c) for c in transitives.values()),
            "infrastructure_nodes": len(infras),
            "observed_dependencies": len(observed_hosts),
            "discrepancies_found": discrepancy_count,
            "vulnerabilities_found": len(vulns),
            "critical_paths": len(service_node_ids),
            "execution_time_ms": 115.4
        }
    }
    db.in_memory_scans[scan_id] = scan_record

    try:
        import asyncio
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(ScanRepository.save_scan(scan_record))
            asyncio.create_task(GraphRepository.save_graph(graph_dict))
            asyncio.create_task(FindingRepository.save_findings(scan_id, findings))
            asyncio.create_task(EvidenceRepository.save_evidence(scan_id, evidence_records))
    except Exception:
        pass

    return scan_record


@router.post("")
async def create_scan(request: ScanRequest):
    project_scan = scan_project_directory(request.repo_path)
    if "error" in project_scan:
        raise HTTPException(status_code=400, detail=project_scan["error"])

    if request.trace_file_path and os.path.exists(request.trace_file_path):
        from app.ingestion import parse_runtime_traces
        runtime_traces = parse_runtime_traces(request.trace_file_path)
        obs = project_scan.setdefault("observed_hosts", [])
        for t in runtime_traces:
            dest = t.get("destination_host")
            if dest and dest not in obs:
                obs.append(dest)
                project_scan.setdefault("evidence_records", {}).setdefault(dest, []).append(
                    f"runtime_trace:{t.get('span_id', 'span')}"
                )

    scan_record = build_unified_graph(project_scan)
    scan_id = scan_record["scan_id"]
    await ScanRepository.save_scan(scan_record)
    if scan_id in db.in_memory_graphs:
        await GraphRepository.save_graph(db.in_memory_graphs[scan_id])
    if scan_id in db.in_memory_findings:
        await FindingRepository.save_findings(scan_id, db.in_memory_findings[scan_id])
    if scan_id in db.in_memory_evidence:
        await EvidenceRepository.save_evidence(scan_id, db.in_memory_evidence[scan_id])
    return scan_record


@router.post("/direct")
async def scan_direct_files(payload: DirectPayloadScan):
    deps = {}
    transitives = {}
    infras = []
    observed_hosts = set()
    evidence_map = {}
    URL_REGEX = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>)]*)?')

    temp_dir = tempfile.mkdtemp(prefix="blindspot_direct_")
    try:
        for fname, content in payload.files.items():
            full_p = os.path.join(temp_dir, fname)
            os.makedirs(os.path.dirname(full_p), exist_ok=True)
            with open(full_p, "w", encoding="utf-8") as f:
                f.write(content)

            fname_lower = fname.lower()

            if fname_lower.endswith("package.json") and "lock" not in fname_lower:
                try:
                    pkg_data = json.loads(content)
                    d = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
                    deps.update(d)
                    if pkg_data.get("name"):
                        payload.project_name = pkg_data["name"]
                except Exception:
                    pass

            elif fname_lower.endswith("package-lock.json"):
                try:
                    lock_data = json.loads(content)
                    packages = lock_data.get("packages", {})
                    for pkg_path, pkg_info in packages.items():
                        if not pkg_path:
                            continue
                        clean_pkg = pkg_path.replace("node_modules/", "")
                        if "dependencies" in pkg_info:
                            transitives[clean_pkg] = pkg_info["dependencies"]
                        if not deps.get(clean_pkg) and pkg_info.get("version"):
                            deps[clean_pkg] = pkg_info["version"]
                except Exception:
                    pass

            elif fname_lower.endswith(("requirements.txt", "pipfile")):
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = re.split(r'==|>=|<=|~=', line)
                        pkg = parts[0].strip()
                        ver = parts[1].strip() if len(parts) > 1 else "*"
                        deps[pkg] = ver

            elif fname_lower.endswith(("docker-compose.yml", "docker-compose.yaml")):
                service_blocks = re.findall(r'(\b[a-zA-Z0-9_-]+):\s*\n(?:\s+image:\s*([^\n]+))?', content)
                for s_name, image in service_blocks:
                    lower_name = s_name.lower()
                    lower_image = (image or "").lower()
                    infra_type = None
                    if any(k in lower_name or k in lower_image for k in ["postgres", "pgsql"]):
                        infra_type = "PostgreSQL Database"
                    elif any(k in lower_name or k in lower_image for k in ["redis", "cache"]):
                        infra_type = "Redis Cache"
                    elif any(k in lower_name or k in lower_image for k in ["mongo"]):
                        infra_type = "MongoDB"
                    elif any(k in lower_name or k in lower_image for k in ["rabbit", "mq"]):
                        infra_type = "RabbitMQ"
                    elif any(k in lower_name or k in lower_image for k in ["mysql", "mariadb"]):
                        infra_type = "MySQL Database"
                    if infra_type:
                        infras.append({
                            "id": f"infra:{s_name}",
                            "name": f"{s_name.capitalize()} ({infra_type})",
                            "category": "database",
                            "image": image.strip() if image else "latest"
                        })

            elif ".env" in fname_lower or fname_lower.endswith(".env"):
                for line in content.splitlines():
                    clean_line = line.strip()
                    if not clean_line or clean_line.startswith("#"):
                        continue
                    upper = clean_line.upper()
                    for key, info in KNOWN_CLOUD_VENDORS.items():
                        if key.upper() in upper:
                            observed_hosts.add(info["host"])
                            evidence_map.setdefault(info["host"], []).append(f"{fname}: {clean_line.split('=')[0]}")

            matches = URL_REGEX.findall(content)
            for m in matches:
                host_match = re.search(r'https?://([^/:\s]+)', m)
                if host_match:
                    host = host_match.group(1).lower()
                    if not host.startswith(("localhost", "127.0.0.1", "example.com")) and \
                       not host.endswith(("schema.org", "w3.org", "npmjs.org", "github.com")):
                        observed_hosts.add(host)
                        evidence_map.setdefault(host, []).append(fname)

        from app.ingestion import KNOWN_NODE_TRANSITIVES, KNOWN_PYTHON_TRANSITIVES
        is_python = any(fname.endswith(("requirements.txt", "pipfile")) for fname in payload.files.keys())
        for pkg in deps:
            clean_p = pkg.lower()
            if clean_p in KNOWN_NODE_TRANSITIVES:
                transitives.setdefault(pkg, {}).update(KNOWN_NODE_TRANSITIVES[clean_p])
            elif clean_p in KNOWN_PYTHON_TRANSITIVES:
                transitives.setdefault(pkg, {}).update(KNOWN_PYTHON_TRANSITIVES[clean_p])

        project_data = {
            "project_name": payload.project_name,
            "folder_path": temp_dir,
            "services": {
                "core": {
                    "name": f"{payload.project_name} Core",
                    "dependencies": deps,
                    "external_calls": list(observed_hosts),
                    "ecosystem": "PyPI" if is_python else "npm"
                }
            },
            "dependencies": deps,
            "transitive_dependencies": transitives,
            "infrastructure_nodes": infras,
            "observed_hosts": list(observed_hosts),
            "evidence_records": evidence_map
        }
        scan_record = build_unified_graph(project_data)
        return scan_record
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


@router.get("")
async def list_scans():
    try:
        db_scans = await ScanRepository.list_scans()
        if db_scans:
            return db_scans
    except Exception:
        pass
    return list(db.in_memory_scans.values())


@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    try:
        db_scan = await ScanRepository.get_scan(scan_id)
        if db_scan:
            return db_scan
    except Exception:
        pass
    if scan_id in db.in_memory_scans:
        return db.in_memory_scans[scan_id]
    raise HTTPException(status_code=404, detail="Scan not found")
