"""
Discovery Result & Orchestrator Subsystem [Role A]:
Normalizes all static (NPM, Composer) and runtime (OTel traces) inputs into a unified
DiscoveryResult structure.
Strictly adheres to contracts/graph-schema.json and contracts/evidence-schema.json,
establishing Consumer -> Dependency edge direction and bidirectional evidence references.
"""

import os
import uuid
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

from app.ingestion.npm_parser import parse_package_lock_json, parse_package_json_detailed
from app.ingestion.composer_parser import parse_composer_lock, parse_composer_json
from app.ingestion.trace_normalizer import parse_runtime_traces, normalize_runtime_traces
from app.security import check_vulnerabilities

logger = logging.getLogger("hdx.ingestion.discovery")


@dataclass
class DiscoveryResult:
    """
    Standard discovery output container passed from Person A (Ingestion)
    to Person B (Graph Engine & Reconciliation).
    """
    project_name: str
    scan_id: str
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    coverage: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_name": self.project_name,
            "scan_id": self.scan_id,
            "created_at": self.created_at,
            "nodes": self.nodes,
            "edges": self.edges,
            "evidence": self.evidence,
            "coverage": self.coverage,
            "warnings": self.warnings
        }

    def to_graph_schema_payload(self) -> Dict[str, Any]:
        """Returns payload strictly adhering to contracts/graph-schema.json."""
        # Provisional discrepancy count is 0. Authoritative discrepancy determination requires
        # reconciliation against declared/deployed information, which is performed by Person B.
        discrepancy_count = 0
        vulnerability_count = sum(1 for n in self.nodes if n.get("status") == "compromised")

        return {
            "scan_id": self.scan_id,
            "created_at": self.created_at,
            "metadata": {
                "target_name": self.project_name,
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "discrepancy_count": discrepancy_count,
                "vulnerability_count": vulnerability_count
            },
            "nodes": self.nodes,
            "edges": self.edges
        }


def discover_project(
    repo_path: str,
    trace_file_path: Optional[str] = None,
    scan_id: Optional[str] = None
) -> DiscoveryResult:
    """
    Orchestrates dependency discovery across NPM manifests, Composer manifests, and runtime traces.
    Produces schema-compliant nodes, edges, and evidence.
    """
    current_scan_id = scan_id or str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    evidence_records: List[Dict[str, Any]] = []
    warnings: List[str] = []
    manifests_found: List[str] = []

    seen_node_ids: Set[str] = set()

    # Determine Project Name and Manifest Version
    project_name = os.path.basename(os.path.abspath(repo_path))
    app_version: Optional[str] = None

    pkg_json_path = os.path.join(repo_path, "package.json")
    if os.path.exists(pkg_json_path):
        pkg_manifest = parse_package_json_detailed(pkg_json_path)
        if pkg_manifest.get("name") and pkg_manifest["name"] != "unknown":
            project_name = pkg_manifest["name"]
        if pkg_manifest.get("version") and pkg_manifest["version"] != "unknown":
            app_version = pkg_manifest["version"]

    composer_json_path = os.path.join(repo_path, "composer.json")
    if not app_version and os.path.exists(composer_json_path):
        composer_manifest = parse_composer_json(composer_json_path)
        if composer_manifest.get("version"):
            app_version = composer_manifest["version"]

    app_node_id = f"app:{project_name}"
    nodes.append({
        "id": app_node_id,
        "label": project_name,
        "type": "application",
        "subtype": "root_project",
        "version": app_version,
        "provenance": "declared",
        "status": "healthy",
        "criticality": "critical",
        "metadata": {"repo_path": repo_path}
    })
    seen_node_ids.add(app_node_id)

    # -------------------------------------------------------------
    # 1. NPM Ingestion (package.json + package-lock.json)
    # -------------------------------------------------------------
    pkg_lock_path = os.path.join(repo_path, "package-lock.json")
    if os.path.exists(pkg_json_path) or os.path.exists(pkg_lock_path):
        manifests_found.append("npm")

        npm_ev_id = f"ev:manifest:npm:{current_scan_id[:8]}"
        evidence_records.append({
            "id": npm_ev_id,
            "evidence_type": "declared",
            "collected_at": now_iso,
            "collector": "npm-manifest-parser",
            "confidence": 1.0,
            "declared_details": {
                "file_path": pkg_lock_path if os.path.exists(pkg_lock_path) else pkg_json_path,
                "manifest_type": "package-lock.json" if os.path.exists(pkg_lock_path) else "package.json",
                "raw_declaration": f"Project: {project_name}"
            }
        })

        if os.path.exists(pkg_lock_path):
            npm_result = parse_package_lock_json(
                pkg_lock_path,
                package_json_path=pkg_json_path,
                root_app_id=app_node_id
            )
            warnings.extend(npm_result.inconsistencies)
            warnings.extend(npm_result.warnings)

            # Match each concrete package instance and version independently
            pkg_items = [
                {"name": pkg.name, "version": pkg.version, "path": pkg.path}
                for pkg in npm_result.packages.values()
            ]
            vuln_findings = check_vulnerabilities(pkg_items, ecosystem="npm")
            vuln_map = {(f["package"], f.get("path")): f for f in vuln_findings}

            for pkg in npm_result.packages.values():
                vuln_entry = vuln_map.get((pkg.name, pkg.path))
                is_compromised = vuln_entry is not None
                status = "compromised" if is_compromised else "healthy"
                criticality = "critical" if is_compromised else ("high" if pkg.is_direct else "medium")

                node_meta = {
                    "ecosystem": "npm",
                    "path": pkg.path,
                    "is_direct": pkg.is_direct,
                    "is_dev": pkg.is_dev,
                    "resolved": pkg.resolved,
                }
                if is_compromised:
                    node_meta["vulnerability"] = vuln_entry

                nodes.append({
                    "id": pkg.id,
                    "label": f"npm:{pkg.name}@{pkg.version}",
                    "type": "software_package",
                    "subtype": "npm",
                    "version": pkg.version,
                    "provenance": "declared",
                    "status": status,
                    "criticality": criticality,
                    "metadata": node_meta
                })
                seen_node_ids.add(pkg.id)

            # NPM Edges: Consumer -> Dependency
            for edge in npm_result.dependency_edges:
                src = app_node_id if edge["source"].startswith("app:") else edge["source"]
                edge_id = f"edge:npm:{src}->{edge['target']}"
                edges.append({
                    "id": edge_id,
                    "source": src,
                    "target": edge["target"],
                    "relation": edge["relation"],
                    "provenance": "declared",
                    "confidence_score": 1.0,
                    "evidence_ids": [npm_ev_id],
                    "metadata": {
                        "ecosystem": "npm",
                        "consumer": edge.get("consumer_name"),
                        "dependency": edge.get("dependency_name")
                    }
                })
        elif os.path.exists(pkg_json_path):
            # Manifest-only project (package.json without lockfile)
            warnings.append("Resolved versions are unavailable because lockfile (package-lock.json) is missing.")
            detailed = parse_package_json_detailed(pkg_json_path)
            prod_deps = detailed.get("dependencies", {})
            dev_deps = detailed.get("devDependencies", {})

            for name, ver_range in prod_deps.items():
                pkg_id = f"pkg:npm/{name}"
                if pkg_id not in seen_node_ids:
                    nodes.append({
                        "id": pkg_id,
                        "label": f"npm:{name} (declared: {ver_range})",
                        "type": "software_package",
                        "subtype": "npm",
                        "version": None,
                        "provenance": "declared",
                        "status": "unknown",
                        "criticality": "high",
                        "metadata": {
                            "ecosystem": "npm",
                            "declared_range": ver_range,
                            "is_direct": True,
                            "is_dev": False,
                            "resolved": None
                        }
                    })
                    seen_node_ids.add(pkg_id)

                edge_id = f"edge:npm:{app_node_id}->{pkg_id}"
                edges.append({
                    "id": edge_id,
                    "source": app_node_id,
                    "target": pkg_id,
                    "relation": "depends_on",
                    "provenance": "declared",
                    "confidence_score": 1.0,
                    "evidence_ids": [npm_ev_id],
                    "metadata": {
                        "ecosystem": "npm",
                        "consumer": project_name,
                        "dependency": name,
                        "declared_range": ver_range
                    }
                })

            for name, ver_range in dev_deps.items():
                pkg_id = f"pkg:npm/{name}"
                if pkg_id not in seen_node_ids:
                    nodes.append({
                        "id": pkg_id,
                        "label": f"npm:{name} (declared: {ver_range})",
                        "type": "software_package",
                        "subtype": "npm",
                        "version": None,
                        "provenance": "declared",
                        "status": "unknown",
                        "criticality": "medium",
                        "metadata": {
                            "ecosystem": "npm",
                            "declared_range": ver_range,
                            "is_direct": True,
                            "is_dev": True,
                            "resolved": None
                        }
                    })
                    seen_node_ids.add(pkg_id)

                edge_id = f"edge:npm:{app_node_id}->{pkg_id}"
                edges.append({
                    "id": edge_id,
                    "source": app_node_id,
                    "target": pkg_id,
                    "relation": "depends_on",
                    "provenance": "declared",
                    "confidence_score": 1.0,
                    "evidence_ids": [npm_ev_id],
                    "metadata": {
                        "ecosystem": "npm",
                        "consumer": project_name,
                        "dependency": name,
                        "declared_range": ver_range
                    }
                })

    # -------------------------------------------------------------
    # 2. Composer Ingestion (composer.json + composer.lock)
    # -------------------------------------------------------------
    composer_json_path = os.path.join(repo_path, "composer.json")
    composer_lock_path = os.path.join(repo_path, "composer.lock")
    if os.path.exists(composer_json_path) or os.path.exists(composer_lock_path):
        manifests_found.append("composer")

        composer_ev_id = f"ev:manifest:composer:{current_scan_id[:8]}"
        evidence_records.append({
            "id": composer_ev_id,
            "evidence_type": "declared",
            "collected_at": now_iso,
            "collector": "composer-lockfile-parser",
            "confidence": 1.0,
            "declared_details": {
                "file_path": composer_lock_path if os.path.exists(composer_lock_path) else composer_json_path,
                "manifest_type": "composer.lock" if os.path.exists(composer_lock_path) else "composer.json",
                "raw_declaration": f"Composer Project: {project_name}"
            }
        })

        if os.path.exists(composer_lock_path):
            composer_result = parse_composer_lock(
                composer_lock_path,
                composer_json_path=composer_json_path,
                root_app_id=app_node_id
            )
            warnings.extend(composer_result.inconsistencies)
            warnings.extend(composer_result.warnings)

            for pkg in composer_result.packages.values():
                nodes.append({
                    "id": pkg.id,
                    "label": f"composer:{pkg.name}@{pkg.version}",
                    "type": "software_package",
                    "subtype": "composer",
                    "version": pkg.version,
                    "provenance": "declared",
                    "status": "healthy",
                    "criticality": "high" if pkg.is_direct else "medium",
                    "metadata": {
                        "ecosystem": "composer",
                        "is_direct": pkg.is_direct,
                        "is_dev": pkg.is_dev,
                        "description": pkg.description
                    }
                })
                seen_node_ids.add(pkg.id)

            # Composer Edges: Consumer -> Dependency
            for edge in composer_result.dependency_edges:
                src = app_node_id if edge["source"].startswith("app:") else edge["source"]
                edge_id = f"edge:composer:{src}->{edge['target']}"
                edges.append({
                    "id": edge_id,
                    "source": src,
                    "target": edge["target"],
                    "relation": edge["relation"],
                    "provenance": "declared",
                    "confidence_score": 1.0,
                    "evidence_ids": [composer_ev_id],
                    "metadata": {
                        "ecosystem": "composer",
                        "consumer": edge.get("consumer_name"),
                        "dependency": edge.get("dependency_name")
                    }
                })
        elif os.path.exists(composer_json_path):
            # Manifest-only Composer project (composer.json without composer.lock)
            warnings.append("Resolved versions are unavailable because lockfile (composer.lock) is missing.")
            manifest = parse_composer_json(composer_json_path)
            prod_deps = manifest.get("dependencies", {})
            dev_deps = manifest.get("devDependencies", {})

            for name, ver_range in prod_deps.items():
                pkg_id = f"pkg:composer/{name}"
                if pkg_id not in seen_node_ids:
                    nodes.append({
                        "id": pkg_id,
                        "label": f"composer:{name} (declared: {ver_range})",
                        "type": "software_package",
                        "subtype": "composer",
                        "version": None,
                        "provenance": "declared",
                        "status": "unknown",
                        "criticality": "high",
                        "metadata": {
                            "ecosystem": "composer",
                            "declared_range": ver_range,
                            "is_direct": True,
                            "is_dev": False,
                            "resolved": None
                        }
                    })
                    seen_node_ids.add(pkg_id)

                edge_id = f"edge:composer:{app_node_id}->{pkg_id}"
                edges.append({
                    "id": edge_id,
                    "source": app_node_id,
                    "target": pkg_id,
                    "relation": "depends_on",
                    "provenance": "declared",
                    "confidence_score": 1.0,
                    "evidence_ids": [composer_ev_id],
                    "metadata": {
                        "ecosystem": "composer",
                        "consumer": project_name,
                        "dependency": name,
                        "declared_range": ver_range
                    }
                })

            for name, ver_range in dev_deps.items():
                pkg_id = f"pkg:composer/{name}"
                if pkg_id not in seen_node_ids:
                    nodes.append({
                        "id": pkg_id,
                        "label": f"composer:{name} (declared: {ver_range})",
                        "type": "software_package",
                        "subtype": "composer",
                        "version": None,
                        "provenance": "declared",
                        "status": "unknown",
                        "criticality": "medium",
                        "metadata": {
                            "ecosystem": "composer",
                            "declared_range": ver_range,
                            "is_direct": True,
                            "is_dev": True,
                            "resolved": None
                        }
                    })
                    seen_node_ids.add(pkg_id)

                edge_id = f"edge:composer:{app_node_id}->{pkg_id}"
                edges.append({
                    "id": edge_id,
                    "source": app_node_id,
                    "target": pkg_id,
                    "relation": "depends_on",
                    "provenance": "declared",
                    "confidence_score": 1.0,
                    "evidence_ids": [composer_ev_id],
                    "metadata": {
                        "ecosystem": "composer",
                        "consumer": project_name,
                        "dependency": name,
                        "declared_range": ver_range
                    }
                })

    # -------------------------------------------------------------
    # 3. Runtime Trace Ingestion (OpenTelemetry / Browser Traces)
    # -------------------------------------------------------------
    trace_count = 0
    if trace_file_path and os.path.exists(trace_file_path):
        raw_traces = parse_runtime_traces(trace_file_path)
        trace_count = len(raw_traces)

        if raw_traces:
            trace_result = normalize_runtime_traces(
                raw_traces,
                default_source_service=app_node_id
            )

            # Add observed evidence
            evidence_records.extend(trace_result.evidence)

            # Add observed nodes (external_api)
            for obs_node in trace_result.nodes:
                if obs_node["id"] not in seen_node_ids:
                    seen_node_ids.add(obs_node["id"])
                    nodes.append(obs_node)

            # Add observed edges (calls_api)
            for obs_edge in trace_result.edges:
                edges.append(obs_edge)

    # -------------------------------------------------------------
    # Guarantee Graph Integrity: Ensure all edge sources & targets exist in nodes
    # -------------------------------------------------------------
    for edge in edges:
        src = edge["source"]
        if src not in seen_node_ids:
            seen_node_ids.add(src)
            src_type = "application" if src.startswith("app:") else "internal_service"
            nodes.append({
                "id": src,
                "label": src,
                "type": src_type,
                "subtype": "observed_service",
                "version": None,
                "provenance": "observed",
                "status": "healthy",
                "criticality": "high",
                "metadata": {"inferred_from": "runtime_trace"}
            })
        tgt = edge["target"]
        if tgt not in seen_node_ids:
            seen_node_ids.add(tgt)
            nodes.append({
                "id": tgt,
                "label": tgt,
                "type": "external_api",
                "subtype": "observed_endpoint",
                "version": None,
                "provenance": "observed",
                "status": "unknown",
                "criticality": "medium",
                "metadata": {"inferred_from": "edge_target"}
            })

    # -------------------------------------------------------------
    # 4. Coverage Summary
    # -------------------------------------------------------------
    total_declared = sum(1 for n in nodes if n["provenance"] == "declared" and n["id"] != app_node_id)
    total_observed = sum(1 for n in nodes if n["provenance"] == "observed")

    coverage = {
        "manifests_found": manifests_found,
        "total_declared_dependencies": total_declared,
        "total_observed_dependencies": total_observed,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "total_evidence_records": len(evidence_records),
        "traces_ingested": trace_count,
        "lockfile_consistent": len(warnings) == 0
    }

    return DiscoveryResult(
        project_name=project_name,
        scan_id=current_scan_id,
        nodes=nodes,
        edges=edges,
        evidence=evidence_records,
        coverage=coverage,
        warnings=warnings,
        created_at=now_iso
    )
