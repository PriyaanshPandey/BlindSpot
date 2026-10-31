from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import uuid
import os
import re
from datetime import datetime
import time

from app.models import ScanRequest, ScanRecord, ScanStatus, ScanSummary, ScanConfig
from app.db import db
from app.db.repositories import ScanRepository, GraphRepository, FindingRepository, EvidenceRepository
from app.ingestion import scan_project_directory, parse_runtime_traces
from app.security import check_vulnerabilities
from app.graph import GraphEngine
from app.analysis.reconciliation import DiscrepancyDetector

router = APIRouter()

class DirectPayloadScan(BaseModel):
    project_name: str = "Uploaded Project"
    files: Dict[str, str] = {}  # { "package.json": "{...}", "index.html": "<...>" }

URL_REGEX = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>)]*)?')

def build_unified_graph(project_data: Dict[str, Any]) -> Dict[str, Any]:
    scan_id = str(uuid.uuid4())
    project_name = project_data.get("project_name", "Target Project")
    services = project_data.get("services", {})
    overall_deps = project_data.get("dependencies", {})
    observed_hosts = project_data.get("observed_hosts", [])
    evidence_map = project_data.get("evidence_records", {})

    # Detect primary ecosystem
    is_python = any(s.get("ecosystem") == "PyPI" for s in services.values())
    ecosystem = "PyPI" if is_python else "npm"

    # Query real OSV database
    vulns = check_vulnerabilities(overall_deps, ecosystem=ecosystem)

    nodes = []
    edges = []

    # 1. Root Application Node
    clean_name = project_name.replace(" ", "-").lower()
    app_id = f"app:{clean_name}"
    nodes.append({
        "id": app_id,
        "label": f"{project_name} (App)",
        "type": "application",
        "provenance": "declared",
        "status": "healthy",
        "criticality": "critical",
        "metadata": {"path": project_data.get("folder_path", "")}
    })

    # 2. Internal Service Nodes
    service_node_ids = []
    # If multiple subservices detected, render each; else single core engine
    active_services = {k: v for k, v in services.items() if v.get("dependencies") or v.get("external_calls")}
    if not active_services:
        active_services = {"core": {"name": f"{project_name} Engine", "dependencies": overall_deps, "external_calls": observed_hosts}}

    edge_counter = 1
    for s_key, s_data in active_services.items():
        s_id = f"service:{clean_name}-{s_key}"
        service_node_ids.append(s_id)
        nodes.append({
            "id": s_id,
            "label": s_data.get("name", f"{s_key.capitalize()} Service"),
            "type": "internal_service",
            "provenance": "declared",
            "status": "healthy",
            "criticality": "critical"
        })
        edges.append({
            "id": f"e_app_to_{s_key}",
            "source": app_id,
            "target": s_id,
            "relation": "calls_api",
            "provenance": "declared",
            "confidence_score": 1.0
        })

        # Connect dependencies to this subservice
        for pkg_name, ver in list(s_data.get("dependencies", {}).items())[:12]:
            clean_ver = str(ver).replace("^", "").replace("~", "").replace(">", "").strip()
            is_vuln = any(v.get("package") == pkg_name for v in vulns)
            pkg_id = f"pkg:{pkg_name}"
            
            # Avoid duplicate nodes
            if not any(n["id"] == pkg_id for n in nodes):
                nodes.append({
                    "id": pkg_id,
                    "label": f"{pkg_name}@{clean_ver}",
                    "type": "software_package",
                    "version": clean_ver,
                    "provenance": "declared",
                    "status": "compromised" if is_vuln else "healthy",
                    "criticality": "critical" if is_vuln else "medium"
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

        # Connect external calls to this subservice
        for host in s_data.get("external_calls", set()):
            is_known_vendor = any(v in host for v in ["stripe.com", "auth0.com", "twilio.com", "sendgrid.com", "firebase", "aws", "cloudflare", "razorpay", "rapidapi", "linkedin", "google"])
            host_id = f"ext:{host}"
            if not any(n["id"] == host_id for n in nodes):
                nodes.append({
                    "id": host_id,
                    "label": host,
                    "type": "vendor" if is_known_vendor else "external_api",
                    "provenance": "declared" if is_known_vendor else "observed",
                    "status": "healthy" if is_known_vendor else "warning",
                    "criticality": "critical" if is_known_vendor else "high"
                })
            edges.append({
                "id": f"e_ext_{edge_counter}",
                "source": s_id,
                "target": host_id,
                "relation": "calls_api",
                "provenance": "declared" if is_known_vendor else "observed",
                "confidence_score": 0.99
            })
            edge_counter += 1

    # 3. Business Journey Node
    journey_id = f"journey:{clean_name}-journey"
    nodes.append({
        "id": journey_id,
        "label": f"Journey: {project_name} Critical Operation",
        "type": "business_journey",
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

    # 4. Generate Real Findings
    findings = []
    finding_idx = 1

    # OSV Vulnerability findings
    for v in vulns:
        findings.append({
            "id": f"find-{finding_idx:03d}",
            "scan_id": scan_id,
            "type": "vulnerability_compromised_package",
            "title": f"Live OSV Advisory: {v.get('package')}@{v.get('version')} ({v.get('cve')})",
            "description": v.get("description", ""),
            "severity": v.get("severity", "high"),
            "target_node_id": f"pkg:{v.get('package')}",
            "affected_journey_ids": [journey_id],
            "evidence_references": ["manifest:package.json" if ecosystem == "npm" else "manifest:requirements.txt"],
            "security_details": {
                "cve_id": v.get("cve"),
                "cvss_score": 9.8 if v.get("severity") == "critical" else 7.8,
                "advisory_source": "Google OSV Database",
                "fixed_version": v.get("fixed_version", "latest")
            },
            "remediation": {
                "summary": f"Upgrade {v.get('package')} to safe release",
                "recommended_action": f"Upgrade to {v.get('fixed_version', 'latest')} or follow security patch guidance."
            }
        })
        finding_idx += 1

    # Discrepancy findings for unverified / undocumented third-party endpoints
    unverified_hosts = [h for h in observed_hosts if not any(v in h for v in ["stripe.com", "auth0.com", "github.com", "npmjs.org", "w3.org", "google.com"])]
    for uh in unverified_hosts:
        ev_list = evidence_map.get(uh, [f"code_reference:{uh}"])
        findings.append({
            "id": f"find-{finding_idx:03d}",
            "scan_id": scan_id,
            "type": "discrepancy_undeclared_endpoint",
            "title": f"Undocumented External Connection: {uh}",
            "description": f"Source code inspection discovered active communication with '{uh}'.",
            "severity": "high",
            "target_node_id": f"ext:{uh}",
            "affected_journey_ids": [journey_id],
            "evidence_references": ev_list[:3] if isinstance(ev_list, list) else [str(ev_list)],
            "remediation": {
                "summary": "Verify or remove unapproved endpoint",
                "recommended_action": f"Audit external calls to '{uh}'. Remove if unrecognized or configure Content-Security-Policy (CSP) headers."
            }
        })
        finding_idx += 1

    db.in_memory_graphs[scan_id] = {
        "scan_id": scan_id,
        "created_at": datetime.utcnow().isoformat(),
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "discrepancy_count": len(unverified_hosts),
            "vulnerability_count": len(vulns)
        }
    }
    db.in_memory_findings[scan_id] = findings

    # 5. Pre-generate Outage Simulation Scenarios for detected external services
    scenarios = []
    for host in observed_hosts[:4]:
        target_id = f"ext:{host}"
        impacted = [target_id] + service_node_ids + [app_id, journey_id]
        scenarios.append({
            "scenario_id": f"scen-{uuid.uuid4().hex[:8]}",
            "scan_id": scan_id,
            "name": f"Outage Scenario: Complete Failure of {host}",
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
        "summary": {
            "declared_dependencies": len(overall_deps),
            "observed_dependencies": len(observed_hosts),
            "discrepancies_found": len(unverified_hosts),
            "vulnerabilities_found": len(vulns),
            "critical_paths": len(service_node_ids),
            "execution_time_ms": 115.4
        }
    }
    db.in_memory_scans[scan_id] = scan_record
    return scan_record

async def process_and_persist_scan(
    project_name: str,
    deps: Dict[str, str],
    observed_hosts: List[str],
    repo_path: str,
    runtime_traces: Optional[List[Dict[str, Any]]] = None,
    trace_file_path: Optional[str] = None
) -> Dict[str, Any]:
    start_time = time.time()
    scan_id = str(uuid.uuid4())

    # 1. Match vulnerabilities (Person A module)
    vulns = check_vulnerabilities(deps)

    # 2. Build Vendor Passports sample data for trusted transitivity
    sample_passports = [
        {
            "vendor_id": "vendor:stripe",
            "name": "Stripe, Inc.",
            "subprocessors": [
                {"provider": "AWS US-East-1", "type": "cloud_infrastructure"}
            ]
        }
    ]

    # 3. Construct unified graph using NetworkX engine
    graph_engine = GraphEngine.from_evidence(
        scan_id=scan_id,
        project_name=project_name,
        dependencies=deps,
        observed_hosts=observed_hosts,
        vulnerabilities=vulns,
        runtime_traces=runtime_traces,
        vendor_passports=sample_passports
    )

    # 4. Run Discrepancy & Reconciliation Detection
    reconciler = DiscrepancyDetector(scan_id=scan_id)
    findings = reconciler.reconcile(
        declared_packages=deps,
        observed_hosts=observed_hosts,
        vulnerabilities=vulns,
        runtime_traces=runtime_traces,
        graph_engine=graph_engine
    )

    # 5. Build Evidence Records
    evidence_records = []
    # Declared evidence
    for pkg, ver in deps.items():
        evidence_records.append({
            "id": f"ev:pkg:{pkg}",
            "evidence_type": "declared",
            "collected_at": datetime.utcnow().isoformat(),
            "collector": "npm-manifest-parser",
            "confidence": 1.0,
            "declared_details": {
                "file_path": f"{repo_path}/package.json",
                "manifest_type": "package.json",
                "raw_declaration": f'"{pkg}": "{ver}"'
            }
        })
    # Observed evidence
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

    # 6. Graph export to canonical dictionary
    graph_dict = graph_engine.to_dict(filter_layer="all")

    # 7. Persist to MongoDB repositories
    await GraphRepository.save_graph(graph_dict)
    await FindingRepository.save_findings(scan_id, findings)
    await EvidenceRepository.save_evidence(scan_id, evidence_records)

    exec_time_ms = round((time.time() - start_time) * 1000, 2)
    discrepancy_count = sum(1 for f in findings if "discrepancy" in f.get("type", ""))

    scan_record = {
        "scan_id": scan_id,
        "project_name": project_name,
        "status": ScanStatus.COMPLETED.value,
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": datetime.utcnow().isoformat(),
        "config": {
            "repo_path": repo_path,
            "trace_file_path": trace_file_path,
            "enable_playwright_crawler": False,
            "enable_vendor_passports": True,
            "knowledge_bundle_mode": "hybrid"
        },
        "summary": {
            "declared_dependencies": len(deps),
            "observed_dependencies": len(observed_hosts),
            "discrepancies_found": discrepancy_count,
            "vulnerabilities_found": len(vulns),
            "critical_paths": 1,
            "execution_time_ms": exec_time_ms
        },
        "error_message": None
    }

    await ScanRepository.save_scan(scan_record)
    return scan_record

@router.post("", status_code=202)
async def create_scan(request: ScanRequest):
    project_scan = scan_project_directory(request.repo_path)
    if "error" in project_scan:
        raise HTTPException(status_code=400, detail=project_scan["error"])

    deps = project_scan.get("dependencies", {})
    observed_hosts = project_scan.get("observed_hosts", [])
    project_name = project_scan.get("project_name", "Target Project")

    # Also check if trace file exists
    runtime_traces = []
    if request.trace_file_path:
        runtime_traces = parse_runtime_traces(request.trace_file_path)
        for t in runtime_traces:
            dest = t.get("destination_host")
            if dest and dest not in observed_hosts:
                observed_hosts.append(dest)

    return await process_and_persist_scan(
        project_name=project_name,
        deps=deps,
        observed_hosts=observed_hosts,
        repo_path=request.repo_path,
        runtime_traces=runtime_traces,
        trace_file_path=request.trace_file_path
    )

@router.post("/direct")
async def scan_direct_files(payload: DirectPayloadScan):
    """Browser upload endpoint."""
    deps = {}
    observed_hosts = set()
    import json

    for fname, content in payload.files.items():
        if fname.endswith("package.json"):
            try:
                pkg_data = json.loads(content)
                d = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
                deps.update(d)
                if pkg_data.get("name"):
                    payload.project_name = pkg_data["name"]
            except Exception:
                pass
        elif fname.endswith("requirements.txt"):
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = re.split(r'==|>=|<=|~=', line)
                    pkg = parts[0].strip()
                    ver = parts[1].strip() if len(parts) > 1 else "*"
                    deps[pkg] = ver

        # Search for external URLs in content
        matches = URL_REGEX.findall(content)
        for m in matches:
            host_match = re.search(r'https?://([^/:\s]+)', m)
            if host_match:
                host = host_match.group(1).lower()
                if not host.startswith("localhost") and not host.startswith("127.0.0.1") and not host.endswith("schema.org") and not host.endswith("w3.org"):
                    observed_hosts.add(host)

    return await process_and_persist_scan(
        project_name=payload.project_name,
        deps=deps,
        observed_hosts=list(observed_hosts),
        repo_path="Browser Upload"
    )

@router.get("")
async def list_scans():
    return await ScanRepository.list_scans()

@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    scan = await ScanRepository.get_scan(scan_id)
    if scan:
        return scan
    raise HTTPException(status_code=404, detail="Scan not found")
