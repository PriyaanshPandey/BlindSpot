from fastapi import APIRouter, HTTPException
import uuid
from typing import Set, List, Dict, Any, Optional
from datetime import datetime

from app.analysis import compute_architecture_impact_score
from app.models import SimulationRequest
from app.db import db
from app.db.repositories import GraphRepository, ScenarioRepository, ScanRepository

router = APIRouter()

# Defensible architectural criticality weights
CRITICALITY_WEIGHTS: Dict[str, float] = {
    "business_journey": 5.0,        # Top revenue/customer mission-critical journeys
    "journey": 5.0,
    "application": 4.0,             # Core customer application container
    "internal_service": 3.5,        # Core microservices powering APIs
    "service": 3.5,
    "app": 4.0,
    "infrastructure_resource": 3.0, # Primary DBs, caches, queues
    "infrastructure": 3.0,
    "database": 3.0,
    "cache": 3.0,
    "vendor": 3.0,                  # Critical 3rd-party SaaS (Payments, Auth, AI)
    "external_api": 2.5,            # External endpoints & shadow APIs
    "vendor_upstream": 1.5,         # 4th/5th party cloud infrastructure
    "software_package": 1.0,        # Direct & transitive code libraries
    "package": 1.0,
    "package_transitive": 0.8,
    "package_deep_transitive": 0.5,
    "unknown": 1.0
}

@router.get("/{scan_id}")
async def get_scenarios(scan_id: str):
    return db.in_memory_scenarios.get(scan_id, [])

@router.post("/{scan_id}/simulate")
async def simulate_failure(scan_id: str, request: SimulationRequest):
    scenario_id = str(uuid.uuid4())
    
    # 1. Fetch graph data from in-memory or repository
    graph = db.in_memory_graphs.get(scan_id)
    if not graph:
        try:
            graph = await GraphRepository.get_graph(scan_id)
        except Exception:
            graph = None

    if not graph:
        graph = {"nodes": [], "edges": []}

    nodes: List[Dict[str, Any]] = graph.get("nodes", [])
    edges: List[Dict[str, Any]] = graph.get("edges", [])

    total_nodes = len(nodes)
    target_id = request.target_node_id
    node_by_id = {n["id"]: n for n in nodes}

    # Resolve target_id if alias exists (e.g., 'vendor:stripe' -> 'pkg:stripe')
    if target_id not in node_by_id:
        target_clean = target_id.split(":")[-1].lower()
        for nid, ndata in node_by_id.items():
            if nid.split(":")[-1].lower() == target_clean or ndata.get("label", "").lower() == target_clean:
                target_id = nid
                break

    # 2. Traverse graph backwards/forwards to compute real blast radius
    # If target fails, callers and downstream business journeys fail
    incoming_map: Dict[str, Set[str]] = {}
    outgoing_map: Dict[str, Set[str]] = {}
    for e in edges:
        s = e.get("source")
        t = e.get("target")
        if s and t:
            outgoing_map.setdefault(s, set()).add(t)
            incoming_map.setdefault(t, set()).add(s)

    impacted: Set[str] = {target_id}
    queue: List[str] = [target_id]

    while queue:
        curr = queue.pop(0)
        # Callers of curr (who rely on curr)
        for caller in incoming_map.get(curr, []):
            if caller not in impacted:
                impacted.add(caller)
                queue.append(caller)
        # Journeys powered by curr or connected downstream
        for down in outgoing_map.get(curr, []):
            if "journey" in down and down not in impacted:
                impacted.add(down)

    # If target is a leaf node or standalone vendor, ensure affected callers/journeys are linked
    if len(impacted) == 1 and total_nodes > 1:
        for nid, n in node_by_id.items():
            if n.get("type") in ["business_journey", "journey"]:
                impacted.add(nid)
            elif n.get("type") in ["application", "app", "internal_service"]:
                impacted.add(nid)
                break

    impacted_list = list(impacted)

    # Defensible weighted architectural impact formula:
    # Impact % = (Sum of criticality weights of impacted nodes / Sum of all node weights) * 100
    total_arch_weight = sum(CRITICALITY_WEIGHTS.get(n.get("type", "unknown"), 1.0) for n in nodes)
    impacted_arch_weight = sum(
        CRITICALITY_WEIGHTS.get(node_by_id[nid].get("type", "unknown"), 1.0)
        for nid in impacted_list if nid in node_by_id
    )
    weighted_impact_pct = round((impacted_arch_weight / max(total_arch_weight, 1.0)) * 100, 1)

    # Raw unweighted percentage for reference
    raw_impact_pct = round((len(impacted_list) / max(total_nodes, 1)) * 100, 1)

    impacted_node_objs = [node_by_id.get(nid, {"id": nid, "label": nid, "type": "unknown"}) for nid in impacted_list]

    services_count = sum(1 for n in impacted_node_objs if n.get("type") in ["internal_service", "application", "service", "app"])
    packages_count = sum(1 for n in impacted_node_objs if n.get("type") in ["software_package", "package", "package_transitive", "package_deep_transitive"])
    infra_count = sum(1 for n in impacted_node_objs if n.get("type") in ["infrastructure", "database", "cache", "infrastructure_resource"])
    vendor_count = sum(1 for n in impacted_node_objs if n.get("type") in ["vendor", "external_api", "vendor_upstream"])
    journeys = [n for n in impacted_node_objs if n.get("type") in ["business_journey", "journey"]]

    target_label = node_by_id.get(target_id, {}).get("label", target_id)

    # Calculate financial exposure if overrides are explicitly provided
    if request.hourly_transactions_override is not None and request.average_transaction_value_override is not None:
        total_exposure = round(
            float(request.hourly_transactions_override)
            * float(request.average_transaction_value_override)
            * float(request.failure_duration_hours)
            * 1.0,
            2
        )
    else:
        total_exposure = 0.0

    # Calculate Architecture Impact Score (0-100) and dynamic risk reduction by comparing baseline vs post-mitigation
    max_j_disruption = 1.0 if journeys else min(1.0, weighted_impact_pct / 100.0)
    baseline_arch_score = compute_architecture_impact_score(
        max_disruption=max_j_disruption,
        blast_node_count=len(impacted_list),
        duration_hours=request.failure_duration_hours
    )

    # Dynamic post-mitigation risk simulation
    post_blast_cb = max(1, round(len(impacted_list) * 0.25))
    post_disrupt_cb = max(0.05, max_j_disruption * 0.20)
    post_dur_cb = max(1.0, request.failure_duration_hours * 0.30)
    post_risk_cb = compute_architecture_impact_score(post_disrupt_cb, post_blast_cb, post_dur_cb)
    cb_reduction = round(((baseline_arch_score - post_risk_cb) / max(baseline_arch_score, 1.0)) * 100, 1) if baseline_arch_score > 0 else 0.0

    post_blast_fb = max(1, round(len(impacted_list) * 0.50))
    post_disrupt_fb = max(0.05, max_j_disruption * 0.15)
    post_dur_fb = max(0.5, request.failure_duration_hours * 0.15)
    post_risk_fb = compute_architecture_impact_score(post_disrupt_fb, post_blast_fb, post_dur_fb)
    fb_reduction = round(((baseline_arch_score - post_risk_fb) / max(baseline_arch_score, 1.0)) * 100, 1) if baseline_arch_score > 0 else 0.0

    scenario_result = {
        "scenario_id": scenario_id,
        "scan_id": scan_id,
        "name": f"Outage Simulation: {target_label}",
        "target_node_id": target_id,
        "simulation_parameters": request.model_dump(),
        "impact_results": {
            "blast_radius_node_count": len(impacted_list),
            "impacted_node_ids": impacted_list,
            "impact_percentage": weighted_impact_pct,
            "system_impact_percentage": weighted_impact_pct,
            "raw_impact_percentage": raw_impact_pct,
            "severity_rating": "CRITICAL" if weighted_impact_pct >= 75 else ("HIGH" if weighted_impact_pct >= 45 else "MODERATE"),
            "total_system_nodes": total_nodes,
            "impacted_services_count": max(services_count, 1) if services_count > 0 else 0,
            "impacted_packages_count": packages_count,
            "impacted_infra_count": infra_count,
            "impacted_vendor_count": max(vendor_count, 1) if vendor_count > 0 else 0,
            "impact_summary": f"Simulating failure of '{target_label}' disables {weighted_impact_pct}% of total architecture criticality ({len(impacted_list)} of {total_nodes} nodes affected).",
            "calculation_basis": "Weighted Graph Blast Radius (Journeys: 5.0, Apps: 4.0, Services: 3.5, DB/Infra: 3.0, Vendors: 3.0, Packages: 1.0)",
            "total_estimated_gross_exposure": total_exposure,
            "exposure_currency": "USD",
            "impacted_journeys": [
                {
                    "journey_id": j.get("id"),
                    "name": j.get("label", "Core Journey"),
                    "disruption_fraction": 1.0,
                    "hourly_transactions": request.hourly_transactions_override or 0,
                    "average_transaction_value": request.average_transaction_value_override or 0,
                    "financial_exposure": total_exposure
                }
                for j in journeys
            ] or [
                {
                    "journey_id": "journey:core-ops",
                    "name": "Core Operations & Transactions",
                    "disruption_fraction": weighted_impact_pct / 100.0,
                    "hourly_transactions": request.hourly_transactions_override or 0,
                    "average_transaction_value": request.average_transaction_value_override or 0,
                    "financial_exposure": total_exposure
                }
            ],
            "architecture_impact_score": baseline_arch_score,
            "mitigation_strategies": [
                {
                    "strategy_type": "circuit_breaker",
                    "title": f"Deploy Circuit Breaker for {target_label}",
                    "description": f"Isolate {target_label} with exponential backoff and timeout fallback to prevent cascading degradation of callers.",
                    "baseline_risk_score": baseline_arch_score,
                    "post_mitigation_risk_score": post_risk_cb,
                    "estimated_risk_reduction_pct": max(5.0, min(95.0, cb_reduction))
                },
                {
                    "strategy_type": "graceful_fallback",
                    "title": "Enable Degraded Read-Only / Secondary Failover",
                    "description": "Serve cached responses or route traffic to redundant regional replica when primary target is unreachable.",
                    "baseline_risk_score": baseline_arch_score,
                    "post_mitigation_risk_score": post_risk_fb,
                    "estimated_risk_reduction_pct": max(5.0, min(95.0, fb_reduction))
                }
            ]
        }
    }

    # Persist in-memory and repository
    db.in_memory_scenarios.setdefault(scan_id, []).append(scenario_result)
    try:
        await ScenarioRepository.save_scenario(scenario_result)
    except Exception:
        pass

    return scenario_result

@router.get("/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str):
    # Check repository first
    try:
        scen = await ScenarioRepository.get_scenario(scenario_id)
        if scen:
            return scen
    except Exception:
        pass

    # Check in-memory
    for scan_scenarios in db.in_memory_scenarios.values():
        for s in scan_scenarios:
            if s.get("scenario_id") == scenario_id:
                return s

    raise HTTPException(status_code=404, detail="Scenario not found")
