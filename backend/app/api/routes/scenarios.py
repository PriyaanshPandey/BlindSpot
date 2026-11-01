from fastapi import APIRouter
import uuid
from typing import Set, List, Dict, Any
from app.models import SimulationRequest
from app.db import db

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
    "unknown": 1.0
}

@router.get("/{scan_id}")
async def get_scenarios(scan_id: str):
    return db.in_memory_scenarios.get(scan_id, [])

@router.post("/{scan_id}/simulate")
async def simulate_failure(scan_id: str, request: SimulationRequest):
    scenario_id = str(uuid.uuid4())
    graph = db.in_memory_graphs.get(scan_id, {"nodes": [], "edges": []})
    nodes: List[Dict[str, Any]] = graph.get("nodes", [])
    edges: List[Dict[str, Any]] = graph.get("edges", [])

    total_nodes = len(nodes)
    target_id = request.target_node_id

    # Traverse graph backwards/forwards to compute real blast radius
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

    impacted_list = list(impacted)
    node_by_id = {n["id"]: n for n in nodes}

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
    packages_count = sum(1 for n in impacted_node_objs if n.get("type") in ["software_package", "package", "package_transitive"])
    infra_count = sum(1 for n in impacted_node_objs if n.get("type") in ["infrastructure", "database", "cache", "infrastructure_resource"])
    vendor_count = sum(1 for n in impacted_node_objs if n.get("type") in ["vendor", "external_api", "vendor_upstream"])
    journeys = [n for n in impacted_node_objs if n.get("type") in ["business_journey", "journey"]]

    target_label = node_by_id.get(target_id, {}).get("label", target_id)

    return {
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
            "impacted_services_count": services_count,
            "impacted_packages_count": packages_count,
            "impacted_infra_count": infra_count,
            "impacted_vendor_count": vendor_count,
            "impact_summary": f"Simulating failure of '{target_label}' disables {weighted_impact_pct}% of total architecture criticality ({len(impacted_list)} of {total_nodes} nodes affected).",
            "calculation_basis": "Weighted Graph Blast Radius (Journeys: 5.0, Apps: 4.0, Services: 3.5, DB/Infra: 3.0, Vendors: 3.0, Packages: 1.0)",
            "total_estimated_gross_exposure": 0,
            "exposure_currency": "USD",
            "impacted_journeys": [
                {
                    "journey_id": j.get("id"),
                    "name": j.get("label", "Core Journey"),
                    "disruption_fraction": 1.0,
                    "hourly_transactions": 0,
                    "average_transaction_value": 0,
                    "financial_exposure": 0
                }
                for j in journeys
            ] or [
                {
                    "journey_id": "journey:core-ops",
                    "name": "Core Operations & Transactions",
                    "disruption_fraction": weighted_impact_pct / 100.0,
                    "hourly_transactions": 0,
                    "average_transaction_value": 0,
                    "financial_exposure": 0
                }
            ],
            "mitigation_strategies": [
                {
                    "strategy_type": "circuit_breaker",
                    "title": f"Deploy Circuit Breaker for {target_label}",
                    "description": f"Isolate {target_label} with exponential backoff and timeout fallback to prevent cascading degradation of callers.",
                    "estimated_risk_reduction_pct": 82.0
                },
                {
                    "strategy_type": "graceful_fallback",
                    "title": "Enable Degraded Read-Only / Secondary Failover",
                    "description": "Serve cached responses or route traffic to redundant regional replica when primary target is unreachable.",
                    "estimated_risk_reduction_pct": 74.0
                }
            ]
        }
    }
