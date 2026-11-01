"""
Simulation Engine [Role B]:
Orchestrates graph-based failure simulations.
Traverses the dependency graph to determine blast radius and calculates financial exposure.
"""
from typing import Dict, Any, List, Optional
import uuid
import logging
from app.graph import GraphEngine
from app.analysis import calculate_financial_exposure, DEFAULT_JOURNEY_METRICS
from app.models import SimulationRequest, ScenarioModel, SimulationParameters, SimulationImpactResults

logger = logging.getLogger("hdx.simulation")

class SimulationEngine:
    def __init__(self, graph_engine: GraphEngine):
        self.graph_engine = graph_engine

    def run_simulation(
        self,
        request: SimulationRequest,
        scan_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Simulates failure of a target dependency node:
        1. Calculates technical blast radius using NetworkX ancestor traversal (systems that depend on this node).
        2. Identifies affected business journeys specifically connected to or relying on the target node.
        3. Computes gross financial exposure.
        4. Generates structured scenario result adhering to scenario-schema.json.
        """
        scenario_id = str(uuid.uuid4())
        target_node = request.target_node_id
        current_scan_id = scan_id or self.graph_engine.scan_id

        # 1. Compute blast radius from real graph traversal
        blast_radius_nodes = self.graph_engine.get_blast_radius(target_node)

        # 2. Identify specifically impacted business journeys:
        # A journey is impacted if:
        # a) target_node directly connects to it (e.g. vendor:stripe powers journey:checkout)
        # b) target_node is a critical node for that specific journey
        # c) target_node is the entire application or core engine
        target_node_data = self.graph_engine.get_node(target_node) or {}
        is_core_or_app = (
            target_node_data.get("type") in ["application", "internal_service"]
            or "app:" in target_node or "service:" in target_node
        )

        impacted_journeys_set = set()
        for successor in self.graph_engine.get_direct_downstream(target_node):
            if successor.startswith("journey:"):
                impacted_journeys_set.add(successor)

        for j_key, j_meta in DEFAULT_JOURNEY_METRICS.items():
            if target_node in j_meta.get("critical_nodes", []):
                impacted_journeys_set.add(j_key)
            elif is_core_or_app:
                impacted_journeys_set.add(j_key)

        for j in impacted_journeys_set:
            blast_radius_nodes.append(j)

        # Deduplicate while preserving order
        unique_impacted = list(dict.fromkeys(blast_radius_nodes))

        # 3. Calculate financial exposure
        financials = calculate_financial_exposure(
            impacted_nodes=unique_impacted,
            target_node_id=target_node,
            failure_duration_hours=request.failure_duration_hours,
            tx_override=request.hourly_transactions_override,
            avg_val_override=request.average_transaction_value_override,
            graph_engine=self.graph_engine
        )

        scenario_record = {
            "scenario_id": scenario_id,
            "scan_id": current_scan_id,
            "name": f"Outage Simulation for {target_node}",
            "target_node_id": target_node,
            "simulation_parameters": {
                "failure_type": request.failure_type,
                "failure_duration_hours": request.failure_duration_hours,
                "hourly_transactions_override": request.hourly_transactions_override,
                "average_transaction_value_override": request.average_transaction_value_override
            },
            "impact_results": {
                "blast_radius_node_count": len(unique_impacted),
                "impacted_node_ids": unique_impacted,
                "impacted_journeys": financials["impacted_journeys"],
                "total_estimated_gross_exposure": financials["total_estimated_gross_exposure"],
                "exposure_currency": financials["exposure_currency"],
                "mitigation_strategies": financials["mitigation_strategies"],
                "architecture_impact_score": financials.get("architecture_impact_score"),
                "system_impact_percentage": financials.get("system_impact_percentage"),
                "severity_rating": financials.get("severity_rating", "HIGH")
            }
        }

        return scenario_record
