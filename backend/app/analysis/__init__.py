"""
Analysis Subsystem [Role B]:
Calculates business journey disruption and financial exposure from dependency outages.
Implements the business impact formula:
Gross Exposure = sum(Hourly_Tx * Avg_Tx_Value * Duration * Disruption_Fraction)
"""
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("hdx.analysis")

# Baseline business journey operational parameters
DEFAULT_JOURNEY_METRICS = {
    "journey:checkout": {
        "name": "Customer Checkout & Payment",
        "hourly_tx": 1200.0,
        "avg_tx_val": 45.0,
        "default_fraction": 1.0,
        "critical_nodes": ["vendor:stripe"]
    },
    "journey:auth": {
        "name": "User Sign-In & Onboarding",
        "hourly_tx": 2500.0,
        "avg_tx_val": 12.0,
        "default_fraction": 0.8,
        "critical_nodes": ["vendor:auth0"]
    },
    "journey:order_tracking": {
        "name": "Order Status & Tracking",
        "hourly_tx": 800.0,
        "avg_tx_val": 5.0,
        "default_fraction": 0.3,
        "critical_nodes": []
    }
}

def calculate_financial_exposure(
    impacted_nodes: List[str],
    target_node_id: Optional[str] = None,
    failure_duration_hours: float = 4.0,
    tx_override: Optional[float] = None,
    avg_val_override: Optional[float] = None,
    graph_engine: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Computes financial exposure by mapping the blast radius of impacted nodes to business journeys.
    Avoids double counting and respects actual graph-connected journeys.
    """
    impacted_journeys = []
    total_exposure = 0.0

    # Determine which journeys are actually affected
    affected_journey_keys = set()
    for node_id in impacted_nodes:
        if node_id.startswith("journey:") and node_id in DEFAULT_JOURNEY_METRICS:
            affected_journey_keys.add(node_id)

    # If no journey was found in impacted_nodes, fall back to checking critical_nodes
    if not affected_journey_keys and target_node_id:
        for j_key, j_meta in DEFAULT_JOURNEY_METRICS.items():
            if target_node_id in j_meta.get("critical_nodes", []):
                affected_journey_keys.add(j_key)

    # Fallback to checkout if still empty
    if not affected_journey_keys:
        affected_journey_keys.add("journey:checkout")

    for j_id in sorted(affected_journey_keys):
        meta = DEFAULT_JOURNEY_METRICS.get(j_id, {
            "name": f"Business Flow ({j_id})",
            "hourly_tx": 1000.0,
            "avg_tx_val": 25.0,
            "default_fraction": 0.5
        })

        hourly = tx_override if tx_override is not None else meta["hourly_tx"]
        avg_val = avg_val_override if avg_val_override is not None else meta["avg_tx_val"]
        fraction = meta["default_fraction"]

        exposure = float(hourly * avg_val * failure_duration_hours * fraction)
        total_exposure += exposure

        impacted_journeys.append({
            "journey_id": j_id,
            "name": meta["name"],
            "disruption_fraction": fraction,
            "hourly_transactions": hourly,
            "average_transaction_value": avg_val,
            "financial_exposure": round(exposure, 2)
        })

    # Sort journeys by highest exposure first
    impacted_journeys.sort(key=lambda x: x["financial_exposure"], reverse=True)

    # Tailored mitigation strategies
    mitigation_strategies = [
        {
            "strategy_type": "fallback_provider",
            "title": "Automated Secondary Gateway Failover",
            "description": "Route checkout transactions through backup payment processor when latency exceeds 2.5s or error rate > 5%",
            "estimated_risk_reduction_pct": 75.0
        },
        {
            "strategy_type": "circuit_breaker",
            "title": "Circuit Breaker on External Integrations",
            "description": "Fail open or degrade gracefully for unessential external calls without halting the main transaction flow",
            "estimated_risk_reduction_pct": 90.0
        },
        {
            "strategy_type": "offline_queue",
            "title": "Asynchronous Event Buffering & Retry Queue",
            "description": "Buffer non-realtime mutations in local durable storage and replay with exponential backoff upon service restoration",
            "estimated_risk_reduction_pct": 60.0
        }
    ]

    max_disruption = max([j["disruption_fraction"] for j in impacted_journeys], default=0.7)
    blast_weight = min(len(impacted_nodes) * 5, 25)
    duration_weight = min(failure_duration_hours * 0.85, 20)
    system_impact_pct = min(99.0, max(28.0, round(max_disruption * 55.0 + blast_weight + duration_weight, 1)))

    return {
        "total_estimated_gross_exposure": round(total_exposure, 2),
        "system_impact_percentage": system_impact_pct,
        "severity_rating": "CRITICAL" if system_impact_pct >= 80 else ("HIGH" if system_impact_pct >= 60 else "MODERATE"),
        "exposure_currency": "USD",
        "impacted_journeys": impacted_journeys,
        "mitigation_strategies": mitigation_strategies
    }
