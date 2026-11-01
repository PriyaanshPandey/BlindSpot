"""
Analysis Subsystem [Role B]:
Calculates business journey disruption and architectural impact from dependency outages.
Implements the business impact formula:
Gross Exposure = sum(Hourly_Tx * Avg_Tx_Value * Duration * Disruption_Fraction)
Architecture Impact Score (0–100) = Journey Disruption (0-55) + Blast Radius (0-25) + Outage Duration (0-20)
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


def compute_architecture_impact_score(
    max_disruption: float,
    blast_node_count: int,
    duration_hours: float
) -> float:
    """
    Computes transparent Architecture Impact Score on a 0-100 scale:
    - Input 1: Journey Disruption (0.0 to 1.0) -> scaled to 0-55 points (Weight: 55%)
    - Input 2: Blast Radius (node count) -> min(count * 5.0, 25.0) points (Weight: 25%)
    - Input 3: Outage Duration (hours) -> min(hours * 0.85, 20.0) points (Weight: 20%)
    Total Scale: 0.0 to 100.0 (strictly bounded, no artificial minimum).
    """
    journey_weight = max(0.0, min(1.0, float(max_disruption))) * 55.0
    blast_weight = min(max(0, int(blast_node_count)) * 5.0, 25.0)
    duration_weight = min(max(0.0, float(duration_hours)) * 0.85, 20.0)
    score = min(100.0, max(0.0, round(journey_weight + blast_weight + duration_weight, 1)))
    return score


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

    # 1. Baseline Architecture Impact Score (0-100)
    max_disruption = max([j["disruption_fraction"] for j in impacted_journeys], default=0.0) if impacted_journeys else 0.0
    baseline_risk_score = compute_architecture_impact_score(
        max_disruption=max_disruption,
        blast_node_count=len(impacted_nodes),
        duration_hours=failure_duration_hours
    )

    # 2. Simulate post-mitigation risk for each strategy and calculate risk reduction by comparing baseline vs post-mitigation
    # Strategy A: Circuit Breaker (Isolates blast radius to target, prevents caller degradation)
    post_blast_cb = max(1, round(len(impacted_nodes) * 0.25))
    post_disruption_cb = max(0.05, max_disruption * 0.20)
    post_duration_cb = max(1.0, failure_duration_hours * 0.30)
    post_risk_cb = compute_architecture_impact_score(post_disruption_cb, post_blast_cb, post_duration_cb)
    reduction_cb = round(((baseline_risk_score - post_risk_cb) / max(baseline_risk_score, 1.0)) * 100, 1) if baseline_risk_score > 0 else 0.0

    # Strategy B: Secondary Gateway / Redundant Replica Failover (Routes traffic through redundant replica)
    post_blast_fb = max(1, round(len(impacted_nodes) * 0.50))
    post_disruption_fb = max(0.05, max_disruption * 0.15)
    post_duration_fb = max(0.5, failure_duration_hours * 0.15)
    post_risk_fb = compute_architecture_impact_score(post_disruption_fb, post_blast_fb, post_duration_fb)
    reduction_fb = round(((baseline_risk_score - post_risk_fb) / max(baseline_risk_score, 1.0)) * 100, 1) if baseline_risk_score > 0 else 0.0

    # Strategy C: Asynchronous Event Buffering & Retry Queue (Prevents transaction drop during transient outage)
    post_blast_oq = max(1, round(len(impacted_nodes) * 0.60))
    post_disruption_oq = max(0.10, max_disruption * 0.35)
    post_duration_oq = max(1.0, failure_duration_hours * 0.40)
    post_risk_oq = compute_architecture_impact_score(post_disruption_oq, post_blast_oq, post_duration_oq)
    reduction_oq = round(((baseline_risk_score - post_risk_oq) / max(baseline_risk_score, 1.0)) * 100, 1) if baseline_risk_score > 0 else 0.0

    mitigation_strategies = [
        {
            "strategy_type": "fallback_provider",
            "title": "Automated Secondary Gateway Failover",
            "description": "Route checkout transactions through backup payment processor when latency exceeds 2.5s or error rate > 5%",
            "baseline_risk_score": baseline_risk_score,
            "post_mitigation_risk_score": post_risk_fb,
            "estimated_risk_reduction_pct": max(5.0, min(95.0, reduction_fb))
        },
        {
            "strategy_type": "circuit_breaker",
            "title": "Circuit Breaker on External Integrations",
            "description": "Fail open or degrade gracefully for unessential external calls without halting the main transaction flow",
            "baseline_risk_score": baseline_risk_score,
            "post_mitigation_risk_score": post_risk_cb,
            "estimated_risk_reduction_pct": max(5.0, min(95.0, reduction_cb))
        },
        {
            "strategy_type": "offline_queue",
            "title": "Asynchronous Event Buffering & Retry Queue",
            "description": "Buffer non-realtime mutations in local durable storage and replay with exponential backoff upon service restoration",
            "baseline_risk_score": baseline_risk_score,
            "post_mitigation_risk_score": post_risk_oq,
            "estimated_risk_reduction_pct": max(5.0, min(95.0, reduction_oq))
        }
    ]

    return {
        "total_estimated_gross_exposure": round(total_exposure, 2),
        "architecture_impact_score": baseline_risk_score,
        "system_impact_percentage": baseline_risk_score,
        "severity_rating": "CRITICAL" if baseline_risk_score >= 80 else ("HIGH" if baseline_risk_score >= 60 else ("MODERATE" if baseline_risk_score >= 35 else "LOW")),
        "exposure_currency": "USD",
        "impacted_journeys": impacted_journeys,
        "mitigation_strategies": mitigation_strategies
    }
