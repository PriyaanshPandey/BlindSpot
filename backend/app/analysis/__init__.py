"""
Analysis Engine [Role B]:
Calculates business journey disruption and financial exposure from dependency outages.
"""
from typing import Dict, Any, List

DEFAULT_JOURNEY_METRICS = {
    "journey:checkout": {
        "name": "Customer Checkout & Payment",
        "hourly_tx": 1200.0,
        "avg_tx_val": 45.0,
        "default_fraction": 1.0
    },
    "journey:auth": {
        "name": "User Sign-In & Onboarding",
        "hourly_tx": 2500.0,
        "avg_tx_val": 12.0,
        "default_fraction": 0.8
    },
    "journey:order_tracking": {
        "name": "Order Status & Tracking",
        "hourly_tx": 800.0,
        "avg_tx_val": 5.0,
        "default_fraction": 0.3
    }
}

def calculate_financial_exposure(
    impacted_nodes: List[str],
    failure_duration_hours: float = 4.0,
    tx_override: float = None,
    avg_val_override: float = None
) -> Dict[str, Any]:
    impacted_journeys = []
    total_exposure = 0.0

    # Map impacted nodes to journeys
    for j_id, meta in DEFAULT_JOURNEY_METRICS.items():
        hourly = tx_override if tx_override is not None else meta["hourly_tx"]
        avg_val = avg_val_override if avg_val_override is not None else meta["avg_tx_val"]
        fraction = meta["default_fraction"]

        exposure = hourly * avg_val * failure_duration_hours * fraction
        total_exposure += exposure

        impacted_journeys.append({
            "journey_id": j_id,
            "name": meta["name"],
            "disruption_fraction": fraction,
            "hourly_transactions": hourly,
            "average_transaction_value": avg_val,
            "financial_exposure": exposure
        })

    return {
        "total_estimated_gross_exposure": total_exposure,
        "exposure_currency": "USD",
        "impacted_journeys": impacted_journeys,
        "mitigation_strategies": [
            {
                "strategy_type": "fallback_provider",
                "title": "Enable Automatic Secondary Gateway Failover",
                "description": "Route checkout transactions through secondary merchant processor when latency exceeds 2.5s",
                "estimated_risk_reduction_pct": 75.0
            },
            {
                "strategy_type": "circuit_breaker",
                "title": "Circuit Breaker on External Telemetry",
                "description": "Isolate unessential telemetry calls to avoid blocking main thread render loop",
                "estimated_risk_reduction_pct": 90.0
            }
        ]
    }

