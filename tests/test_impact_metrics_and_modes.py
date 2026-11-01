import pytest
from app.analysis import compute_architecture_impact_score, calculate_financial_exposure
from app.graph import GraphEngine
from app.analysis.simulation import SimulationEngine
from app.models import SimulationRequest
from app.integrations.gemini import sanitize_context_for_gemini, explain_finding
from app.integrations.gemini.grounding import resolve_authoritative_advisory


def test_architecture_impact_score_inputs_scales_and_weights():
    """
    Verifies that the Architecture Impact Score (0–100) combines inputs transparently:
    - Journey Disruption: 0.0 - 1.0 -> 0 - 55 points (Scale: 55%)
    - Blast Radius: 0 - 5+ nodes -> 0 - 25 points (Scale: 25%)
    - Outage Duration: 0 - 24 hours -> 0 - 20 points (Scale: 20%)
    - Total: 0 to 100 with NO arbitrary minimum floor (can be 0.0).
    """
    # Case 0: Absolute zero outage (no arbitrary floor like 28)
    score_zero = compute_architecture_impact_score(max_disruption=0.0, blast_node_count=0, duration_hours=0.0)
    assert score_zero == 0.0

    # Case 1: Max Journey disruption only (55 pts)
    score_journey_only = compute_architecture_impact_score(max_disruption=1.0, blast_node_count=0, duration_hours=0.0)
    assert score_journey_only == 55.0

    # Case 2: Max Blast radius only (25 pts)
    score_blast_only = compute_architecture_impact_score(max_disruption=0.0, blast_node_count=5, duration_hours=0.0)
    assert score_blast_only == 25.0

    # Blast radius beyond 5 nodes is capped at 25 pts
    score_blast_over = compute_architecture_impact_score(max_disruption=0.0, blast_node_count=50, duration_hours=0.0)
    assert score_blast_over == 25.0

    # Case 3: Max Duration only (20 pts)
    score_duration_only = compute_architecture_impact_score(max_disruption=0.0, blast_node_count=0, duration_hours=24.0)
    assert score_duration_only == 20.0

    # Case 4: Full catastrophic outage (capped at 100)
    score_max = compute_architecture_impact_score(max_disruption=1.0, blast_node_count=10, duration_hours=24.0)
    assert score_max == 100.0


def test_architecture_impact_score_predictable_scaling():
    """
    Verifies that Architecture Impact Score changes monotonically and predictably
    as blast radius, duration, and journey disruption increase.
    """
    # 1. Monotonicity with duration
    d_1h = compute_architecture_impact_score(max_disruption=0.5, blast_node_count=2, duration_hours=1.0)
    d_4h = compute_architecture_impact_score(max_disruption=0.5, blast_node_count=2, duration_hours=4.0)
    d_12h = compute_architecture_impact_score(max_disruption=0.5, blast_node_count=2, duration_hours=12.0)
    d_24h = compute_architecture_impact_score(max_disruption=0.5, blast_node_count=2, duration_hours=24.0)
    assert d_1h < d_4h < d_12h < d_24h

    # 2. Monotonicity with blast radius
    b_1 = compute_architecture_impact_score(max_disruption=0.5, blast_node_count=1, duration_hours=4.0)
    b_2 = compute_architecture_impact_score(max_disruption=0.5, blast_node_count=2, duration_hours=4.0)
    b_3 = compute_architecture_impact_score(max_disruption=0.5, blast_node_count=3, duration_hours=4.0)
    b_5 = compute_architecture_impact_score(max_disruption=0.5, blast_node_count=5, duration_hours=4.0)
    assert b_1 < b_2 < b_3 < b_5

    # 3. Monotonicity with journey disruption
    j_20 = compute_architecture_impact_score(max_disruption=0.2, blast_node_count=2, duration_hours=4.0)
    j_50 = compute_architecture_impact_score(max_disruption=0.5, blast_node_count=2, duration_hours=4.0)
    j_80 = compute_architecture_impact_score(max_disruption=0.8, blast_node_count=2, duration_hours=4.0)
    j_100 = compute_architecture_impact_score(max_disruption=1.0, blast_node_count=2, duration_hours=4.0)
    assert j_20 < j_50 < j_80 < j_100


def test_dynamic_risk_reduction_calculation():
    """
    Verifies that every resilience strategy calculates its risk reduction by comparing
    baseline risk against simulated post-mitigation risk (never static/hardcoded).
    """
    engine = GraphEngine(scan_id="test-risk-calc")
    engine.add_node("app:frontend", "Frontend", "application")
    engine.add_node("service:api", "API Service", "internal_service")
    engine.add_node("vendor:stripe", "Stripe", "vendor")
    engine.add_node("journey:checkout", "Checkout Flow", "business_journey")

    engine.add_edge("app:frontend", "service:api", "calls")
    engine.add_edge("service:api", "vendor:stripe", "calls")
    engine.add_edge("vendor:stripe", "journey:checkout", "powers")

    sim_engine = SimulationEngine(graph_engine=engine)
    req = SimulationRequest(
        target_node_id="vendor:stripe",
        failure_type="complete_outage",
        failure_duration_hours=12.0
    )

    result = sim_engine.run_simulation(req, scan_id="test-risk-calc")
    impact = result["impact_results"]

    baseline_score = impact["architecture_impact_score"]
    assert baseline_score is not None
    assert 0 < baseline_score <= 100

    mitigations = impact["mitigation_strategies"]
    assert len(mitigations) >= 2

    for strat in mitigations:
        # Must contain baseline and post-mitigation scores
        assert "baseline_risk_score" in strat
        assert "post_mitigation_risk_score" in strat
        assert "estimated_risk_reduction_pct" in strat

        base = strat["baseline_risk_score"]
        post = strat["post_mitigation_risk_score"]
        reduction = strat["estimated_risk_reduction_pct"]

        # Post-mitigation risk must be lower than baseline risk
        assert post < base
        # Reduction percentage must be mathematically derived from (base - post) / base
        expected_reduction = round(((base - post) / base) * 100, 1)
        assert abs(reduction - expected_reduction) <= 1.0
        assert 0.0 < reduction <= 100.0


def test_missing_journey_and_zero_denominator_handling():
    """
    Verifies that missing journey data and zero denominators are handled cleanly
    without throwing ZeroDivisionError or returning NaN.
    """
    exposure = calculate_financial_exposure(
        impacted_nodes=[],
        target_node_id="unknown_leaf_node",
        failure_duration_hours=0.0
    )
    assert exposure["architecture_impact_score"] >= 0.0
    assert exposure["total_estimated_gross_exposure"] == 0.0

    for strat in exposure["mitigation_strategies"]:
        assert strat["estimated_risk_reduction_pct"] >= 0.0
        assert not isinstance(strat["estimated_risk_reduction_pct"], str)


def test_mode_switching_affects_ai_context_and_preserves_findings():
    """
    Verifies that mode selection (builder vs enterprise) changes AI prompt instructions
    while preserving underlying scan findings identically.
    """
    # 1. Authoritative advisory resolution is unchanged by mode
    auth = resolve_authoritative_advisory("axios", "0.21.1", "CVE-2020-28168")
    assert auth["is_verified_vulnerable"] is False
    assert auth["verification_status"] == "ALREADY_FIXED"

    finding_data = {
        "finding_id": "find-101",
        "title": "Axios SSRF in Data Submission",
        "severity": "high",
        "category": "vulnerability",
        "target_node_id": "pkg:axios@0.21.1",
        "package_name": "axios",
        "installed_version": "0.21.1",
        "cve_id": "CVE-2020-28168",
        "remediation": {"recommended_action": "Verify patched version"}
    }

    # 2. Builder Mode Context
    builder_context = sanitize_context_for_gemini(finding_data, audience="builder")
    assert builder_context["audience"] == "builder"
    assert builder_context["target_package"] == "axios"
    assert builder_context["cve_id"] == "CVE-2020-28168"
    assert builder_context["authoritative_details"]["verification_status"] == "ALREADY_FIXED"

    # 3. Enterprise Mode Context
    enterprise_context = sanitize_context_for_gemini(finding_data, audience="enterprise")
    assert enterprise_context["audience"] == "enterprise"
    assert enterprise_context["target_package"] == "axios"
    assert enterprise_context["cve_id"] == "CVE-2020-28168"
    assert enterprise_context["authoritative_details"]["verification_status"] == "ALREADY_FIXED"

    # 4. Context preservation: Findings metadata is identical across modes
    assert builder_context["target_package"] == enterprise_context["target_package"]
    assert builder_context["cve_id"] == enterprise_context["cve_id"]
    assert builder_context["authoritative_details"] == enterprise_context["authoritative_details"]
