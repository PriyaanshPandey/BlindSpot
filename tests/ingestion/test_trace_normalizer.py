"""
Unit tests for Runtime Trace Normalization [Role A].
Tests OpenTelemetry trace ingestion, span extraction, relationship deduplication,
evidence linkage, and failed connection handling.
"""

import json
import pytest
from app.ingestion.trace_normalizer import (
    parse_runtime_traces,
    normalize_runtime_traces,
    TraceNormalizationResult
)


def test_parse_runtime_traces_backward_compatible():
    """Verifies existing public parse_runtime_traces function."""
    traces = parse_runtime_traces("fixtures/runtime/traces.sample.json")
    assert isinstance(traces, list)
    assert len(traces) == 3
    assert traces[0]["destination_host"] == "api.stripe.com"


def test_trace_normalization_and_deduplication():
    """Verifies that multiple calls to the same endpoint/host are deduplicated with aggregated evidence."""
    raw_spans = [
        {
            "trace_id": "t1",
            "span_id": "s1",
            "name": "POST /checkout",
            "timestamp": "2026-10-31T12:00:01Z",
            "http_target": "https://api.stripe.com/v1/charges",
            "http_method": "POST",
            "status_code": 200,
            "destination_host": "api.stripe.com",
            "duration_ms": 150.0
        },
        {
            "trace_id": "t1",
            "span_id": "s2",
            "name": "POST /checkout",
            "timestamp": "2026-10-31T12:00:02Z",
            "http_target": "https://api.stripe.com/v1/charges",
            "http_method": "POST",
            "status_code": 200,
            "destination_host": "api.stripe.com",
            "duration_ms": 170.0
        },
        {
            "trace_id": "t2",
            "span_id": "s3",
            "name": "POST /track",
            "timestamp": "2026-10-31T12:00:03Z",
            "http_target": "https://telemetry.untrusted-cdn.net/collect",
            "http_method": "POST",
            "status_code": 204,
            "destination_host": "telemetry.untrusted-cdn.net",
            "duration_ms": 300.0
        }
    ]

    result = normalize_runtime_traces(raw_spans)

    assert result.total_spans_ingested == 3
    # 2 calls to stripe + 1 call to telemetry = 2 unique groups
    assert len(result.observed_groups) == 2

    stripe_group = next(g for g in result.observed_groups if g.destination_host == "api.stripe.com")
    assert stripe_group.frequency_count == 2
    assert stripe_group.successful_calls == 2
    assert stripe_group.failed_calls == 0
    assert stripe_group.average_duration_ms == 160.0
    assert len(stripe_group.evidence_ids) == 2
    assert "trace:t1:s1" in stripe_group.evidence_ids
    assert "trace:t1:s2" in stripe_group.evidence_ids

    # Nodes
    node_ids = [n["id"] for n in result.nodes]
    assert "ext:api.stripe.com" in node_ids
    assert "ext:telemetry.untrusted-cdn.net" in node_ids

    stripe_node = next(n for n in result.nodes if n["id"] == "ext:api.stripe.com")
    assert stripe_node["type"] == "external_api"
    assert stripe_node["provenance"] == "observed"
    assert stripe_node["status"] == "healthy"

    # Edges
    assert len(result.edges) == 2
    stripe_edge = next(e for e in result.edges if e["target"] == "ext:api.stripe.com")
    assert stripe_edge["relation"] == "calls_api"
    assert stripe_edge["provenance"] == "observed"
    assert stripe_edge["evidence_ids"] == ["trace:t1:s1", "trace:t1:s2"]

    # Evidence
    assert len(result.evidence) == 3
    ev1 = next(ev for ev in result.evidence if ev["id"] == "trace:t1:s1")
    assert ev1["evidence_type"] == "observed"
    assert ev1["collector"] == "otel-trace-normalizer"
    assert ev1["observed_details"]["destination_host"] == "api.stripe.com"


def test_failed_connection_distinguishes_server_error_from_unreachable():
    """
    Verifies that HTTP 503 is marked warning (unhealthy server response),
    whereas actual connection failure (no status code / code 0) is marked unreachable.
    """
    # 1. HTTP 503 server error -> warning
    spans_503 = [
        {
            "trace_id": "fail_503_t",
            "span_id": "fail_503_s",
            "name": "GET /status",
            "timestamp": "2026-10-31T12:00:00Z",
            "http_target": "https://failing-partner.com/api",
            "http_method": "GET",
            "status_code": 503,
            "destination_host": "failing-partner.com",
            "duration_ms": 2500.0
        }
    ]
    res_503 = normalize_runtime_traces(spans_503)
    node_503 = next(n for n in res_503.nodes if n["id"] == "ext:failing-partner.com")
    assert node_503["status"] == "warning"
    assert node_503["metadata"]["successful_calls"] == 0
    assert node_503["metadata"]["failed_calls"] == 1
    assert node_503["metadata"]["server_errors"] == 1
    assert node_503["metadata"]["connection_failures"] == 0

    # 2. Complete connection failure (status code is None) -> unreachable
    spans_conn_fail = [
        {
            "trace_id": "fail_conn_t",
            "span_id": "fail_conn_s",
            "name": "GET /timeout",
            "timestamp": "2026-10-31T12:00:00Z",
            "http_target": "https://dead-endpoint.com/api",
            "http_method": "GET",
            "status_code": None,
            "destination_host": "dead-endpoint.com",
            "duration_ms": 5000.0,
            "note": "Connection timed out"
        }
    ]
    res_conn_fail = normalize_runtime_traces(spans_conn_fail)
    node_conn_fail = next(n for n in res_conn_fail.nodes if n["id"] == "ext:dead-endpoint.com")
    assert node_conn_fail["status"] == "unreachable"
    assert node_conn_fail["metadata"]["successful_calls"] == 0
    assert node_conn_fail["metadata"]["failed_calls"] == 1
    assert node_conn_fail["metadata"]["server_errors"] == 0
    assert node_conn_fail["metadata"]["connection_failures"] == 1


def test_span_deduplication_by_trace_and_span_id():
    """
    Verifies that identical spans with the same trace_id and span_id
    are deduplicated and do not inflate frequency counts or duplicate evidence IDs.
    """
    duplicated_spans = [
        {
            "trace_id": "trace-dup-1",
            "span_id": "span-dup-1",
            "name": "POST /payment",
            "timestamp": "2026-10-31T12:00:00Z",
            "http_target": "https://api.stripe.com/v1/charges",
            "http_method": "POST",
            "status_code": 200,
            "destination_host": "api.stripe.com",
            "duration_ms": 100.0
        },
        # Duplicate of the exact same span
        {
            "trace_id": "trace-dup-1",
            "span_id": "span-dup-1",
            "name": "POST /payment",
            "timestamp": "2026-10-31T12:00:00Z",
            "http_target": "https://api.stripe.com/v1/charges",
            "http_method": "POST",
            "status_code": 200,
            "destination_host": "api.stripe.com",
            "duration_ms": 100.0
        }
    ]

    result = normalize_runtime_traces(duplicated_spans)
    assert result.total_spans_ingested == 1
    stripe_group = next(g for g in result.observed_groups if g.destination_host == "api.stripe.com")
    assert stripe_group.frequency_count == 1
    assert stripe_group.evidence_ids == ["trace:trace-dup-1:span-dup-1"]


def test_destination_hostname_normalization():
    """Verifies consistent normalization of hostnames with ports, schemes, and uppercase letters."""
    spans = [
        {
            "trace_id": "t-norm-1",
            "span_id": "s-norm-1",
            "http_target": "https://API.Stripe.com:443/v1/charges",
            "http_method": "POST",
            "status_code": 200,
            "destination_host": "API.STRIPE.COM:443",
            "duration_ms": 120.0
        },
        {
            "trace_id": "t-norm-2",
            "span_id": "s-norm-2",
            "http_target": "http://api.stripe.com:80/v1/charges",
            "http_method": "POST",
            "status_code": 200,
            "destination_host": "api.stripe.com.",
            "duration_ms": 130.0
        }
    ]
    result = normalize_runtime_traces(spans)
    # Both spans should be grouped together under the normalized host api.stripe.com
    assert len(result.observed_groups) == 1
    assert result.observed_groups[0].destination_host == "api.stripe.com"
    assert result.nodes[0]["id"] == "ext:api.stripe.com"


def test_source_service_explicit_vs_default():
    """
    Verifies that explicit source_service in trace data is used,
    default application node ID is used as fallback, and no hardcoded
    name string matching occurs.
    """
    spans = [
        {
            "trace_id": "t-src-1",
            "span_id": "s-src-1",
            "name": "POST /checkout",  # Contains 'checkout', but should NOT hardcode to nexus-frontend
            "source_service": "service:custom-cart",
            "http_target": "https://api.stripe.com/v1/charges",
            "http_method": "POST",
            "status_code": 200,
            "destination_host": "api.stripe.com",
            "duration_ms": 100.0
        },
        {
            "trace_id": "t-src-2",
            "span_id": "s-src-2",
            "name": "POST /checkout",  # Without explicit source_service, falls back to default
            "http_target": "https://api.stripe.com/v1/charges",
            "http_method": "POST",
            "status_code": 200,
            "destination_host": "api.stripe.com",
            "duration_ms": 100.0
        }
    ]
    result = normalize_runtime_traces(spans, default_source_service="app:default-service")
    edges_by_src = {e["source"]: e for e in result.edges}
    assert "service:custom-cart" in edges_by_src
    assert "app:default-service" in edges_by_src
    assert "app:nexus-frontend" not in edges_by_src


def test_edge_uniqueness_for_different_http_methods():
    """
    Regression test for Requirement 2:
    GET and POST requests from the same source to the same destination
    must produce unique edge IDs with no collisions.
    """
    spans = [
        {
            "trace_id": "t-method-1",
            "span_id": "s-method-1",
            "http_target": "https://api.stripe.com/v1/customers",
            "http_method": "GET",
            "status_code": 200,
            "destination_host": "api.stripe.com",
            "duration_ms": 100.0
        },
        {
            "trace_id": "t-method-2",
            "span_id": "s-method-2",
            "http_target": "https://api.stripe.com/v1/charges",
            "http_method": "POST",
            "status_code": 201,
            "destination_host": "api.stripe.com",
            "duration_ms": 250.0
        }
    ]

    result = normalize_runtime_traces(spans, default_source_service="app:nexus-frontend")

    # Verify edge IDs
    edge_ids = [e["id"] for e in result.edges]
    assert len(edge_ids) == 2
    assert len(set(edge_ids)) == 2, f"Duplicate edge IDs detected: {edge_ids}"

    get_edge = next(e for e in result.edges if e["metadata"]["http_method"] == "GET")
    post_edge = next(e for e in result.edges if e["metadata"]["http_method"] == "POST")

    assert get_edge["id"] != post_edge["id"]
    assert "#GET" in get_edge["id"]
    assert "#POST" in post_edge["id"]
    assert get_edge["source"] == "app:nexus-frontend"
    assert post_edge["source"] == "app:nexus-frontend"
    assert get_edge["target"] == "ext:api.stripe.com"
    assert post_edge["target"] == "ext:api.stripe.com"


def test_endpoint_level_aggregation_across_multiple_sources_and_methods():
    """
    Regression test for Requirement 3:
    When multiple source services and HTTP methods communicate with the same external host,
    aggregate the endpoint node's statistics across all groups.
    Keep source-specific and method-specific statistics on their respective edges.
    """
    spans = [
        # Source 1, GET (3 calls, 200 OK, 100ms)
        {
            "trace_id": "t1",
            "span_id": "s1",
            "source_service": "service:orders",
            "http_target": "https://api.stripe.com/v1/charges/ch_1",
            "http_method": "GET",
            "status_code": 200,
            "destination_host": "api.stripe.com",
            "duration_ms": 100.0
        },
        {
            "trace_id": "t1",
            "span_id": "s2",
            "source_service": "service:orders",
            "http_target": "https://api.stripe.com/v1/charges/ch_2",
            "http_method": "GET",
            "status_code": 200,
            "destination_host": "api.stripe.com",
            "duration_ms": 100.0
        },
        {
            "trace_id": "t1",
            "span_id": "s3",
            "source_service": "service:orders",
            "http_target": "https://api.stripe.com/v1/charges/ch_3",
            "http_method": "GET",
            "status_code": 200,
            "destination_host": "api.stripe.com",
            "duration_ms": 100.0
        },
        # Source 1, POST (2 calls, 500 server error, 200ms)
        {
            "trace_id": "t2",
            "span_id": "s4",
            "source_service": "service:orders",
            "http_target": "https://api.stripe.com/v1/refunds",
            "http_method": "POST",
            "status_code": 500,
            "destination_host": "api.stripe.com",
            "duration_ms": 200.0
        },
        {
            "trace_id": "t2",
            "span_id": "s5",
            "source_service": "service:orders",
            "http_target": "https://api.stripe.com/v1/refunds",
            "http_method": "POST",
            "status_code": 500,
            "destination_host": "api.stripe.com",
            "duration_ms": 200.0
        },
        # Source 2, POST (1 call, 404 client error, 300ms)
        {
            "trace_id": "t3",
            "span_id": "s6",
            "source_service": "service:billing",
            "http_target": "https://api.stripe.com/v1/invoices/inv_missing",
            "http_method": "POST",
            "status_code": 404,
            "destination_host": "api.stripe.com",
            "duration_ms": 300.0
        }
    ]

    result = normalize_runtime_traces(spans)

    # There should only be 1 endpoint node for api.stripe.com
    stripe_nodes = [n for n in result.nodes if n["id"] == "ext:api.stripe.com"]
    assert len(stripe_nodes) == 1
    node = stripe_nodes[0]
    meta = node["metadata"]

    # Total observed calls: 3 + 2 + 1 = 6
    assert meta["total_observed_calls"] == 6
    # Successful calls: 3
    assert meta["successful_calls"] == 3
    # Failed calls: 2 (500) + 1 (404) = 3
    assert meta["failed_calls"] == 3
    # Client errors: 1 (404)
    assert meta["client_errors"] == 1
    # Server errors: 2 (500)
    assert meta["server_errors"] == 2
    # Connection failures: 0
    assert meta["connection_failures"] == 0
    # Average duration: (3*100 + 2*200 + 1*300) / 6 = 1000 / 6 = 166.67
    assert meta["average_duration_ms"] == 166.67

    # Edges maintain source and method specific stats
    assert len(result.edges) == 3
    orders_get = next(e for e in result.edges if e["source"] == "service:orders" and e["metadata"]["http_method"] == "GET")
    assert orders_get["metadata"]["frequency_count"] == 3
    assert orders_get["metadata"]["successful_calls"] == 3
    assert orders_get["metadata"]["failed_calls"] == 0
    assert orders_get["metadata"]["average_duration_ms"] == 100.0

    orders_post = next(e for e in result.edges if e["source"] == "service:orders" and e["metadata"]["http_method"] == "POST")
    assert orders_post["metadata"]["frequency_count"] == 2
    assert orders_post["metadata"]["successful_calls"] == 0
    assert orders_post["metadata"]["server_errors"] == 2
    assert orders_post["metadata"]["failed_calls"] == 2
    assert orders_post["metadata"]["average_duration_ms"] == 200.0

    billing_post = next(e for e in result.edges if e["source"] == "service:billing" and e["metadata"]["http_method"] == "POST")
    assert billing_post["metadata"]["frequency_count"] == 1
    assert billing_post["metadata"]["successful_calls"] == 0
    assert billing_post["metadata"]["client_errors"] == 1
    assert billing_post["metadata"]["failed_calls"] == 1
    assert billing_post["metadata"]["average_duration_ms"] == 300.0


def test_http_status_classification_distinctions():
    """
    Regression test for Requirement 4:
    Properly separate 4xx client errors, 5xx server errors, 200 success, and no response / code 0.
    404 and 401 must not be classified as server errors or unreachable.
    """
    # 1. HTTP 200 OK
    res_200 = normalize_runtime_traces([{
        "trace_id": "t200", "span_id": "s200", "http_target": "https://api.test.com/ok",
        "http_method": "GET", "status_code": 200, "destination_host": "api.test.com"
    }])
    n200 = res_200.nodes[0]
    assert n200["status"] == "healthy"
    assert n200["metadata"]["successful_calls"] == 1
    assert n200["metadata"]["failed_calls"] == 0
    assert n200["metadata"]["client_errors"] == 0
    assert n200["metadata"]["server_errors"] == 0
    assert n200["metadata"]["connection_failures"] == 0

    # 2. HTTP 401 Unauthorized
    res_401 = normalize_runtime_traces([{
        "trace_id": "t401", "span_id": "s401", "http_target": "https://api.auth.com/login",
        "http_method": "POST", "status_code": 401, "destination_host": "api.auth.com"
    }])
    n401 = res_401.nodes[0]
    assert n401["status"] != "unreachable"
    assert n401["metadata"]["successful_calls"] == 0
    assert n401["metadata"]["failed_calls"] == 1
    assert n401["metadata"]["client_errors"] == 1
    assert n401["metadata"]["server_errors"] == 0
    assert n401["metadata"]["connection_failures"] == 0

    # 3. HTTP 404 Not Found
    res_404 = normalize_runtime_traces([{
        "trace_id": "t404", "span_id": "s404", "http_target": "https://api.missing.com/item",
        "http_method": "GET", "status_code": 404, "destination_host": "api.missing.com"
    }])
    n404 = res_404.nodes[0]
    assert n404["status"] != "unreachable"
    assert n404["metadata"]["successful_calls"] == 0
    assert n404["metadata"]["failed_calls"] == 1
    assert n404["metadata"]["client_errors"] == 1
    assert n404["metadata"]["server_errors"] == 0
    assert n404["metadata"]["connection_failures"] == 0

    # 4. HTTP 503 Service Unavailable
    res_503 = normalize_runtime_traces([{
        "trace_id": "t503", "span_id": "s503", "http_target": "https://api.down.com/status",
        "http_method": "GET", "status_code": 503, "destination_host": "api.down.com"
    }])
    n503 = res_503.nodes[0]
    assert n503["status"] != "unreachable"
    assert n503["metadata"]["successful_calls"] == 0
    assert n503["metadata"]["failed_calls"] == 1
    assert n503["metadata"]["client_errors"] == 0
    assert n503["metadata"]["server_errors"] == 1
    assert n503["metadata"]["connection_failures"] == 0

    # 5. No response / connection failure (None or 0)
    res_no_resp = normalize_runtime_traces([{
        "trace_id": "t_no_resp", "span_id": "s_no_resp", "http_target": "https://api.unreachable.com/data",
        "http_method": "GET", "status_code": None, "destination_host": "api.unreachable.com"
    }])
    n_no_resp = res_no_resp.nodes[0]
    assert n_no_resp["status"] == "unreachable"
    assert n_no_resp["metadata"]["successful_calls"] == 0
    assert n_no_resp["metadata"]["failed_calls"] == 1
    assert n_no_resp["metadata"]["client_errors"] == 0
    assert n_no_resp["metadata"]["server_errors"] == 0
    assert n_no_resp["metadata"]["connection_failures"] == 1

