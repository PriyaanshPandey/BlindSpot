"""
Runtime Trace Normalization Subsystem [Role A]:
Ingests OpenTelemetry and browser network traces. Normalizes raw HTTP observations into
evidence-backed observed dependencies with deduplication, timestamp tracking,
and distinction between successful connections and failed/attempted requests.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("hdx.ingestion.traces")


@dataclass
class ObservedSpan:
    """Individual span record parsed from trace telemetry."""
    trace_id: str
    span_id: str
    name: str
    timestamp: str
    http_target: str
    http_method: str
    status_code: Optional[int]
    destination_host: str
    duration_ms: float
    note: Optional[str] = None

    @property
    def is_successful(self) -> bool:
        if self.status_code is None:
            return False
        return 200 <= self.status_code < 400

    @property
    def is_client_error(self) -> bool:
        if self.status_code is None:
            return False
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        if self.status_code is None:
            return False
        return 500 <= self.status_code < 600

    @property
    def is_connection_failure(self) -> bool:
        return self.status_code is None or self.status_code == 0

    @property
    def evidence_id(self) -> str:
        return f"trace:{self.trace_id}:{self.span_id}"


@dataclass
class ObservedDependencyGroup:
    """Aggregated, deduplicated relationship between a source service and external destination."""
    source_service: str
    destination_host: str
    endpoint: str
    http_method: str
    frequency_count: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    client_error_calls: int = 0
    server_error_calls: int = 0
    connection_failure_calls: int = 0
    total_duration_ms: float = 0.0
    first_seen: str = ""
    last_seen: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    spans: List[ObservedSpan] = field(default_factory=list)

    @property
    def average_duration_ms(self) -> float:
        return round(self.total_duration_ms / max(1, self.frequency_count), 2)

    @property
    def connection_status(self) -> str:
        """
        Determines health status based on call outcomes.
        Distinguishes 4xx client errors, 5xx server errors, and complete connection failures.
        A 404 or 401 response is not classified as a server error or unreachable.
        """
        if self.frequency_count == 0:
            return "unknown"
        # Connection failure = client could not connect at all (no status code / code 0)
        if self.connection_failure_calls > 0 and self.successful_calls == 0 and self.server_error_calls == 0 and self.client_error_calls == 0:
            return "unreachable"
        if self.server_error_calls > 0 or self.connection_failure_calls > 0 or self.client_error_calls > 0:
            return "warning"
        return "healthy"

    @property
    def confidence_score(self) -> float:
        """Computes confidence score based on observation frequency and success."""
        base = 0.95 if self.successful_calls > 0 else 0.70
        freq_boost = min(0.04, self.frequency_count * 0.01)
        return round(min(1.0, base + freq_boost), 2)

    @property
    def target_node_id(self) -> str:
        return f"ext:{self.destination_host}"


@dataclass
class TraceNormalizationResult:
    """Consolidated result containing normalized observed nodes, edges, and evidence records."""
    total_spans_ingested: int
    observed_groups: List[ObservedDependencyGroup] = field(default_factory=list)
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)


def parse_runtime_traces(trace_file_path: str) -> List[Dict[str, Any]]:
    """
    Public backward-compatible parser for raw runtime trace JSON files.
    """
    if not os.path.exists(trace_file_path):
        return []
    try:
        with open(trace_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception as e:
        logger.warning(f"Failed to read trace file at {trace_file_path}: {e}")
        return []


def _get_source_service(span_data: Dict[str, Any], default_source: str) -> str:
    """
    Extracts an explicit source-service identifier when provided by trace data;
    otherwise uses the supplied default application node ID.
    Does NOT use hardcoded keyword matching on span names.
    """
    explicit = (
        span_data.get("source_service")
        or span_data.get("source")
        or span_data.get("service_name")
        or span_data.get("service")
    )
    if explicit and isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    return default_source


def _normalize_host(raw_host: str) -> str:
    """
    Normalizes destination hostnames consistently:
    strips whitespace, lowercases, removes URI scheme, trailing paths, default ports (:80, :443),
    and trailing dots.
    """
    if not raw_host:
        return "unknown-external-host"
    host = str(raw_host).strip().lower()
    if "://" in host:
        parsed = urlparse(host)
        host = parsed.netloc or parsed.path
    if "/" in host:
        host = host.split("/")[0]
    if ":" in host:
        parts = host.split(":")
        if len(parts) == 2 and parts[1] in ("80", "443"):
            host = parts[0]
    host = host.rstrip(".")
    return host or "unknown-external-host"


def _extract_destination_host(span_data: Dict[str, Any]) -> str:
    """Extracts and normalizes external destination hostname."""
    if span_data.get("destination_host"):
        return _normalize_host(span_data["destination_host"])
    target = span_data.get("http_target", "")
    if target:
        parsed = urlparse(target)
        if parsed.netloc:
            return _normalize_host(parsed.netloc)
    return "unknown-external-host"


def normalize_runtime_traces(
    raw_spans: List[Dict[str, Any]],
    default_source_service: str = "app:nexus-frontend",
    collector_name: str = "otel-trace-normalizer"
) -> TraceNormalizationResult:
    """
    Normalizes a list of raw trace span dictionaries into structured observed dependencies,
    deduplicating repeated spans by (trace_id, span_id) so duplicate evidence IDs do not inflate
    frequency counts, and grouping relationships consistently.
    """
    # 1. Deduplicate raw spans by (trace_id, span_id)
    seen_span_ids: Set[str] = set()
    deduped_raw_spans: List[Dict[str, Any]] = []

    for item in raw_spans:
        t_id = str(item.get("trace_id", "")).strip()
        s_id = str(item.get("span_id", "")).strip()
        if t_id and s_id:
            span_key = f"{t_id}:{s_id}"
            if span_key in seen_span_ids:
                # Duplicate span: ignore to prevent inflating frequency counts
                continue
            seen_span_ids.add(span_key)
        deduped_raw_spans.append(item)

    parsed_spans: List[ObservedSpan] = []
    for item in deduped_raw_spans:
        trace_id = str(item.get("trace_id", "unknown-trace")).strip()
        span_id = str(item.get("span_id", "unknown-span")).strip()
        dest_host = _extract_destination_host(item)
        target = item.get("http_target", "")
        method = item.get("http_method", "GET").upper()
        status = item.get("status_code")
        status_int = int(status) if status is not None else None
        duration = float(item.get("duration_ms", 0.0))
        ts = item.get("timestamp") or datetime.now(timezone.utc).isoformat()

        span = ObservedSpan(
            trace_id=trace_id,
            span_id=span_id,
            name=item.get("name", f"{method} {target}"),
            timestamp=ts,
            http_target=target,
            http_method=method,
            status_code=status_int,
            destination_host=dest_host,
            duration_ms=duration,
            note=item.get("note")
        )
        parsed_spans.append(span)

    # 2. Group and aggregate by (source_service, destination_host, method)
    groups_map: Dict[str, ObservedDependencyGroup] = {}
    evidence_records: List[Dict[str, Any]] = []

    for idx, raw_item in enumerate(deduped_raw_spans):
        span = parsed_spans[idx]
        src_service = _get_source_service(raw_item, default_source_service)
        endpoint = span.http_target or span.destination_host

        group_key = f"{src_service}->{span.destination_host}#{span.http_method}"

        if group_key not in groups_map:
            groups_map[group_key] = ObservedDependencyGroup(
                source_service=src_service,
                destination_host=span.destination_host,
                endpoint=endpoint,
                http_method=span.http_method,
                first_seen=span.timestamp,
                last_seen=span.timestamp
            )

        group = groups_map[group_key]
        group.frequency_count += 1
        group.total_duration_ms += span.duration_ms
        group.spans.append(span)
        if span.evidence_id not in group.evidence_ids:
            group.evidence_ids.append(span.evidence_id)
        group.last_seen = span.timestamp

        if span.is_successful:
            group.successful_calls += 1
        elif span.is_client_error:
            group.failed_calls += 1
            group.client_error_calls += 1
        elif span.is_server_error:
            group.failed_calls += 1
            group.server_error_calls += 1
        else:
            group.failed_calls += 1
            group.connection_failure_calls += 1

        # Build evidence record strictly matching contracts/evidence-schema.json
        evidence_rec = {
            "id": span.evidence_id,
            "evidence_type": "observed",
            "collected_at": span.timestamp,
            "collector": collector_name,
            "confidence": 0.99 if span.is_successful else 0.75,
            "observed_details": {
                "source": "otel_trace",
                "endpoint": span.http_target,
                "destination_host": span.destination_host,
                "protocol": "https" if span.http_target.startswith("https") else "http",
                "method": span.http_method,
                "trace_id": span.trace_id,
                "span_id": span.span_id,
                "frequency_count": 1
            }
        }
        evidence_records.append(evidence_rec)

    # Convert groups into Graph Nodes and Edges matching graph-schema.json
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    # 1. Endpoint-level Aggregation: Aggregate statistics across all source services and methods per host
    endpoint_groups: Dict[str, List[ObservedDependencyGroup]] = {}
    for group in groups_map.values():
        endpoint_groups.setdefault(group.target_node_id, []).append(group)

    for target_id, host_groups in endpoint_groups.items():
        sample_group = host_groups[0]
        dest_host = sample_group.destination_host
        total_calls = sum(g.frequency_count for g in host_groups)
        successful_calls = sum(g.successful_calls for g in host_groups)
        failed_calls = sum(g.failed_calls for g in host_groups)
        client_errors = sum(g.client_error_calls for g in host_groups)
        server_errors = sum(g.server_error_calls for g in host_groups)
        connection_failures = sum(g.connection_failure_calls for g in host_groups)
        total_duration = sum(g.total_duration_ms for g in host_groups)
        avg_duration = round(total_duration / max(1, total_calls), 2)

        # Aggregate health status across all communicating services/methods
        if total_calls == 0:
            endpoint_status = "unknown"
        elif connection_failures > 0 and successful_calls == 0 and server_errors == 0 and client_errors == 0:
            endpoint_status = "unreachable"
        elif server_errors > 0 or connection_failures > 0 or client_errors > 0:
            endpoint_status = "warning"
        else:
            endpoint_status = "healthy"

        criticality = "high" if "telemetry" not in dest_host else "medium"
        nodes.append({
            "id": target_id,
            "label": dest_host,
            "type": "external_api",
            "subtype": "observed_endpoint",
            "version": None,
            "provenance": "observed",
            "status": endpoint_status,
            "criticality": criticality,
            "metadata": {
                "total_observed_calls": total_calls,
                "successful_calls": successful_calls,
                "failed_calls": failed_calls,
                "client_errors": client_errors,
                "server_errors": server_errors,
                "connection_failures": connection_failures,
                "average_duration_ms": avg_duration,
                "sample_endpoint": sample_group.endpoint
            }
        })

    # 2. Edges: Keep source-specific and method-specific statistics on each respective edge
    for group in groups_map.values():
        target_id = group.target_node_id
        # Include normalized HTTP method in edge ID to guarantee edge uniqueness across multiple methods
        edge_id = f"edge:obs:{group.source_service}->{target_id}#{group.http_method}"
        edges.append({
            "id": edge_id,
            "source": group.source_service,
            "target": target_id,
            "relation": "calls_api",
            "provenance": "observed",
            "confidence_score": group.confidence_score,
            "evidence_ids": list(group.evidence_ids),
            "metadata": {
                "frequency_count": group.frequency_count,
                "successful_calls": group.successful_calls,
                "failed_calls": group.failed_calls,
                "client_errors": group.client_error_calls,
                "server_errors": group.server_error_calls,
                "connection_failures": group.connection_failure_calls,
                "average_duration_ms": group.average_duration_ms,
                "http_method": group.http_method,
                "first_seen": group.first_seen,
                "last_seen": group.last_seen
            }
        })

    return TraceNormalizationResult(
        total_spans_ingested=len(parsed_spans),
        observed_groups=list(groups_map.values()),
        nodes=nodes,
        edges=edges,
        evidence=evidence_records
    )
