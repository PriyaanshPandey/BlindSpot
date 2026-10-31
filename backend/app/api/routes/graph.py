from fastapi import APIRouter, HTTPException, Query
from datetime import datetime
from typing import Optional, List, Literal
from app.db.repositories import GraphRepository, FindingRepository, EvidenceRepository, ScanRepository
from app.graph import GraphEngine

router = APIRouter()

VALID_FILTER_LAYERS = {"all", "declared_only", "observed_only", "discrepancies_only"}

@router.get("/{scan_id}/graph")
async def get_scan_graph(
    scan_id: str,
    filter_layer: Literal["all", "declared_only", "observed_only", "discrepancies_only"] = Query(
        "all",
        description="Layer filter: all, declared_only, observed_only, discrepancies_only"
    )
):
    if not isinstance(filter_layer, str):
        filter_layer = getattr(filter_layer, "default", "all")

    if filter_layer not in VALID_FILTER_LAYERS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid filter_layer: '{filter_layer}'. Must be one of: {sorted(list(VALID_FILTER_LAYERS))}"
        )
    scan = await ScanRepository.get_scan(scan_id)
    graph_data = await GraphRepository.get_graph(scan_id)

    if not scan and not graph_data:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not graph_data:
        return {
            "scan_id": scan_id,
            "created_at": scan.get("started_at", datetime.utcnow().isoformat()) if scan else datetime.utcnow().isoformat(),
            "nodes": [],
            "edges": [],
            "metadata": {
                "target_name": scan.get("project_name", "Application") if scan else "Application",
                "total_nodes": 0,
                "total_edges": 0,
                "discrepancy_count": 0,
                "vulnerability_count": 0
            }
        }

    if filter_layer == "all":
        return graph_data

    # Layer-based filtering using GraphEngine
    engine = GraphEngine(scan_id=scan_id)
    engine.created_at = graph_data.get("created_at", datetime.utcnow().isoformat())
    engine.target_name = graph_data.get("metadata", {}).get("target_name", "Application")
    for node in graph_data.get("nodes", []):
        engine.add_node(
            node_id=node["id"],
            label=node["label"],
            node_type=node["type"],
            subtype=node.get("subtype"),
            version=node.get("version"),
            provenance=node.get("provenance", "declared"),
            status=node.get("status", "healthy"),
            criticality=node.get("criticality", "medium"),
            metadata=node.get("metadata")
        )
    for edge in graph_data.get("edges", []):
        engine.add_edge(
            source=edge["source"],
            target=edge["target"],
            relation=edge.get("relation", "depends_on"),
            provenance=edge.get("provenance", "declared"),
            confidence_score=edge.get("confidence_score", 1.0),
            evidence_ids=edge.get("evidence_ids"),
            metadata=edge.get("metadata"),
            edge_id=edge.get("id")
        )
    return engine.to_dict(filter_layer=filter_layer)

@router.get("/{scan_id}/findings")
async def get_scan_findings(scan_id: str):
    scan = await ScanRepository.get_scan(scan_id)
    findings = await FindingRepository.get_findings(scan_id)

    if not scan and not findings:
        raise HTTPException(status_code=404, detail="Scan not found")

    return findings or []

@router.get("/{scan_id}/evidence")
async def get_scan_evidence(scan_id: str):
    scan = await ScanRepository.get_scan(scan_id)
    evidence = await EvidenceRepository.get_evidence(scan_id)

    if not scan and not evidence:
        raise HTTPException(status_code=404, detail="Scan not found")

    return evidence or []
