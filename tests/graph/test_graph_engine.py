try:
    import pytest
except ImportError:
    pass
from app.graph import GraphEngine
from app.models import NodeType, NodeProvenance, NodeStatus, Criticality, EdgeRelation, EdgeProvenance

def test_blast_radius_computation():
    engine = GraphEngine()
    # Directed dependency: frontend depends on api, api depends on stripe
    engine.add_node("app:frontend", "Frontend App", NodeType.APPLICATION)
    engine.add_node("service:api", "API Gateway", NodeType.INTERNAL_SERVICE)
    engine.add_node("vendor:stripe", "Stripe Payments", NodeType.VENDOR)

    engine.add_edge("app:frontend", "service:api", EdgeRelation.CALLS_API)
    engine.add_edge("service:api", "vendor:stripe", EdgeRelation.CALLS_API)

    # If Stripe fails, api and frontend are impacted
    blast_radius = engine.get_blast_radius("vendor:stripe")
    assert "vendor:stripe" in blast_radius
    assert "service:api" in blast_radius
    assert "app:frontend" in blast_radius

def test_find_dependency_chains():
    engine = GraphEngine()
    engine.add_node("app:ui", "UI", NodeType.APPLICATION)
    engine.add_node("service:gateway", "Gateway", NodeType.INTERNAL_SERVICE)
    engine.add_node("service:orders", "Orders", NodeType.INTERNAL_SERVICE)
    engine.add_node("vendor:db", "Database", NodeType.INFRASTRUCTURE_RESOURCE)

    engine.add_edge("app:ui", "service:gateway")
    engine.add_edge("service:gateway", "service:orders")
    engine.add_edge("service:orders", "vendor:db")

    chains = engine.find_dependency_chains("app:ui", "vendor:db")
    assert len(chains) == 1
    assert chains[0] == ["app:ui", "service:gateway", "service:orders", "vendor:db"]

def test_isolated_nodes():
    engine = GraphEngine()
    engine.add_node("node:connected1", "Connected 1", NodeType.APPLICATION)
    engine.add_node("node:connected2", "Connected 2", NodeType.INTERNAL_SERVICE)
    engine.add_node("node:isolated", "Isolated Component", NodeType.RUNTIME_COMPONENT)

    engine.add_edge("node:connected1", "node:connected2")

    isolated = engine.get_isolated_nodes()
    assert "node:isolated" in isolated
    assert "node:connected1" not in isolated

def test_graph_filtering_layers():
    engine = GraphEngine()
    engine.add_node("node:dec", "Declared Node", NodeType.APPLICATION, provenance=NodeProvenance.DECLARED)
    engine.add_node("node:obs", "Observed Node", NodeType.EXTERNAL_API, provenance=NodeProvenance.OBSERVED, status=NodeStatus.WARNING)
    engine.add_edge("node:dec", "node:obs", relation=EdgeRelation.CALLS_API, provenance=EdgeProvenance.OBSERVED)

    # declared_only filter
    dec_graph = engine.to_dict(filter_layer="declared_only")
    node_ids = [n["id"] for n in dec_graph["nodes"]]
    assert "node:dec" in node_ids
    assert "node:obs" not in node_ids

    # observed_only filter
    obs_graph = engine.to_dict(filter_layer="observed_only")
    obs_node_ids = [n["id"] for n in obs_graph["nodes"]]
    assert "node:obs" in obs_node_ids

    # discrepancies_only filter
    disc_graph = engine.to_dict(filter_layer="discrepancies_only")
    disc_node_ids = [n["id"] for n in disc_graph["nodes"]]
    assert "node:obs" in disc_node_ids
