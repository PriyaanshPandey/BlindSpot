from app.graph import GraphEngine

def test_blast_radius_computation():
    engine = GraphEngine()
    # frontend depends on api, api depends on stripe
    engine.add_edge("app:frontend", "service:api")
    engine.add_edge("service:api", "vendor:stripe")

    blast_radius = engine.get_blast_radius("vendor:stripe")
    assert "vendor:stripe" in blast_radius
    assert "service:api" in blast_radius
    assert "app:frontend" in blast_radius

