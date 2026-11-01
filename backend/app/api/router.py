from fastapi import APIRouter
from app.api.routes import scans, graph, scenarios, ai, knowledge, intelligence, solana

api_router = APIRouter()

api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])
api_router.include_router(graph.router, prefix="/scans", tags=["Graph & Findings"])
api_router.include_router(scenarios.router, prefix="/scans", tags=["Simulation"])
api_router.include_router(ai.router, prefix="/ai", tags=["AI Enrichment"])
api_router.include_router(knowledge.router, prefix="/knowledge", tags=["Knowledge Plane"])
api_router.include_router(intelligence.router, prefix="/scans", tags=["Third-Party Intelligence"])
api_router.include_router(solana.router, prefix="/scans", tags=["Solana & Trust"])
