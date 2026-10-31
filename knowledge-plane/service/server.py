#!/usr/bin/env python3
"""
Workstream D: DigitalOcean Knowledge Distribution Service
Public read-only service for hosting knowledge bundles and vendor passports.
Enforces the privacy-first rule: zero customer data ingestion.
"""
import os
import sys
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent.parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.integrations.knowledge import load_local_knowledge_bundle, fetch_remote_manifest

app = FastAPI(
    title="HDX Public Knowledge Plane (DigitalOcean)",
    version="1.0.0",
    description="Public distribution service for verified vulnerability intelligence and signed vendor passports."
)

@app.get("/health")
def health():
    return {"status": "healthy", "service": "hdx-knowledge-plane-distribution"}

@app.get("/v1/manifest")
async def get_manifest():
    return await fetch_remote_manifest()

@app.get("/v1/bundles/{bundle_id}")
async def get_bundle_by_id(bundle_id: str):
    bundle = load_local_knowledge_bundle()
    return bundle

@app.get("/v1/passports")
def list_vendor_passports():
    bundle = load_local_knowledge_bundle()
    return bundle.get("vendor_passports", [])

# Enforce privacy boundary: explicitly reject any upload
@app.api_route("/v1/{path:path}", methods=["POST", "PUT", "PATCH"])
def reject_customer_uploads(path: str):
    raise HTTPException(
        status_code=405,
        detail="Privacy Constraint Violation: The Knowledge Plane is strictly outbound read-only. Customer data upload is prohibited."
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)

