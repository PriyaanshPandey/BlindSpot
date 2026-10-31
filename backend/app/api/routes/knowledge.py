"""
Workstream D: Knowledge Routes
Exposes knowledge manifest retrieval, bundle downloading, and cryptographic verification.
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Dict, Any

from app.integrations.knowledge import (
    load_local_knowledge_bundle,
    fetch_remote_manifest,
    verify_bundle_integrity
)
from app.integrations.signing import verify_bundle

router = APIRouter()

class VerifyBundleRequest(BaseModel):
    bundle: Optional[Dict[str, Any]] = None
    simulate_tamper: bool = False

@router.get("/manifest")
async def get_knowledge_manifest():
    """
    Returns public knowledge manifest with bundle hashes and distribution channels.
    """
    return await fetch_remote_manifest()

@router.get("/bundle")
async def get_current_bundle():
    """
    Returns the currently active signed knowledge bundle.
    """
    bundle = load_local_knowledge_bundle()
    verification = await verify_bundle_integrity(bundle)
    return {
        "bundle": bundle,
        "verification_summary": verification
    }

@router.post("/verify")
async def verify_bundle_endpoint(request: VerifyBundleRequest):
    """
    Executes live verification against Ed25519 signature and Solana Devnet Anchor.
    If simulate_tamper is True, alters payload to demonstrate that tampered bundles are rejected.
    """
    target_bundle = request.bundle or load_local_knowledge_bundle()
    
    if request.simulate_tamper:
        # Deliberately modify bundle content to test tamper resistance
        target_bundle = dict(target_bundle)
        target_bundle["advisories_count"] = 999999
        target_bundle["tamper_injected"] = "Unauthorized adversary modification"

    integrity_report = await verify_bundle_integrity(target_bundle)
    return integrity_report
