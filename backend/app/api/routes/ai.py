"""
Workstream D: AI Routes
Provides privacy-safe vulnerability and dependency explanations via Gemini API.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from app.integrations.gemini import (
    explain_finding,
    sanitize_context_for_gemini,
    enrich_vendor_profile,
    check_gemini_status
)

router = APIRouter()

class ExplainFindingRequest(BaseModel):
    finding_id: str
    title: str
    package_name: Optional[str] = None
    target_node_id: Optional[str] = None
    version: Optional[str] = "unknown"
    cve_id: Optional[str] = None
    severity: str = "medium"
    journey_name: Optional[str] = "Customer Checkout"
    audience: str = Field(default="developer", description="Technical explanation for engineers (builder or enterprise)")
    user_approved_transmission: bool = Field(default=True, description="Must be explicitly acknowledged by user")
    api_key: Optional[str] = Field(default=None, description="Optional user-provided Gemini API key")
    fixed_version: Optional[str] = None
    affected_version_range: Optional[str] = None
    cvss_score: Optional[float] = None
    advisory_source: Optional[str] = None
    advisory_description: Optional[str] = None
    is_verified_vulnerable: Optional[bool] = None

class PreviewPayloadRequest(BaseModel):
    finding_id: str
    title: str
    package_name: Optional[str] = None
    target_node_id: Optional[str] = None
    version: Optional[str] = "unknown"
    cve_id: Optional[str] = None
    severity: str = "medium"
    journey_name: Optional[str] = "Customer Checkout"
    audience: str = "builder"
    fixed_version: Optional[str] = None
    affected_version_range: Optional[str] = None
    cvss_score: Optional[float] = None
    advisory_source: Optional[str] = None
    advisory_description: Optional[str] = None
    is_verified_vulnerable: Optional[bool] = None

class VendorEnrichRequest(BaseModel):
    vendor_domain: str = "stripe.com"

@router.get("/status")
async def get_ai_status(refresh: bool = False):
    """
    Returns the current readiness and configuration status of the Gemini AI integration.
    Supports ?refresh=true to force a fresh verification check against the Google API.
    """
    return check_gemini_status(force_refresh=refresh)

@router.post("/preview-payload")
async def preview_ai_payload(request: PreviewPayloadRequest):
    """
    Returns the exact sanitized payload that will be transmitted to Gemini.
    Provides complete transparency that no source code or secrets are sent.
    """
    raw_dict = request.model_dump()
    sanitized = sanitize_context_for_gemini(raw_dict)
    return {
        "status": "sanitized_for_transmission",
        "privacy_guarantee": "No source code, file paths, tokens, or private hostnames included.",
        "payload_to_send": sanitized
    }

@router.post("/explain")
async def explain_vulnerability(request: ExplainFindingRequest):
    """
    Generates structured AI explanation for a vulnerability finding.
    Enforces user approval and returns structured explanation or explicit error status.
    """
    if not request.user_approved_transmission:
        raise HTTPException(
            status_code=400,
            detail="User must approve transmission of public vulnerability metadata."
        )

    raw_dict = request.model_dump()
    explanation = await explain_finding(raw_dict)
    return explanation

@router.post("/enrich-vendor")
async def enrich_vendor(request: VendorEnrichRequest):
    """
    Enriches detected external domain with known third-party cloud sub-processors.
    """
    return await enrich_vendor_profile(request.vendor_domain)
