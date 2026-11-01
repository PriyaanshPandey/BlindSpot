"""
Workstream D: AI Routes
Provides privacy-safe vulnerability and dependency explanations via Gemini API.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from app.integrations.gemini import explain_finding, sanitize_context_for_gemini, enrich_vendor_profile

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
    audience: str = Field(default="developer", description="Technical explanation for engineers")
    user_approved_transmission: bool = Field(default=True, description="Must be explicitly acknowledged by user")
    api_key: Optional[str] = Field(default=None, description="Optional user-provided Gemini API key")

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

class VendorEnrichRequest(BaseModel):
    vendor_domain: str = "stripe.com"

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
    """
    if not request.user_approved_transmission:
        raise HTTPException(
            status_code=400,
            detail="User must approve transmission of public vulnerability metadata."
        )
    raw_dict = request.model_dump()
    result = await explain_finding(raw_dict)
    return result

@router.post("/enrich-vendor")
async def enrich_vendor(request: VendorEnrichRequest):
    """
    Retrieves publicly disclosed sub-processors and cloud infrastructure for a third-party vendor.
    """
    return await enrich_vendor_profile(request.vendor_domain)
