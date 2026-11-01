"""
Solana integration and Vendor Certificate API routes.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional

from app.integrations.solana import send_obv_transfer, verify_bundle_on_solana
from app.db.repositories import VendorCertificateRepository

router = APIRouter()

class OBVTransferRequest(BaseModel):
    project_name: str = "Target Project"
    obv_payload: Dict[str, Any] = Field(default_factory=dict)
    vendor_key: str = "solana"
    certificate_pem: Optional[str] = None

class CertificateUploadRequest(BaseModel):
    vendor_key: str
    certificate_pem: str

@router.post("/solana-transfer")
async def handle_solana_transfer(req: OBVTransferRequest):
    """
    Executes an On-Chain Value (OBV) transfer hashed with SHA-256 onto Solana.
    If a certificate is provided, verifies and persists vendor authenticity.
    """
    cert_status = None
    if req.certificate_pem:
        await VendorCertificateRepository.save_certificate(req.vendor_key, req.certificate_pem)
        is_valid = await VendorCertificateRepository.verify_certificate(req.vendor_key)
        cert_status = {"stored": True, "valid": is_valid}

    transfer_result = await send_obv_transfer(req.obv_payload)
    if not transfer_result.get("submitted"):
        raise HTTPException(status_code=502, detail="Failed to anchor OBV transfer to Solana")

    verification = await verify_bundle_on_solana(
        bundle_hash=transfer_result.get("hash"),
        tx_signature=transfer_result.get("tx_signature")
    )

    return {
        "status": "success",
        "vendor": req.vendor_key,
        "certificate_status": cert_status,
        "transfer": transfer_result,
        "verification": verification
    }

@router.post("/vendor-certificates")
async def upload_vendor_certificate(req: CertificateUploadRequest):
    """
    Stores and validates a third-party vendor X.509 certificate.
    """
    record = await VendorCertificateRepository.save_certificate(req.vendor_key, req.certificate_pem)
    is_valid = await VendorCertificateRepository.verify_certificate(req.vendor_key)
    return {
        "vendor_key": req.vendor_key,
        "valid": is_valid,
        "created_at": record.get("created_at")
    }

@router.get("/vendor-certificates/{vendor_key}")
async def get_vendor_certificate(vendor_key: str):
    """
    Retrieves stored certificate details and verification state for a vendor.
    """
    record = await VendorCertificateRepository.get_certificate(vendor_key)
    if not record:
        raise HTTPException(status_code=404, detail=f"No certificate found for vendor '{vendor_key}'")
    return record

