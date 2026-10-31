from fastapi import APIRouter
from pydantic import BaseModel
from app.integrations.gemini import enrich_vendor_profile

router = APIRouter()

class VendorEnrichRequest(BaseModel):
    vendor_domain: str = "stripe.com"

@router.post("/enrich-vendor")
async def enrich_vendor(request: VendorEnrichRequest):
    return await enrich_vendor_profile(request.vendor_domain)

