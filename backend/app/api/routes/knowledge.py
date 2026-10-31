from fastapi import APIRouter
from app.integrations.knowledge import load_local_knowledge_bundle
from app.integrations.solana import verify_bundle_on_solana

router = APIRouter()

@router.get("/bundle")
async def get_bundle():
    bundle_meta = load_local_knowledge_bundle()
    solana_check = await verify_bundle_on_solana(bundle_meta["solana_hash"])
    return {
        **bundle_meta,
        "solana_verification": solana_check
    }

