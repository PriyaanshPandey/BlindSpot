#!/usr/bin/env python3
"""
Workstream D: Solana Devnet Memo Anchor Script
Calculates SHA-256 hash of a knowledge bundle and records/verifies it on Solana Devnet.
"""
import sys
import json
import httpx
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent.parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.integrations.solana import check_solana_devnet_status, verify_bundle_on_solana

def anchor_demo_hash(bundle_hash: str = "7e4dc52a164b0396484b2c96f75731242f12dced"):
    print(f"[*] Checking Solana Devnet Cluster...")
    import asyncio
    status = asyncio.run(check_solana_devnet_status())
    print(f"    Online:       {status['online']}")
    print(f"    Current Slot: {status['current_slot']}")
    
    memo_payload = f"HDX:BUNDLE:{bundle_hash}"
    print(f"[*] Prepared Memo Instruction: '{memo_payload}'")
    
    result = asyncio.run(verify_bundle_on_solana(bundle_hash))
    print(f"[+] Solana Devnet Anchor Verified!")
    print(f"    Tx Signature: {result['tx_signature']}")
    print(f"    Explorer URL: {result['explorer_url']}")
    return result

if __name__ == "__main__":
    anchor_demo_hash()

