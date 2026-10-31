import asyncio
import pytest
from app.integrations.solana import check_solana_devnet_status, verify_bundle_on_solana

def test_solana_devnet_status():
    status = asyncio.run(check_solana_devnet_status())
    assert "online" in status
    assert status["cluster"] == "devnet"

def test_verify_bundle_on_solana():
    test_hash = "7e4dc52a164b0396484b2c96f75731242f12dced"
    result = asyncio.run(verify_bundle_on_solana(test_hash))
    assert result["verified"] is True
    assert result["bundle_hash"] == test_hash
    assert "explorer.solana.com" in result["explorer_url"]
