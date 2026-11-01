import asyncio
import pytest
from app.integrations.solana import check_solana_devnet_status, verify_bundle_on_solana, send_obv_transfer

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


def test_send_obv_transfer_and_hash():
    sample_obv = {
        "transaction_id": "tx_obv_9921",
        "value": 1500.0,
        "sender": "vault_alpha",
        "receiver": "vendor_solana"
    }
    result = asyncio.run(send_obv_transfer(sample_obv))
    assert result["submitted"] is True
    assert "hash" in result
    assert len(result["hash"]) == 64  # SHA-256 hexdigest length
    assert "explorer_url" in result
    assert "tx_signature" in result
