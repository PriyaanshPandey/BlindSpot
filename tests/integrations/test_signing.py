import pytest
from app.integrations.signing import (
    generate_keypair,
    sign_bundle,
    verify_bundle,
    compute_bundle_hash
)

def test_keypair_generation():
    priv, pub = generate_keypair()
    assert len(priv) == 64  # 32 bytes hex
    assert len(pub) == 64   # 32 bytes hex

def test_sign_and_verify_valid_bundle():
    bundle_data = {
        "bundle_id": "test-bundle-001",
        "advisories": [{"cve": "CVE-2018-3721", "pkg": "event-stream"}]
    }
    priv, pub = generate_keypair()
    signed = sign_bundle(bundle_data, private_key_hex=priv)
    
    assert "ed25519_signature" in signed
    assert "bundle_sha256_hash" in signed
    
    # Verify with matching public key
    result = verify_bundle(signed, public_key_hex=pub)
    assert result["is_valid"] is True
    assert result["error"] is None

def test_reject_tampered_bundle():
    bundle_data = {
        "bundle_id": "test-bundle-002",
        "advisories": [{"cve": "CVE-2018-3721", "pkg": "event-stream"}]
    }
    priv, pub = generate_keypair()
    signed = sign_bundle(bundle_data, private_key_hex=priv)
    
    # Adversary alters content without updating cryptographic signature
    tampered = dict(signed)
    tampered["advisories"] = [{"cve": "CVE-2018-3721", "pkg": "malicious-injected-package"}]
    
    result = verify_bundle(tampered, public_key_hex=pub)
    assert result["is_valid"] is False
    assert result["error"] is not None
    assert "verification failed" in result["error"].lower() or "mismatch" in result["error"].lower()
