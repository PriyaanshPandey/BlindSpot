from app.integrations.signing import verify_bundle_signature

def test_verify_bundle_signature():
    content = b"sample bundle data"
    assert verify_bundle_signature(content, "sig_dummy", "pubkey_dummy") is True

