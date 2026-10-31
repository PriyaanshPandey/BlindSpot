"""
Workstream D: Cryptographic Signing Integration
Implements authentic Ed25519 bundle signing and signature verification using the Python cryptography library.
"""
import json
import hashlib
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Fields excluded from signature and hash computation to prevent circular dependency
EXCLUDED_FROM_SIGNING = {
    "ed25519_signature",
    "bundle_sha256_hash",
    "solana_tx_anchor",
    "signing_key_id"
}

# Default public key for sample verified bundles (32 raw bytes hex)
_DEFAULT_TEST_PRIVATE_KEY = ed25519.Ed25519PrivateKey.generate()
_DEFAULT_TEST_PUBLIC_KEY = _DEFAULT_TEST_PRIVATE_KEY.public_key()

DEFAULT_PUBLIC_KEY_HEX = _DEFAULT_TEST_PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
).hex()

DEFAULT_PRIVATE_KEY_HEX = _DEFAULT_TEST_PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
).hex()

def generate_keypair() -> Tuple[str, str]:
    """Generates a new Ed25519 private/public keypair in raw hex format."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    priv_hex = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()
    
    pub_hex = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()
    
    return priv_hex, pub_hex

def canonicalize_json(data: Dict[str, Any]) -> bytes:
    """Produces deterministic canonical JSON bytes with sorted keys and no whitespace."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

def compute_bundle_hash(bundle_data: Dict[str, Any]) -> str:
    """Computes SHA-256 hash of the canonicalized bundle data excluding signature fields."""
    content_to_hash = {k: v for k, v in bundle_data.items() if k not in EXCLUDED_FROM_SIGNING}
    canonical_bytes = canonicalize_json(content_to_hash)
    return hashlib.sha256(canonical_bytes).hexdigest()

def sign_bundle(bundle_data: Dict[str, Any], private_key_hex: Optional[str] = None) -> Dict[str, Any]:
    """Signs a knowledge bundle using an Ed25519 private key."""
    if private_key_hex:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    else:
        private_key = _DEFAULT_TEST_PRIVATE_KEY
        
    bundle_hash = compute_bundle_hash(bundle_data)
    canonical_bytes = canonicalize_json({k: v for k, v in bundle_data.items() if k not in EXCLUDED_FROM_SIGNING})
    
    signature = private_key.sign(canonical_bytes)
    pub_hex = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()
    
    result = dict(bundle_data)
    result["bundle_sha256_hash"] = bundle_hash
    result["ed25519_signature"] = signature.hex()
    result["signing_key_id"] = pub_hex
    
    return result

def verify_bundle(bundle_data: Dict[str, Any], public_key_hex: Optional[str] = None) -> Dict[str, Any]:
    """
    Verifies the Ed25519 signature of a knowledge bundle.
    Rejects tampered or modified bundles.
    """
    signature_hex = bundle_data.get("ed25519_signature")
    if not signature_hex:
        return {
            "is_valid": False,
            "bundle_sha256": compute_bundle_hash(bundle_data),
            "error": "Missing 'ed25519_signature' in bundle"
        }
        
    try:
        sig_bytes = bytes.fromhex(signature_hex)
        key_hex = public_key_hex or bundle_data.get("signing_key_id") or DEFAULT_PUBLIC_KEY_HEX
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
        
        # Verify against canonical payload without signature & metadata fields
        content_to_verify = {k: v for k, v in bundle_data.items() if k not in EXCLUDED_FROM_SIGNING}
        canonical_bytes = canonicalize_json(content_to_verify)
        
        public_key.verify(sig_bytes, canonical_bytes)
        
        computed_hash = compute_bundle_hash(bundle_data)
        recorded_hash = bundle_data.get("bundle_sha256_hash", computed_hash)
        
        if computed_hash != recorded_hash:
            return {
                "is_valid": False,
                "bundle_sha256": computed_hash,
                "error": f"Bundle hash mismatch: computed {computed_hash} != recorded {recorded_hash}"
            }
            
        return {
            "is_valid": True,
            "bundle_sha256": computed_hash,
            "signing_key_id": key_hex,
            "error": None
        }
    except Exception as exc:
        return {
            "is_valid": False,
            "bundle_sha256": compute_bundle_hash(bundle_data),
            "error": f"Ed25519 verification failed: {str(exc)}"
        }

def verify_bundle_signature(bundle_content: bytes, signature_hex: str, public_key_hex: str) -> bool:
    """Convenience helper for raw byte verification."""
    try:
        sig_bytes = bytes.fromhex(signature_hex)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub_key.verify(sig_bytes, bundle_content)
        return True
    except Exception:
        return False
