#!/usr/bin/env python3
"""
Workstream D: Knowledge Plane Bundle Publisher
Packages public vulnerability advisories and vendor passports,
computes canonical SHA-256 hash, signs with Ed25519, and saves release bundle.
"""
import os
import sys
import json
import hashlib
from datetime import datetime
from pathlib import Path

# Add backend directory to sys.path so we can import app.integrations
backend_dir = Path(__file__).resolve().parent.parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.integrations.signing import sign_bundle, canonicalize_json, generate_keypair

def publish_new_bundle(output_path: str = None) -> dict:
    knowledge_dir = Path(__file__).resolve().parent.parent
    passports_file = knowledge_dir / "sample-data" / "vendor-passports.json"
    
    vendor_passports = []
    if passports_file.exists():
        with open(passports_file, "r", encoding="utf-8") as f:
            vendor_passports = json.load(f)

    # Core release bundle content
    bundle_data = {
        "bundle_id": f"bundle-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
        "version": "1.1.0",
        "published_at": datetime.utcnow().isoformat() + "Z",
        "publisher": "HDX Public Knowledge Authority (DigitalOcean)",
        "vendor_passports": vendor_passports,
        "cve_advisories": [
            {
                "cve_id": "CVE-2018-3721",
                "package": "event-stream",
                "affected_versions": ["3.3.6"],
                "severity": "critical",
                "fixed_version": "3.3.7"
            },
            {
                "cve_id": "CVE-2022-23529",
                "package": "jsonwebtoken",
                "affected_versions": ["8.5.1"],
                "severity": "high",
                "fixed_version": "9.0.0"
            }
        ]
    }

    # Sign bundle with Ed25519
    signed_bundle = sign_bundle(bundle_data)
    
    # Save bundle
    dest = output_path or (knowledge_dir / "bundles" / "bundle-release.json")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(signed_bundle, f, indent=2)

    print(f"[+] Knowledge Bundle published successfully to: {dest}")
    print(f"    Bundle ID:    {signed_bundle['bundle_id']}")
    print(f"    SHA-256 Hash: {signed_bundle['bundle_sha256_hash']}")
    print(f"    Ed25519 Sig:  {signed_bundle['ed25519_signature'][:32]}...")
    return signed_bundle

if __name__ == "__main__":
    publish_new_bundle()

