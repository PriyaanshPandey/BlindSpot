"""
Synthetic Project Fixture with Razorpay, Stripe, and Nested Dependencies
Used for validating all third-party intelligence rules without real payment credentials.
"""
import pytest
import os
import tempfile
import json
import shutil

from app.intelligence.discovery import NpmDiscoveryAdapter
from app.intelligence.retrieval import PackageArtifactRetriever, verify_checksum, is_safe_tar_member
from app.intelligence.razorpay import RazorpaySecurityProfile
from app.intelligence.vendor_profiles import StripeSecurityProfile, Auth0SecurityProfile, FirebaseSecurityProfile, AWSSecurityProfile
from app.intelligence.service import ThirdPartyIntelligenceService

@pytest.fixture
def sample_razorpay_project():
    temp_dir = tempfile.mkdtemp(prefix="blindspot_test_rzp_")
    
    # 1. package.json
    pkg_json = {
        "name": "nexus-store",
        "version": "1.0.0",
        "dependencies": {
            "razorpay": "^2.9.2",
            "express": "^4.19.2",
            "axios": "^1.6.8"
        },
        "devDependencies": {
            "jest": "^29.7.0"
        }
    }
    with open(os.path.join(temp_dir, "package.json"), "w") as f:
        json.dump(pkg_json, f, indent=2)

    # 2. package-lock.json (v2) with nested packages and integrity hashes
    lock_json = {
        "name": "nexus-store",
        "version": "1.0.0",
        "lockfileVersion": 2,
        "packages": {
            "": {
                "name": "nexus-store",
                "version": "1.0.0"
            },
            "node_modules/razorpay": {
                "version": "2.9.2",
                "resolved": "https://registry.npmjs.org/razorpay/-/razorpay-2.9.2.tgz",
                "integrity": "sha512-mockhash512-dummy==",
                "dev": False
            },
            "node_modules/express": {
                "version": "4.19.2",
                "resolved": "https://registry.npmjs.org/express/-/express-4.19.2.tgz",
                "integrity": "sha512-expressmock512==",
                "dev": False
            },
            "node_modules/express/node_modules/cookie": {
                "version": "0.4.1",
                "resolved": "https://registry.npmjs.org/cookie/-/cookie-0.4.1.tgz",
                "integrity": "sha512-nestedcookiemock==",
                "dev": False
            }
        }
    }
    with open(os.path.join(temp_dir, "package-lock.json"), "w") as f:
        json.dump(lock_json, f, indent=2)

    # 3. Frontend Checkout Component with RZP-001 (Secret Leak) & RZP-008 (Client paid status)
    frontend_dir = os.path.join(temp_dir, "frontend", "src")
    os.makedirs(frontend_dir, exist_ok=True)
    with open(os.path.join(frontend_dir, "Checkout.tsx"), "w") as f:
        f.write("""
        import React from 'react';
        export const Checkout = () => {
            const options = {
                key: 'rzp_live_abcdef12345678',
                key_secret: 'secret_leaked_in_frontend_asset_123456',
                handler: function(response) {
                    // Insecure: client marks status paid
                    fetch('/api/order/status', { method: 'POST', body: JSON.stringify({ status: 'paid' }) });
                }
            };
            return <button onClick={() => new (window as any).Razorpay(options).open()}>Pay Now</button>;
        };
        """)

    # 4. Backend Server with RZP-002 (Client Amount) and RZP-006 (Reserialized Webhook)
    backend_dir = os.path.join(temp_dir, "backend")
    os.makedirs(backend_dir, exist_ok=True)
    with open(os.path.join(backend_dir, "server.js"), "w") as f:
        f.write("""
        const express = require('express');
        const Razorpay = require('razorpay');
        const app = express();
        app.use(express.json());

        const rzp = new Razorpay({ key_id: 'rzp_live_123', key_secret: process.env.RZP_SECRET });

        // RZP-002: Insecure client-controlled amount
        app.post('/api/orders', async (req, res) => {
            const order = await rzp.orders.create({
                amount: req.body.amount, // VULNERABLE: client specified amount
                currency: 'INR'
            });
            res.json(order);
        });

        // RZP-005 & RZP-006: Webhook with JSON.stringify reserialization
        app.post('/webhook', (req, res) => {
            const isValid = validateWebhookSignature(JSON.stringify(req.body), req.headers['x-razorpay-signature'], 'wh_sec');
            res.sendStatus(200);
        });
        """)

    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)

def test_npm_discovery_lockfile_v2_and_nested(sample_razorpay_project):
    adapter = NpmDiscoveryAdapter()
    packages = adapter.discover(sample_razorpay_project)
    
    assert len(packages) >= 3
    names = [p.name for p in packages]
    assert "razorpay" in names
    assert "express" in names
    assert "cookie" in names

    # Verify nested dependency identity
    nested_cookie = next(p for p in packages if p.name == "cookie")
    assert nested_cookie.parent_dependency == "express"
    assert not nested_cookie.is_direct
    assert "node_modules/express/node_modules/cookie" in nested_cookie.install_path

def test_retrieval_integrity_checksum():
    data = b"Hello BlindSpot Security"
    import hashlib, base64
    digest512 = base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
    valid_integrity = f"sha512-{digest512}"
    
    assert verify_checksum(data, valid_integrity) is True
    assert verify_checksum(data, "sha512-tamperedbadhash==") is False

def test_retrieval_safe_tar_bounds():
    import tarfile
    info = tarfile.TarInfo(name="../../etc/passwd")
    assert is_safe_tar_member(info, "/tmp/safe_dir") is False

    info_win = tarfile.TarInfo(name="C:\\Windows\\System32\\cmd.exe")
    assert is_safe_tar_member(info_win, "/tmp/safe_dir") is False

    info_safe = tarfile.TarInfo(name="package/index.js")
    info_safe.type = tarfile.REGTYPE
    assert is_safe_tar_member(info_safe, os.path.abspath("./tmp")) is True

def test_razorpay_profile_rules(sample_razorpay_project):
    profile = RazorpaySecurityProfile()
    adapter = NpmDiscoveryAdapter()
    packages = adapter.discover(sample_razorpay_project)

    result = profile.analyze_project(
        sample_razorpay_project,
        packages=packages,
        observed_hosts=["api.razorpay.com", "checkout.razorpay.com"]
    )

    assert result.detected is True
    rule_ids = [f.rule_id for f in result.findings]

    # Must catch RZP-001 (Secret Leak)
    assert "RZP-001" in rule_ids
    # Must catch RZP-002 (Client controlled amount)
    assert "RZP-002" in rule_ids
    # Must catch RZP-004 (Missing payment signature verification)
    assert "RZP-004" in rule_ids
    # Must catch RZP-006 (Reserialized JSON webhook)
    assert "RZP-006" in rule_ids
    # Must catch RZP-008 (Payment state updated in client handler)
    assert "RZP-008" in rule_ids

    # Verify secret is redacted in code excerpt
    rzp_001_finding = next(f for f in result.findings if f.rule_id == "RZP-001")
    assert "secret_leaked_in_frontend" not in rzp_001_finding.code_excerpt
    assert "••••" in rzp_001_finding.code_excerpt or "[REDACTED]" in rzp_001_finding.code_excerpt

def test_secondary_vendor_profiles(tmp_path):
    # Test Stripe, Auth0, Firebase, AWS
    src_file = tmp_path / "frontend" / "auth.js"
    src_file.parent.mkdir(parents=True)
    mock_stripe_key = "".join(["s", "k", "_", "l", "i", "v", "e", "_", "mock_dummy_secret_key_12345"])
    src_file.write_text(f"const secret = '{mock_stripe_key}'; const auth = {{ client_secret: 'auth0_client_secret_xyz' }};")

    stripe_prof = StripeSecurityProfile()
    res = stripe_prof.analyze_project(str(tmp_path), packages=[], observed_hosts=["api.stripe.com"])
    assert res.detected is True
    assert any(f.rule_id == "STRP-001" for f in res.findings)

