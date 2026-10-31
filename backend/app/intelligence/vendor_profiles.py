"""
Baseline Security Profiles for Stripe, Auth0, Firebase, and AWS:
Provides modular, extensible checks for secondary cloud and SaaS integrations.
"""
import os
import re
from typing import Dict, Any, List
from app.intelligence.models import (
    IntegrationFinding,
    IntegrationFindingStatus,
    ConfidenceLevel,
    VendorProfileResult
)
from app.intelligence.rules import redact_sensitive_text

class StripeSecurityProfile:
    VENDOR_ID = "stripe"
    VENDOR_NAME = "Stripe Payments"

    def analyze_project(self, project_path: str, packages: List[Any], observed_hosts: List[str]) -> VendorProfileResult:
        signals = []
        endpoints = []
        has_sdk = any("stripe" in p.name.lower() for p in packages)
        if has_sdk:
            signals.append("Stripe SDK declared in dependencies")
        for h in observed_hosts:
            if "stripe.com" in h.lower():
                signals.append(f"Network interaction with {h}")
                endpoints.append(h)

        findings: List[IntegrationFinding] = []
        if not signals:
            return VendorProfileResult(vendor_id=self.VENDOR_ID, vendor_name=self.VENDOR_NAME, detected=False)

        # Check for exposed Secret Key in client files
        sk_regex = re.compile(r'sk_live_[0-9a-zA-Z_]{16,}')
        for root, _, files in os.walk(project_path):
            if any(x in root for x in [".git", "node_modules", "dist", ".venv"]):
                continue
            is_client = any(x in root.lower() for x in ["client", "frontend", "public", "web"])
            for f in files:
                if f.endswith((".js", ".jsx", ".ts", ".tsx", ".html", ".env")):
                    p = os.path.join(root, f)
                    try:
                        with open(p, "r", encoding="utf-8", errors="ignore") as fl:
                            for idx, line in enumerate(fl, start=1):
                                if is_client and sk_regex.search(line):
                                    findings.append(IntegrationFinding(
                                        finding_id="strp-find-001",
                                        rule_id="STRP-001",
                                        vendor=self.VENDOR_ID,
                                        title="Stripe Secret Key Exposed in Client Code",
                                        description="Live Stripe Secret Key (sk_live_...) detected in public or frontend code assets.",
                                        severity="critical",
                                        confidence=ConfidenceLevel.HIGH,
                                        status=IntegrationFindingStatus.CONFIRMED,
                                        target_node_id="vendor:stripe",
                                        file_path=os.path.relpath(p, project_path),
                                        line_number=idx,
                                        code_excerpt=redact_sensitive_text(line.strip()),
                                        explanation="Allows full control over Stripe balance, refunds, and customer data.",
                                        remediation="Move Stripe secret key to backend environment variables; use only pk_live_... on the client.",
                                        affected_journey="journey:checkout"
                                    ))
                                    break
                    except Exception:
                        pass

        return VendorProfileResult(
            vendor_id=self.VENDOR_ID,
            vendor_name=self.VENDOR_NAME,
            detected=True,
            detection_signals=signals,
            endpoints_contacted=endpoints,
            findings=findings,
            checked_rules_count=3,
            passed_rules_count=max(0, 3 - len(findings)),
            summary={"status": "vulnerable" if findings else "healthy"}
        )

class Auth0SecurityProfile:
    VENDOR_ID = "auth0"
    VENDOR_NAME = "Auth0 Identity"

    def analyze_project(self, project_path: str, packages: List[Any], observed_hosts: List[str]) -> VendorProfileResult:
        signals = []
        endpoints = []
        has_sdk = any("auth0" in p.name.lower() for p in packages)
        if has_sdk:
            signals.append("Auth0 SDK declared in dependencies")
        for h in observed_hosts:
            if "auth0.com" in h.lower():
                signals.append(f"Network interaction with {h}")
                endpoints.append(h)

        findings: List[IntegrationFinding] = []
        if not signals:
            return VendorProfileResult(vendor_id=self.VENDOR_ID, vendor_name=self.VENDOR_NAME, detected=False)

        # Check for exposed Client Secret in frontend
        secret_regex = re.compile(r'(?i)auth0.*client_secret\s*[:=]\s*[\'"][^\'"]+[\'"]')
        for root, _, files in os.walk(project_path):
            if any(x in root for x in [".git", "node_modules", "dist", ".venv"]):
                continue
            if any(x in root.lower() for x in ["frontend", "client", "public"]):
                for f in files:
                    if f.endswith((".js", ".jsx", ".ts", ".tsx", ".html", ".env")):
                        p = os.path.join(root, f)
                        try:
                            with open(p, "r", encoding="utf-8", errors="ignore") as fl:
                                for idx, line in enumerate(fl, start=1):
                                    if secret_regex.search(line):
                                        findings.append(IntegrationFinding(
                                            finding_id="auth0-find-001",
                                            rule_id="AUTH0-001",
                                            vendor=self.VENDOR_ID,
                                            title="Auth0 Client Secret Exposed in Frontend",
                                            description="Auth0 Application Client Secret found in client-side bundles.",
                                            severity="critical",
                                            confidence=ConfidenceLevel.HIGH,
                                            status=IntegrationFindingStatus.CONFIRMED,
                                            target_node_id="vendor:auth0",
                                            file_path=os.path.relpath(p, project_path),
                                            line_number=idx,
                                            code_excerpt=redact_sensitive_text(line.strip()),
                                            explanation="Client Secret enables token forgery and OAuth impersonation.",
                                            remediation="Use PKCE (Proof Key for Code Exchange) flow for SPA clients without client secret.",
                                            affected_journey="journey:auth"
                                        ))
                                        break
                        except Exception:
                            pass

        return VendorProfileResult(
            vendor_id=self.VENDOR_ID,
            vendor_name=self.VENDOR_NAME,
            detected=True,
            detection_signals=signals,
            endpoints_contacted=endpoints,
            findings=findings,
            checked_rules_count=3,
            passed_rules_count=max(0, 3 - len(findings)),
            summary={"status": "vulnerable" if findings else "healthy"}
        )

class FirebaseSecurityProfile:
    VENDOR_ID = "firebase"
    VENDOR_NAME = "Firebase Platform"

    def analyze_project(self, project_path: str, packages: List[Any], observed_hosts: List[str]) -> VendorProfileResult:
        signals = []
        endpoints = []
        has_sdk = any("firebase" in p.name.lower() for p in packages)
        if has_sdk:
            signals.append("Firebase SDK declared in dependencies")
        for h in observed_hosts:
            if "firebase" in h.lower() or "googleapis.com" in h.lower():
                endpoints.append(h)

        findings: List[IntegrationFinding] = []
        if not signals:
            return VendorProfileResult(vendor_id=self.VENDOR_ID, vendor_name=self.VENDOR_NAME, detected=False)

        # Check for service account private key in repo
        for root, _, files in os.walk(project_path):
            if any(x in root for x in [".git", "node_modules", "dist", ".venv"]):
                continue
            for f in files:
                if f.endswith(".json") and "serviceAccountKey" in f:
                    findings.append(IntegrationFinding(
                        finding_id="fb-find-001",
                        rule_id="FB-001",
                        vendor=self.VENDOR_ID,
                        title="Firebase Service Account Key Committed",
                        description=f"Raw Firebase Service Account key file committed at {f}.",
                        severity="critical",
                        confidence=ConfidenceLevel.HIGH,
                        status=IntegrationFindingStatus.CONFIRMED,
                        target_node_id="vendor:firebase",
                        file_path=f,
                        explanation="Service accounts grant full administrative access to Firestore, Authentication, and Storage.",
                        remediation="Revoke key in Google Cloud Console and load credentials using Application Default Credentials (ADC).",
                        affected_journey="journey:auth"
                    ))
                    break

        return VendorProfileResult(
            vendor_id=self.VENDOR_ID,
            vendor_name=self.VENDOR_NAME,
            detected=True,
            detection_signals=signals,
            endpoints_contacted=endpoints,
            findings=findings,
            checked_rules_count=2,
            passed_rules_count=max(0, 2 - len(findings)),
            summary={"status": "vulnerable" if findings else "healthy"}
        )

class AWSSecurityProfile:
    VENDOR_ID = "aws"
    VENDOR_NAME = "Amazon Web Services (AWS)"

    def analyze_project(self, project_path: str, packages: List[Any], observed_hosts: List[str]) -> VendorProfileResult:
        signals = []
        endpoints = []
        has_sdk = any("aws-sdk" in p.name.lower() or "boto3" in p.name.lower() for p in packages)
        if has_sdk:
            signals.append("AWS SDK declared in dependencies")
        for h in observed_hosts:
            if "amazonaws.com" in h.lower():
                endpoints.append(h)

        findings: List[IntegrationFinding] = []
        if not signals:
            return VendorProfileResult(vendor_id=self.VENDOR_ID, vendor_name=self.VENDOR_NAME, detected=False)

        # Check for AKIA hardcoded keys in codebase
        akia_regex = re.compile(r'AKIA[0-9A-Z]{16}')
        for root, _, files in os.walk(project_path):
            if any(x in root for x in [".git", "node_modules", "dist", ".venv"]):
                continue
            for f in files:
                if f.endswith((".js", ".ts", ".py", ".env", ".json")):
                    p = os.path.join(root, f)
                    try:
                        with open(p, "r", encoding="utf-8", errors="ignore") as fl:
                            for idx, line in enumerate(fl, start=1):
                                if akia_regex.search(line) and not line.strip().startswith("#"):
                                    findings.append(IntegrationFinding(
                                        finding_id="aws-find-001",
                                        rule_id="AWS-001",
                                        vendor=self.VENDOR_ID,
                                        title="Hardcoded AWS Access Key ID",
                                        description="Long-term AWS Access Key ID found committed in source code or configuration.",
                                        severity="high",
                                        confidence=ConfidenceLevel.HIGH,
                                        status=IntegrationFindingStatus.CONFIRMED,
                                        target_node_id="vendor:aws",
                                        file_path=os.path.relpath(p, project_path),
                                        line_number=idx,
                                        code_excerpt=redact_sensitive_text(line.strip()),
                                        explanation="Hardcoded IAM access keys pose high exposure risks of unauthorized AWS account compromise.",
                                        remediation="Use IAM Roles, AWS Secrets Manager, or short-lived STS credentials.",
                                        affected_journey="journey:order_tracking"
                                    ))
                                    break
                    except Exception:
                        pass

        return VendorProfileResult(
            vendor_id=self.VENDOR_ID,
            vendor_name=self.VENDOR_NAME,
            detected=True,
            detection_signals=signals,
            endpoints_contacted=endpoints,
            findings=findings,
            checked_rules_count=2,
            passed_rules_count=max(0, 2 - len(findings)),
            summary={"status": "vulnerable" if findings else "healthy"}
        )

