"""
Supply Chain & Package Integrity Security Rules:
Implements checks for:
- SUP-001: Packages declaring preinstall/install lifecycle scripts (flag risk, never execute)
- SUP-002: Integrity hash verification failures / fake digests
- SUP-003: Packages sourced from unverified file/local/untrusted URLs
"""
from typing import List, Dict, Any
from app.intelligence.models import (
    PackageInstance,
    IntegrationFinding,
    IntegrationFindingStatus,
    ConfidenceLevel,
    RetrievalStatus
)

class SupplyChainSecurityProfile:
    VENDOR_ID = "supply_chain"
    VENDOR_NAME = "Supply Chain & Package Provenance"

    def analyze_packages(self, packages: List[PackageInstance]) -> List[IntegrationFinding]:
        findings: List[IntegrationFinding] = []

        for pkg in packages:
            # SUP-001: Preinstall / Install Lifecycle Script Detection
            if pkg.has_install_script:
                findings.append(IntegrationFinding(
                    finding_id=f"sup-script-{pkg.name}",
                    rule_id="SUP-001",
                    vendor=self.VENDOR_ID,
                    title=f"Suspicious Lifecycle Script Detected in {pkg.name}",
                    description=f"Package '{pkg.name}' declares automated install/preinstall lifecycle scripts ('hasInstallScript: true'). BlindSpot static scanner flags this supply-chain risk and never executes untrusted package scripts.",
                    severity="high",
                    confidence=ConfidenceLevel.HIGH,
                    status=IntegrationFindingStatus.CONFIRMED,
                    target_node_id=f"pkg:{pkg.name}",
                    file_path="package-lock.json",
                    explanation="Malicious npm packages frequently leverage preinstall/postinstall hooks to steal developer environment credentials or establish persistent backdoors upon installation.",
                    remediation="Audit package lifecycle scripts before installation; consider using `npm install --ignore-scripts` in CI/CD pipelines.",
                    affected_journey="journey:checkout"
                ))

            # SUP-002: Integrity Digest Mismatch / Fake Digest
            if pkg.retrieval_status == RetrievalStatus.INTEGRITY_MISMATCH:
                findings.append(IntegrationFinding(
                    finding_id=f"sup-integrity-{pkg.name}",
                    rule_id="SUP-002",
                    vendor=self.VENDOR_ID,
                    title=f"Lockfile Cryptographic Integrity Mismatch: {pkg.name}",
                    description=f"Cryptographic hash for package '{pkg.name}@{pkg.version}' does not match the published registry tarball digest recorded in package-lock.json. Artifact was safely rejected from scanning.",
                    severity="critical",
                    confidence=ConfidenceLevel.HIGH,
                    status=IntegrationFindingStatus.CONFIRMED,
                    target_node_id=f"pkg:{pkg.name}",
                    file_path="package-lock.json",
                    code_excerpt=f"integrity: {pkg.integrity}",
                    explanation="Integrity mismatches indicate potential lockfile tampering, man-in-the-middle artifact corruption, or upstream registry supply-chain poisoning.",
                    remediation="Regenerate package-lock.json from an authenticated, trusted npm registry and verify checksums against official package releases.",
                    affected_journey="journey:checkout"
                ))

            # SUP-003: Unverified Local / File-based Dependency Origin
            if pkg.resolved_url and pkg.resolved_url.startswith(("file:", "link:")):
                findings.append(IntegrationFinding(
                    finding_id=f"sup-file-{pkg.name}",
                    rule_id="SUP-003",
                    vendor=self.VENDOR_ID,
                    title=f"Unpinned Local File Dependency: {pkg.name}",
                    description=f"Package '{pkg.name}' references an unverified local filesystem path ({pkg.resolved_url}) rather than a cryptographically signed public registry artifact.",
                    severity="medium",
                    confidence=ConfidenceLevel.HIGH,
                    status=IntegrationFindingStatus.CONFIRMED,
                    target_node_id=f"pkg:{pkg.name}",
                    file_path="package-lock.json",
                    explanation="Local file dependencies bypass registry integrity and vulnerability verification checks.",
                    remediation="Publish vetted packages to a private package registry (e.g. GitHub Packages or Verdaccio) with enforced SHA-512 integrity hashes.",
                    affected_journey="journey:checkout"
                ))

        return findings

