"""
Central Third-Party Intelligence Coordinator:
Orchestrates dependency discovery, package code retrieval, vulnerability analysis,
vendor security profile checks (Razorpay, Stripe, Auth0, Firebase, AWS), supply chain,
and deep security inspection.
"""
import os
import logging
from typing import Dict, Any, List, Optional

from app.intelligence.models import (
    PackageInstance,
    VendorProfileResult,
    IntegrationFinding
)
from app.intelligence.discovery import ExtensibleDependencyDiscovery
from app.intelligence.retrieval import PackageArtifactRetriever
from app.intelligence.vulnerability import get_vulnerabilities_for_packages
from app.intelligence.razorpay import RazorpaySecurityProfile
from app.intelligence.supply_chain import SupplyChainSecurityProfile
from app.intelligence.deep_security import DeepSecurityAnalyzer
from app.intelligence.vendor_profiles import (
    StripeSecurityProfile,
    Auth0SecurityProfile,
    FirebaseSecurityProfile,
    AWSSecurityProfile
)

logger = logging.getLogger("blindspot.intelligence.service")

class ThirdPartyIntelligenceService:
    def __init__(self, cache_dir: Optional[str] = None):
        self.discovery = ExtensibleDependencyDiscovery()
        self.retriever = PackageArtifactRetriever(cache_dir=cache_dir)
        self.supply_chain = SupplyChainSecurityProfile()
        self.deep_analyzer = DeepSecurityAnalyzer()
        self.vendor_profiles = [
            RazorpaySecurityProfile(),
            StripeSecurityProfile(),
            Auth0SecurityProfile(),
            FirebaseSecurityProfile(),
            AWSSecurityProfile()
        ]

    def analyze_third_party_security(
        self,
        project_path: str,
        observed_hosts: Optional[List[str]] = None,
        allow_network: bool = True
    ) -> Dict[str, Any]:
        """
        Runs comprehensive third-party intelligence analysis on project:
        1. Discovers all package instances with lockfile precision.
        2. Retrieves & verifies exact package code artifacts.
        3. Matches vulnerabilities with Google OSV batch API.
        4. Runs supply-chain integrity analysis.
        5. Runs deep security and integration rules.
        """
        abs_path = os.path.abspath(project_path)
        observed = observed_hosts or []

        # 1. Discover Package Instances
        packages: List[PackageInstance] = self.discovery.discover_all(abs_path)

        # 2. Retrieve & Verify Artifacts
        for pkg in packages[:15]:
            self.retriever.retrieve_package(pkg, project_root=abs_path, allow_network=allow_network)

        # 3. Vulnerability Intelligence
        vuln_map = get_vulnerabilities_for_packages(packages, allow_network=allow_network)

        # 4. Supply Chain Checks (SUP-001, SUP-002, etc.)
        supply_chain_findings = self.supply_chain.analyze_packages(packages)

        # 5. Deep Security & Integration Analysis (SEC-001, RZP-001..RZP-005, AUTH-001, etc.)
        deep_findings = self.deep_analyzer.scan_codebase(abs_path, observed_hosts=observed)

        # 6. Vendor Integration Profiles
        vendor_results: List[VendorProfileResult] = []
        all_integration_findings: List[IntegrationFinding] = []

        all_integration_findings.extend(supply_chain_findings)
        all_integration_findings.extend(deep_findings)

        for profile in self.vendor_profiles:
            try:
                res = profile.analyze_project(
                    project_path=abs_path,
                    packages=packages,
                    observed_hosts=observed
                )
                if res.detected:
                    vendor_results.append(res)
                    # Add unique findings
                    for f in res.findings:
                        if not any(existing.rule_id == f.rule_id for existing in all_integration_findings):
                            all_integration_findings.append(f)
            except Exception as e:
                logger.error(f"Error evaluating vendor profile {profile.VENDOR_ID}: {e}")

        # Summary calculations
        total_vulns = sum(len(v) for v in vuln_map.values())
        retrieved_count = sum(1 for p in packages if p.has_source_retrieved)

        return {
            "project_path": abs_path,
            "packages": [p.model_dump() for p in packages],
            "total_packages": len(packages),
            "retrieved_packages_count": retrieved_count,
            "vulnerabilities": vuln_map,
            "total_vulnerabilities": total_vulns,
            "vendor_integrations": [v.model_dump() for v in vendor_results],
            "integration_findings": [f.model_dump() for f in all_integration_findings],
            "total_integration_findings": len(all_integration_findings)
        }
