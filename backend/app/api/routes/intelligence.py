"""
Third-Party Dependency Intelligence & Integration Security API Routes:
Endpoints for:
- Third-party dependency inventory
- Exact package metadata and retrieved source inspection
- Vendor integration profiles (Razorpay, Stripe, Auth0, Firebase, AWS)
- Security findings and business journey impact
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional, Dict, Any, List
import os

from app.db.repositories import ScanRepository
from app.intelligence.service import ThirdPartyIntelligenceService

router = APIRouter()
intel_service = ThirdPartyIntelligenceService()

# In-memory intelligence cache per scan_id
_SCAN_INTELLIGENCE_CACHE: Dict[str, Dict[str, Any]] = {}

@router.get("/{scan_id}/third-party/summary")
async def get_third_party_summary(scan_id: str):
    scan = await ScanRepository.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    repo_path = scan.get("config", {}).get("repo_path") if scan.get("config") else None
    if not repo_path or not os.path.exists(repo_path):
        repo_path = "./demo/nexus-commerce"

    if scan_id not in _SCAN_INTELLIGENCE_CACHE:
        # Run intelligence analysis
        res = intel_service.analyze_third_party_security(
            project_path=repo_path,
            observed_hosts=scan.get("summary", {}).get("observed_hosts", [])
        )
        _SCAN_INTELLIGENCE_CACHE[scan_id] = res

    data = _SCAN_INTELLIGENCE_CACHE[scan_id]
    return {
        "scan_id": scan_id,
        "total_packages": data["total_packages"],
        "retrieved_packages_count": data["retrieved_packages_count"],
        "total_vulnerabilities": data["total_vulnerabilities"],
        "total_integration_findings": data["total_integration_findings"],
        "vendor_integrations": [
            {
                "vendor_id": v["vendor_id"],
                "vendor_name": v["vendor_name"],
                "detected": v["detected"],
                "findings_count": len(v["findings"]),
                "checked_rules_count": v["checked_rules_count"],
                "passed_rules_count": v["passed_rules_count"]
            }
            for v in data["vendor_integrations"]
        ]
    }

@router.get("/{scan_id}/third-party/packages")
async def get_packages(scan_id: str, ecosystem: Optional[str] = None):
    if scan_id not in _SCAN_INTELLIGENCE_CACHE:
        await get_third_party_summary(scan_id)
    
    packages = _SCAN_INTELLIGENCE_CACHE.get(scan_id, {}).get("packages", [])
    if ecosystem:
        packages = [p for p in packages if p.get("ecosystem") == ecosystem]
    return packages

@router.get("/{scan_id}/third-party/packages/{package_name:path}/source")
async def get_package_source_inspector(scan_id: str, package_name: str):
    if scan_id not in _SCAN_INTELLIGENCE_CACHE:
        await get_third_party_summary(scan_id)

    packages = _SCAN_INTELLIGENCE_CACHE.get(scan_id, {}).get("packages", [])
    target_pkg = next((p for p in packages if p.get("name") == package_name or p.get("instance_id") == package_name), None)

    if not target_pkg:
        raise HTTPException(status_code=404, detail=f"Package {package_name} not found in inventory")

    src_path = target_pkg.get("extracted_source_path")
    files_list = []
    sample_content = None

    if src_path and os.path.exists(src_path):
        for root, _, files in os.walk(src_path):
            for f in files[:30]:  # Limit file list
                rel = os.path.relpath(os.path.join(root, f), src_path)
                files_list.append(rel)
                # Load first readable JS/TS file as sample
                if not sample_content and f.endswith((".js", ".ts", ".json")):
                    try:
                        with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as fl:
                            sample_content = {
                                "file": rel,
                                "content": fl.read(2000)
                            }
                    except Exception:
                        pass

    return {
        "package": target_pkg,
        "source_retrieved": target_pkg.get("has_source_retrieved", False),
        "retrieval_status": target_pkg.get("retrieval_status"),
        "integrity_hash": target_pkg.get("integrity"),
        "source_files": files_list,
        "sample_code": sample_content
    }

@router.get("/{scan_id}/third-party/integrations")
async def get_integrations(scan_id: str):
    if scan_id not in _SCAN_INTELLIGENCE_CACHE:
        await get_third_party_summary(scan_id)

    return _SCAN_INTELLIGENCE_CACHE.get(scan_id, {}).get("vendor_integrations", [])

@router.get("/{scan_id}/third-party/security-report")
async def get_security_report(scan_id: str, vendor: Optional[str] = None):
    if scan_id not in _SCAN_INTELLIGENCE_CACHE:
        await get_third_party_summary(scan_id)

    findings = _SCAN_INTELLIGENCE_CACHE.get(scan_id, {}).get("integration_findings", [])
    if vendor:
        findings = [f for f in findings if f.get("vendor") == vendor]
    return findings

