"""
Third-Party Dependency Intelligence Module:
Models, discovery, retrieval, vulnerability inspection, rule engine, and vendor profiles.
"""
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from enum import Enum

class EcosystemType(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    COMPOSER = "composer"
    MAVEN = "maven"
    NUGET = "nuget"

class DependencyScope(str, Enum):
    PROD = "production"
    DEV = "development"
    OPTIONAL = "optional"
    PEER = "peer"
    TRANSITIVE = "transitive"

class RetrievalStatus(str, Enum):
    LOCAL_NODE_MODULES = "local_node_modules"
    REMOTE_VERIFIED = "remote_verified"
    INTEGRITY_MISMATCH = "integrity_mismatch"
    DOWNLOAD_FAILED = "download_failed"
    UNSUPPORTED_SOURCE = "unsupported_source"
    REJECTED_SSRF = "rejected_ssrf"
    EXTRACT_ERROR = "extract_error"
    UNPROCESSED = "unprocessed"

class PackageInstance(BaseModel):
    instance_id: str  # unique identity: pkg:<name>@<version>#<install_path>
    name: str
    version: str
    ecosystem: EcosystemType = EcosystemType.NPM
    declared_range: Optional[str] = None
    is_direct: bool = True
    scope: DependencyScope = DependencyScope.PROD
    install_path: str = ""
    parent_dependency: Optional[str] = None
    registry_url: Optional[str] = None
    resolved_url: Optional[str] = None
    integrity: Optional[str] = None
    repository_url: Optional[str] = None
    publisher: Optional[str] = None
    has_install_script: bool = False
    has_source_retrieved: bool = False
    retrieval_status: RetrievalStatus = RetrievalStatus.UNPROCESSED
    extracted_source_path: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class IntegrationFindingStatus(str, Enum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    NEEDS_REVIEW = "needs_review"
    NOT_DETECTED = "not_detected"
    NOT_ASSESSED = "not_assessed"

class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class IntegrationFinding(BaseModel):
    finding_id: str
    rule_id: str
    vendor: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    status: IntegrationFindingStatus = IntegrationFindingStatus.CONFIRMED
    target_node_id: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_excerpt: Optional[str] = None
    evidence_reference: Optional[str] = None
    advisory_reference: Optional[str] = None
    explanation: str
    remediation: str
    affected_journey: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class VendorProfileResult(BaseModel):
    vendor_id: str
    vendor_name: str
    detected: bool = False
    sdk_version: Optional[str] = None
    detection_signals: List[str] = Field(default_factory=list)
    endpoints_contacted: List[str] = Field(default_factory=list)
    findings: List[IntegrationFinding] = Field(default_factory=list)
    checked_rules_count: int = 0
    passed_rules_count: int = 0
    summary: Dict[str, Any] = Field(default_factory=dict)
