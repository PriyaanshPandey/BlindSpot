from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union
from enum import Enum
from datetime import datetime

class NodeType(str, Enum):
    APPLICATION = "application"
    INTERNAL_SERVICE = "internal_service"
    EXTERNAL_API = "external_api"
    VENDOR = "vendor"
    SOFTWARE_PACKAGE = "software_package"
    RUNTIME_COMPONENT = "runtime_component"
    INFRASTRUCTURE_RESOURCE = "infrastructure_resource"
    BUSINESS_JOURNEY = "business_journey"

class NodeProvenance(str, Enum):
    DECLARED = "declared"
    OBSERVED = "observed"
    DEPLOYED = "deployed"
    INFERRED = "inferred"
    DISCLOSED = "disclosed"

class NodeStatus(str, Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    COMPROMISED = "compromised"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"

class Criticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class EdgeRelation(str, Enum):
    DEPENDS_ON = "depends_on"
    CALLS_API = "calls_api"
    TRANSITIVE_DEPENDENCY = "transitive_dependency"
    HOSTED_ON = "hosted_on"
    AUTHENTICATES_VIA = "authenticates_via"
    POWERS_JOURNEY = "powers_journey"
    ROUTES_TRAFFIC_TO = "routes_traffic_to"

class EdgeProvenance(str, Enum):
    DECLARED = "declared"
    OBSERVED = "observed"
    DEPLOYED = "deployed"
    VENDOR_PASSPORT = "vendor_passport"

class NodeModel(BaseModel):
    id: str
    label: str
    type: NodeType
    subtype: Optional[str] = None
    version: Optional[str] = None
    provenance: NodeProvenance = NodeProvenance.DECLARED
    status: NodeStatus = NodeStatus.HEALTHY
    criticality: Criticality = Criticality.MEDIUM
    metadata: Dict[str, Any] = Field(default_factory=dict)

class EdgeModel(BaseModel):
    id: str
    source: str
    target: str
    relation: EdgeRelation
    provenance: EdgeProvenance = EdgeProvenance.DECLARED
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class GraphMetadata(BaseModel):
    target_name: Optional[str] = None
    total_nodes: int = 0
    total_edges: int = 0
    discrepancy_count: int = 0
    vulnerability_count: int = 0

class GraphData(BaseModel):
    scan_id: str
    created_at: str
    nodes: List[NodeModel] = Field(default_factory=list)
    edges: List[EdgeModel] = Field(default_factory=list)
    metadata: GraphMetadata = Field(default_factory=GraphMetadata)

class EvidenceType(str, Enum):
    DECLARED = "declared"
    OBSERVED = "observed"
    DEPLOYED = "deployed"
    VENDOR_PASSPORT = "vendor_passport"

class DeclaredDetails(BaseModel):
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    manifest_type: Optional[str] = None
    raw_declaration: Optional[str] = None

class ObservedDetails(BaseModel):
    source: Optional[str] = None  # otel_trace, dns_log, proxy_access_log, playwright_crawler
    endpoint: Optional[str] = None
    destination_host: Optional[str] = None
    protocol: Optional[str] = None
    method: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    frequency_count: Optional[int] = None

class DeployedDetails(BaseModel):
    platform: Optional[str] = None
    container_image: Optional[str] = None
    image_digest: Optional[str] = None
    resource_arn: Optional[str] = None
    env_variables: List[str] = Field(default_factory=list)

class VendorPassportDetails(BaseModel):
    vendor_name: Optional[str] = None
    passport_version: Optional[str] = None
    public_key_fingerprint: Optional[str] = None
    signature_valid: Optional[bool] = None
    solana_tx_anchor: Optional[str] = None

class EvidenceModel(BaseModel):
    id: str
    evidence_type: EvidenceType
    collected_at: str
    collector: Optional[str] = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    declared_details: Optional[DeclaredDetails] = None
    observed_details: Optional[ObservedDetails] = None
    deployed_details: Optional[DeployedDetails] = None
    vendor_passport_details: Optional[VendorPassportDetails] = None

class FindingType(str, Enum):
    DISCREPANCY_UNDECLARED_ENDPOINT = "discrepancy_undeclared_endpoint"
    DISCREPANCY_PHANTOM_DEPENDENCY = "discrepancy_phantom_dependency"
    DISCREPANCY_VERSION_DRIFT = "discrepancy_version_drift"
    VULNERABILITY_KNOWN_CVE = "vulnerability_known_cve"
    VULNERABILITY_COMPROMISED_PACKAGE = "vulnerability_compromised_package"
    VENDOR_UNVERIFIED_PASSPORT = "vendor_unverified_passport"
    SINGLE_POINT_OF_FAILURE = "single_point_of_failure"

class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class SecurityDetails(BaseModel):
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    advisory_source: Optional[str] = None
    fixed_version: Optional[str] = None

class Remediation(BaseModel):
    summary: Optional[str] = None
    recommended_action: Optional[str] = None
    code_patch: Optional[str] = None
    doc_update_sample: Optional[str] = None

class FindingModel(BaseModel):
    id: str
    scan_id: str
    type: FindingType
    title: str
    description: str
    severity: FindingSeverity
    target_node_id: str
    affected_journey_ids: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    security_details: Optional[SecurityDetails] = None
    remediation: Optional[Remediation] = None

class FailureType(str, Enum):
    COMPLETE_OUTAGE = "complete_outage"
    HIGH_LATENCY_TIMEOUT = "high_latency_timeout"
    PACKET_LOSS = "packet_loss"
    SECURITY_QUARANTINE = "security_quarantine"

class SimulationParameters(BaseModel):
    failure_type: FailureType = FailureType.COMPLETE_OUTAGE
    failure_duration_hours: float = Field(default=4.0, ge=0.1)
    hourly_transactions_override: Optional[float] = None
    average_transaction_value_override: Optional[float] = None

class SimulationRequest(BaseModel):
    target_node_id: str
    failure_type: str = "complete_outage"
    failure_duration_hours: float = 4.0
    hourly_transactions_override: Optional[float] = None
    average_transaction_value_override: Optional[float] = None

class ImpactedJourney(BaseModel):
    journey_id: str
    name: str
    disruption_fraction: float = Field(default=1.0, ge=0.0, le=1.0)
    hourly_transactions: float
    average_transaction_value: float
    financial_exposure: float

class MitigationStrategy(BaseModel):
    strategy_type: str  # circuit_breaker, fallback_provider, retry_backoff, offline_queue, redundant_dns
    title: str
    description: str
    estimated_risk_reduction_pct: float
    baseline_risk_score: Optional[float] = None
    post_mitigation_risk_score: Optional[float] = None

class SimulationImpactResults(BaseModel):
    blast_radius_node_count: int
    impacted_node_ids: List[str] = Field(default_factory=list)
    impacted_journeys: List[ImpactedJourney] = Field(default_factory=list)
    total_estimated_gross_exposure: float
    exposure_currency: str = "USD"
    mitigation_strategies: List[MitigationStrategy] = Field(default_factory=list)
    architecture_impact_score: Optional[float] = None
    system_impact_percentage: Optional[float] = None

class ScenarioModel(BaseModel):
    scenario_id: str
    scan_id: str
    name: str
    target_node_id: str
    simulation_parameters: SimulationParameters
    impact_results: SimulationImpactResults

class ScanStatus(str, Enum):
    QUEUED = "queued"
    PARSING_MANIFESTS = "parsing_manifests"
    INGESTING_TRACES = "ingesting_traces"
    RECONCILING = "reconciling"
    ANALYZING_RISKS = "analyzing_risks"
    COMPLETED = "completed"
    FAILED = "failed"

class ScanConfig(BaseModel):
    repo_path: str = "./demo/nexus-commerce"
    trace_file_path: Optional[str] = "./fixtures/runtime/traces.sample.json"
    enable_playwright_crawler: bool = False
    enable_vendor_passports: bool = True
    knowledge_bundle_mode: str = "hybrid"

class ScanSummary(BaseModel):
    declared_dependencies: int = 0
    observed_dependencies: int = 0
    discrepancies_found: int = 0
    vulnerabilities_found: int = 0
    critical_paths: int = 0
    execution_time_ms: float = 0.0

class ScanRecord(BaseModel):
    scan_id: str
    project_name: str
    status: ScanStatus = ScanStatus.COMPLETED
    started_at: str
    completed_at: Optional[str] = None
    config: Optional[ScanConfig] = None
    summary: Optional[ScanSummary] = None
    error_message: Optional[str] = None

class ScanRequest(BaseModel):
    repo_path: str = "./demo/nexus-commerce"
    trace_file_path: Optional[str] = "./fixtures/runtime/traces.sample.json"
    enable_vendor_passports: bool = True
