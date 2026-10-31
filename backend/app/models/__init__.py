from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
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

class ProvenanceType(str, Enum):
    DECLARED = "declared"
    OBSERVED = "observed"
    DEPLOYED = "deployed"
    INFERRED = "inferred"
    DISCLOSED = "disclosed"

class NodeModel(BaseModel):
    id: str
    label: str
    type: NodeType
    subtype: Optional[str] = None
    version: Optional[str] = None
    provenance: ProvenanceType = ProvenanceType.DECLARED
    status: str = "healthy"
    criticality: str = "medium"
    metadata: Dict[str, Any] = Field(default_factory=dict)

class EdgeModel(BaseModel):
    id: str
    source: str
    target: str
    relation: str
    provenance: str = "declared"
    confidence_score: float = 1.0
    evidence_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class GraphData(BaseModel):
    scan_id: str
    created_at: str
    nodes: List[NodeModel] = Field(default_factory=list)
    edges: List[EdgeModel] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class FindingModel(BaseModel):
    id: str
    scan_id: str
    type: str
    title: str
    description: str
    severity: str
    target_node_id: str
    affected_journey_ids: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    remediation: Optional[Dict[str, Any]] = None

class SimulationRequest(BaseModel):
    target_node_id: str
    failure_type: str = "complete_outage"
    failure_duration_hours: float = 4.0
    hourly_transactions_override: Optional[float] = None
    average_transaction_value_override: Optional[float] = None

class ScanRequest(BaseModel):
    repo_path: str = "./demo/nexus-commerce"
    trace_file_path: Optional[str] = "./fixtures/runtime/traces.sample.json"
    enable_vendor_passports: bool = True

