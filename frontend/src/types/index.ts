export type NodeType =
  | 'application'
  | 'internal_service'
  | 'external_api'
  | 'vendor'
  | 'vendor_upstream'
  | 'software_package'
  | 'runtime_component'
  | 'infrastructure_resource'
  | 'business_journey';

export type ProvenanceType = 'declared' | 'observed' | 'deployed' | 'inferred' | 'disclosed';

export interface GraphNode {
  id: string;
  label: string;
  type: NodeType;
  subtype?: string;
  version?: string;
  provenance: ProvenanceType;
  status: 'healthy' | 'warning' | 'compromised' | 'unreachable' | 'unknown';
  criticality: 'critical' | 'high' | 'medium' | 'low';
  metadata?: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  provenance: string;
  confidence_score: number;
  evidence_ids?: string[];
  metadata?: Record<string, unknown>;
}

export interface GraphData {
  scan_id: string;
  created_at: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  metadata: {
    total_nodes: number;
    total_edges: number;
    discrepancy_count: number;
    vulnerability_count: number;
  };
}

export interface Finding {
  id: string;
  scan_id: string;
  type: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  target_node_id: string;
  affected_journey_ids: string[];
  evidence_references: string[];
  security_details?: {
    cve_id?: string;
    cvss_score?: number;
    advisory_source?: string;
    fixed_version?: string;
  };
  remediation?: {
    summary: string;
    recommended_action: string;
    code_patch?: string;
  };
}

export interface ImpactedJourney {
  journey_id: string;
  name: string;
  disruption_fraction: number;
  hourly_transactions: number;
  average_transaction_value: number;
  financial_exposure: number;
}

export interface SimulationResult {
  scenario_id: string;
  scan_id: string;
  name: string;
  target_node_id: string;
  simulation_parameters: {
    failure_duration_hours: number;
    failure_type: string;
  };
  impact_results: {
    blast_radius_node_count: number;
    impacted_node_ids: string[];
    impact_percentage?: number;
    system_impact_percentage?: number;
    severity_rating?: string;
    total_system_nodes?: number;
    impacted_services_count?: number;
    impacted_packages_count?: number;
    impacted_infra_count?: number;
    impacted_vendor_count?: number;
    impact_summary?: string;
    total_estimated_gross_exposure: number;
    exposure_currency: string;
    impacted_journeys: ImpactedJourney[];
    architecture_impact_score?: number;
    mitigation_strategies: Array<{
      strategy_type: string;
      title: string;
      description: string;
      estimated_risk_reduction_pct: number;
      baseline_risk_score?: number;
      post_mitigation_risk_score?: number;
    }>;
  };
}

export interface ScanSummary {
  scan_id: string;
  project_name: string;
  status: string;
  started_at: string;
  completed_at?: string;
  summary: {
    declared_dependencies: number;
    observed_dependencies: number;
    discrepancies_found: number;
    vulnerabilities_found: number;
    critical_paths: number;
    execution_time_ms: number;
  };
}

export interface KnowledgeManifest {
  manifest_version: string;
  active_bundle_id: string;
  bundle_sha256: string;
  signing_key_id: string;
  published_at: string;
  distribution_channel: string;
  operating_mode: string;
  privacy_isolation: string;
}

export interface BundleVerificationSummary {
  bundle_id: string;
  version: string;
  bundle_sha256: string;
  overall_status: 'verified' | 'tampered_or_invalid';
  is_genuine: boolean;
  ed25519_verification: {
    is_valid: boolean;
    bundle_sha256: string;
    signing_key_id?: string;
    error?: string | null;
  };
  solana_verification: {
    verified: boolean;
    cluster: string;
    tx_signature: string;
    slot: number;
    is_on_chain: boolean;
    explorer_url: string;
  };
}

export interface VerifiedScannerFinding {
  package_name: string;
  installed_version: string;
  cve_id: string;
  severity: string;
  affected_version_range?: string;
  fixed_version?: string | null;
  cvss_score?: number;
  advisory_source: string;
  advisory_description: string;
  is_verified_vulnerable: boolean;
  verification_status: string;
}

export interface ValidationReport {
  passed: boolean;
  flags_count: number;
  flags: string[];
  checked_against_authoritative: boolean;
  source_of_truth: string;
}

export interface AIExplanation {
  finding_id: string;
  target_package: string;
  version?: string;
  audience: 'builder' | 'enterprise';
  summary: string;
  why_it_matters: string;
  technical_impact: string;
  safe_remediation_steps: string[];
  confidence_score: number;
  is_ai_generated: boolean;
  is_fallback: boolean;
  ai_status?: string;
  error_message?: string;
  model_used?: string;
  notice: string;
  verified_scanner_finding?: VerifiedScannerFinding;
  ai_generated_explanation?: {
    summary: string;
    why_it_matters: string;
    technical_impact: string;
  };
  ai_generated_inference?: {
    architectural_risk_scope: string;
    inferred_blast_radius: string;
    ai_hypotheses: string[];
  };
  unverified_information?: {
    has_unverified_claims: boolean;
    unsupported_claims: string[];
    advisory_gaps: string[];
  };
  validation_report?: ValidationReport;
}

export interface AIStatusResponse {
  status: 'AI_READY' | 'AI_NOT_CONFIGURED' | 'AI_UNAVAILABLE_OFFLINE' | 'AI_AUTH_FAILED' | 'AI_QUOTA_EXCEEDED' | 'AI_MODEL_UNAVAILABLE' | 'AI_REQUEST_FAILED';
  configured: boolean;
  model: string;
  message: string;
}
