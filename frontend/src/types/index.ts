export type NodeType =
  | 'application'
  | 'internal_service'
  | 'external_api'
  | 'vendor'
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
  remediation?: {
    summary: string;
    recommended_action: string;
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
  impact_results: {
    blast_radius_node_count: number;
    impacted_node_ids: string[];
    total_estimated_gross_exposure: number;
    exposure_currency: string;
    impacted_journeys: ImpactedJourney[];
    mitigation_strategies: Array<{
      strategy_type: string;
      title: string;
      description: string;
      estimated_risk_reduction_pct: number;
    }>;
  };
}

