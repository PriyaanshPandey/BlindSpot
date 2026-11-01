import {
  GraphData,
  Finding,
  SimulationResult,
  ScanSummary,
  KnowledgeManifest,
  BundleVerificationSummary,
  AIExplanation
} from '../types';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

export async function createScan(repoPath: string = './demo/nexus-commerce'): Promise<ScanSummary> {
  const res = await fetch(`${API_BASE}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      repo_path: repoPath,
      trace_file_path: './fixtures/runtime/traces.sample.json',
      enable_vendor_passports: true
    })
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(errText || `Scan trigger failed: ${res.statusText}`);
  }
  return res.json();
}

export async function scanUploadedFiles(projectName: string, files: Record<string, string>): Promise<ScanSummary> {
  const res = await fetch(`${API_BASE}/scans/direct`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      project_name: projectName,
      files
    })
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(errText || `Direct file scan failed: ${res.statusText}`);
  }
  return res.json();
}

export async function uploadZipScan(file: File): Promise<ScanSummary> {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`${API_BASE}/scans/upload-zip`, {
    method: 'POST',
    body: formData
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(errText || `ZIP archive scan failed: ${res.statusText}`);
  }
  return res.json();
}

export async function getScan(scanId: string): Promise<ScanSummary> {
  const res = await fetch(`${API_BASE}/scans/${scanId}`);
  if (!res.ok) throw new Error(`Fetch scan failed: ${res.statusText}`);
  return res.json();
}

export async function getScanGraph(scanId: string, filterLayer: string = 'all'): Promise<GraphData> {
  const res = await fetch(`${API_BASE}/scans/${scanId}/graph?filter_layer=${filterLayer}`);
  if (!res.ok) throw new Error(`Fetch graph failed: ${res.statusText}`);
  return res.json();
}

export async function getScanFindings(scanId: string): Promise<Finding[]> {
  const res = await fetch(`${API_BASE}/scans/${scanId}/findings`);
  if (!res.ok) throw new Error(`Fetch findings failed: ${res.statusText}`);
  return res.json();
}

export async function simulateFailure(
  scanId: string,
  targetNodeId: string,
  durationHours: number = 4.0,
  txOverride?: number,
  avgValOverride?: number
): Promise<SimulationResult> {
  const res = await fetch(`${API_BASE}/scans/${scanId}/simulate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target_node_id: targetNodeId,
      failure_type: 'complete_outage',
      failure_duration_hours: durationHours,
      hourly_transactions_override: txOverride,
      average_transaction_value_override: avgValOverride
    })
  });
  if (!res.ok) throw new Error(`Failure simulation failed: ${res.statusText}`);
  return res.json();
}

export async function previewAIPayload(finding: Finding, audience: 'builder' | 'enterprise') {
  const res = await fetch(`${API_BASE}/ai/preview-payload`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      finding_id: finding.id,
      title: finding.title,
      package_name: finding.target_node_id.replace('pkg:', '').replace('ext:', ''),
      cve_id: finding.security_details?.cve_id,
      severity: finding.severity,
      audience
    })
  });
  if (!res.ok) throw new Error(`Preview payload failed: ${res.statusText}`);
  return res.json();
}

export async function explainFindingAI(
  finding: Finding,
  audience: string = 'developer',
  approved: boolean = true,
  apiKey?: string
): Promise<AIExplanation> {
  const res = await fetch(`${API_BASE}/ai/explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      finding_id: finding.id,
      title: finding.title,
      package_name: finding.target_node_id.replace('pkg:', '').replace('ext:', ''),
      cve_id: finding.security_details?.cve_id,
      severity: finding.severity,
      audience,
      user_approved_transmission: approved,
      api_key: apiKey || undefined
    })
  });
  if (!res.ok) throw new Error(`AI explanation failed: ${res.statusText}`);
  return res.json();
}

export async function getKnowledgeManifest(): Promise<KnowledgeManifest> {
  const res = await fetch(`${API_BASE}/knowledge/manifest`);
  if (!res.ok) throw new Error(`Knowledge manifest fetch failed: ${res.statusText}`);
  return res.json();
}

export async function verifyKnowledgeBundle(simulateTamper: boolean = false): Promise<BundleVerificationSummary> {
  const res = await fetch(`${API_BASE}/knowledge/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ simulate_tamper: simulateTamper })
  });
  if (!res.ok) throw new Error(`Bundle verification failed: ${res.statusText}`);
  return res.json();
}
