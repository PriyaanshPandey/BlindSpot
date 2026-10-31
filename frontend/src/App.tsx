import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { PrivacyBanner } from './components/PrivacyBanner';
import { KnowledgeStatusBadge } from './components/KnowledgeStatusBadge';
import { AIExplainModal } from './components/AIExplainModal';
import { BuilderDashboard } from './pages/BuilderDashboard';
import { EnterpriseDashboard } from './pages/EnterpriseDashboard';
import {
  GraphData,
  Finding,
  GraphNode,
  SimulationResult,
  ScanSummary
} from './types';
import {
  createScan,
  getScanGraph,
  getScanFindings,
  simulateFailure
} from './api/client';

export const App: React.FC = () => {
  const [mode, setMode] = useState<'builder' | 'enterprise'>('enterprise');
  const [isScanning, setIsScanning] = useState(false);
  const [scan, setScan] = useState<ScanSummary | null>(null);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedFindingForAI, setSelectedFindingForAI] = useState<Finding | null>(null);
  const [isKnowledgeModalOpen, setIsKnowledgeModalOpen] = useState(false);
  const [simulation, setSimulation] = useState<SimulationResult | null>(null);
  const [durationHours, setDurationHours] = useState<number>(4);

  // Initial load
  useEffect(() => {
    handleRunScan();
  }, []);

  const handleRunScan = async () => {
    setIsScanning(true);
    try {
      const scanRes = await createScan('./demo/nexus-commerce');
      setScan(scanRes);

      const [graphRes, findingsRes] = await Promise.all([
        getScanGraph(scanRes.scan_id),
        getScanFindings(scanRes.scan_id)
      ]);

      setGraphData(graphRes);
      setFindings(findingsRes);
      setSimulation(null);
    } catch (err) {
      console.warn('Backend unavailable, using baseline data:', err);
      // Fallback baseline for initial standalone UI development
      setGraphData({
        scan_id: 'default-scan',
        created_at: new Date().toISOString(),
        nodes: [
          { id: 'app:nexus-frontend', label: 'Nexus Web Storefront', type: 'application', provenance: 'declared', status: 'healthy', criticality: 'critical' },
          { id: 'service:nexus-api', label: 'Checkout API Gateway', type: 'internal_service', provenance: 'declared', status: 'healthy', criticality: 'critical' },
          { id: 'vendor:stripe', label: 'Stripe Payments', type: 'vendor', provenance: 'declared', status: 'healthy', criticality: 'critical' },
          { id: 'vendor:auth0', label: 'Auth0 Identity', type: 'vendor', provenance: 'declared', status: 'healthy', criticality: 'high' },
          { id: 'vendor:aws-us-east-1', label: 'AWS US-East-1', type: 'infrastructure_resource', provenance: 'disclosed', status: 'healthy', criticality: 'critical' },
          { id: 'pkg:event-stream', label: 'npm: event-stream@3.3.6', type: 'software_package', provenance: 'declared', status: 'compromised', criticality: 'critical' },
          { id: 'unknown:analytics-cdn', label: 'telemetry.untrusted-cdn.net', type: 'external_api', provenance: 'observed', status: 'warning', criticality: 'high' },
          { id: 'journey:checkout', label: 'Journey: Customer Checkout', type: 'business_journey', provenance: 'inferred', status: 'healthy', criticality: 'critical' }
        ],
        edges: [
          { id: 'e1', source: 'app:nexus-frontend', target: 'service:nexus-api', relation: 'calls_api', provenance: 'declared', confidence_score: 1.0 },
          { id: 'e2', source: 'service:nexus-api', target: 'vendor:stripe', relation: 'calls_api', provenance: 'declared', confidence_score: 1.0 },
          { id: 'e3', source: 'service:nexus-api', target: 'vendor:auth0', relation: 'authenticates_via', provenance: 'declared', confidence_score: 1.0 },
          { id: 'e4', source: 'vendor:stripe', target: 'vendor:aws-us-east-1', relation: 'depends_on', provenance: 'vendor_passport', confidence_score: 0.95 },
          { id: 'e5', source: 'service:nexus-api', target: 'pkg:event-stream', relation: 'transitive_dependency', provenance: 'declared', confidence_score: 1.0 },
          { id: 'e6', source: 'app:nexus-frontend', target: 'unknown:analytics-cdn', relation: 'calls_api', provenance: 'observed', confidence_score: 0.99 },
          { id: 'e7', source: 'vendor:stripe', target: 'journey:checkout', relation: 'powers_journey', provenance: 'inferred', confidence_score: 1.0 }
        ],
        metadata: { total_nodes: 8, total_edges: 7, discrepancy_count: 1, vulnerability_count: 1 }
      });
      setFindings([
        {
          id: 'find-001',
          scan_id: 'default-scan',
          type: 'discrepancy_undeclared_endpoint',
          title: 'Undocumented External Endpoint Observed',
          description: 'Browser network crawling detected communication with telemetry.untrusted-cdn.net which is absent from declared infrastructure and architecture documentation.',
          severity: 'high',
          target_node_id: 'unknown:analytics-cdn',
          affected_journey_ids: ['journey:checkout'],
          evidence_references: ['trace:span-99120', 'playwright:browser-network-log-01'],
          remediation: {
            summary: 'Audit third-party frontend scripts',
            recommended_action: 'Remove unauthorized script tag from frontend/checkout.js or declare legitimate vendor with CSP.'
          }
        },
        {
          id: 'find-002',
          scan_id: 'default-scan',
          type: 'vulnerability_compromised_package',
          title: 'Compromised Transitive Dependency Detected',
          description: 'Package event-stream@3.3.6 contains malicious code injection targeting cryptocurrency wallets and sensitive credentials (CVE-2018-3721).',
          severity: 'critical',
          target_node_id: 'pkg:event-stream',
          affected_journey_ids: ['journey:checkout'],
          evidence_references: ['manifest:package.json'],
          security_details: {
            cve_id: 'CVE-2018-3721',
            cvss_score: 9.8,
            advisory_source: 'OSV / GitHub Security Advisory',
            fixed_version: '3.3.7'
          },
          remediation: {
            summary: 'Upgrade package to non-compromised release',
            recommended_action: 'Run `npm install event-stream@3.3.7` or remove dependency.'
          }
        }
      ]);
    } finally {
      setIsScanning(false);
    }
  };

  const handleSimulateOutage = async (targetNodeId: string, hours: number = durationHours) => {
    try {
      const scanId = scan?.scan_id || 'default-scan';
      const simRes = await simulateFailure(scanId, targetNodeId, hours);
      setSimulation(simRes);
    } catch (err) {
      console.error('Simulation error:', err);
    }
  };

  const handleDurationChange = (newHours: number) => {
    setDurationHours(newHours);
    if (simulation) {
      handleSimulateOutage(simulation.target_node_id, newHours);
    }
  };

  return (
    <div className="min-h-screen bg-[#080C14] text-slate-100 flex flex-col font-sans">
      {/* Navigation */}
      <Navbar
        mode={mode}
        setMode={setMode}
        onTriggerScan={handleRunScan}
        isScanning={isScanning}
        onOpenKnowledgeModal={() => setIsKnowledgeModalOpen(true)}
      />

      {/* Local-First Privacy Guarantee Banner */}
      <PrivacyBanner />

      {/* Main Mode Views */}
      <main className="flex-1">
        {mode === 'builder' ? (
          <BuilderDashboard
            scan={scan}
            graphData={graphData}
            findings={findings}
            onTriggerScan={handleRunScan}
            isScanning={isScanning}
            onSelectFinding={setSelectedFindingForAI}
            onSelectNode={setSelectedNode}
          />
        ) : (
          <EnterpriseDashboard
            graphData={graphData}
            findings={findings}
            selectedNode={selectedNode}
            onSelectNode={setSelectedNode}
            onSimulateOutage={handleSimulateOutage}
            simulation={simulation}
            durationHours={durationHours}
            onDurationChange={handleDurationChange}
            onResetSimulation={() => setSimulation(null)}
            onExplainAI={setSelectedFindingForAI}
          />
        )}
      </main>

      {/* Modals & Dialogs */}
      <KnowledgeStatusBadge
        isOpen={isKnowledgeModalOpen}
        onClose={() => setIsKnowledgeModalOpen(false)}
      />

      <AIExplainModal
        finding={selectedFindingForAI}
        mode={mode}
        isOpen={selectedFindingForAI !== null}
        onClose={() => setSelectedFindingForAI(null)}
      />
    </div>
  );
};
export default App;
