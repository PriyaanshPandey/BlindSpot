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
  const [targetPath, setTargetPath] = useState<string>('./demo/nexus-commerce');
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
    handleRunScan('./demo/nexus-commerce');
  }, []);

  const handleRunScan = async (pathOverride?: string) => {
    const pathToScan = pathOverride || targetPath;
    setIsScanning(true);
    try {
      const scanRes = await createScan(pathToScan);
      setScan(scanRes);

      const [graphRes, findingsRes] = await Promise.all([
        getScanGraph(scanRes.scan_id),
        getScanFindings(scanRes.scan_id)
      ]);

      setGraphData(graphRes);
      setFindings(findingsRes);
      setSelectedNode(null);
      setSimulation(null);
    } catch (err: any) {
      console.warn('Scan invocation notice:', err);
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
      {/* Navigation with Target Folder Selector */}
      <Navbar
        mode={mode}
        setMode={setMode}
        targetPath={targetPath}
        setTargetPath={setTargetPath}
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
            onTriggerScan={() => handleRunScan(targetPath)}
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
