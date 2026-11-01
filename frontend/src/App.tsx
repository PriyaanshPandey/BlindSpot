import React, { useState, useEffect } from 'react';
import { AppSidebar } from './components/AppSidebar';
import { AppHeaderStrip } from './components/AppHeaderStrip';
import { AnalysisLoadingOverlay } from './components/AnalysisLoadingOverlay';
import { KnowledgeStatusBadge } from './components/KnowledgeStatusBadge';
import { AIExplainModal } from './components/AIExplainModal';
import { AskBlindSpot } from './components/AskBlindSpot';
import { GraphExplorer } from './components/GraphExplorer';
import { NodeInspectorDrawer } from './components/NodeInspectorDrawer';
import { LandingPage } from './components/LandingPage';
import { ThirdPartyIntelligenceView } from './components/ThirdPartyIntelligenceView';
import { LiveRadarView } from './components/LiveRadarView';
import { VendorPassportsView } from './components/VendorPassportsView';
import {
  ShieldCheck,
  Flame,
  Sparkles,
  ArrowUpRight,
  Wrench,
  Radar,
  Globe,
  Database,
  Server,
  CheckCircle2
} from 'lucide-react';
import {
  GraphData,
  Finding,
  GraphNode,
  SimulationResult,
  ScanSummary
} from './types';
import {
  createScan,
  scanUploadedFiles,
  uploadZipScan,
  getScanGraph,
  getScanFindings,
  simulateFailure
} from './api/client';

export const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<'landing' | 'dashboard'>('landing');
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [mode, setMode] = useState<'builder' | 'enterprise'>('enterprise');
  const [activeTab, setActiveTab] = useState<'graph' | 'findings' | 'passports' | 'third-party'>('graph');
  const [targetPath, setTargetPath] = useState<string>('./demo/nexus-commerce');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProjectName, setScanProjectName] = useState<string>('Nexus Commerce');
  const [scan, setScan] = useState<ScanSummary | null>(null);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedFindingForAI, setSelectedFindingForAI] = useState<Finding | null>(null);
  const [isKnowledgeModalOpen, setIsKnowledgeModalOpen] = useState(false);
  const [simulation, setSimulation] = useState<SimulationResult | null>(null);
  const [durationHours, setDurationHours] = useState<number>(4);
  const [filterLayer, setFilterLayer] = useState<string>('all');

  // Initial pre-load of sample demo in background
  useEffect(() => {
    handleRunScan('./demo/nexus-commerce', false);
  }, []);

  const handleRunScan = async (pathOverride?: string, shouldSwitchView: boolean = true) => {
    const pathToScan = pathOverride || targetPath;
    setIsScanning(true);
    setScanProjectName(pathToScan.split('/').pop() || 'Codebase');
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
      if (shouldSwitchView) {
        setCurrentView('dashboard');
        setActiveTab('graph');
      }
    } catch (err: any) {
      console.warn('Scan notice:', err);
    } finally {
      // Keep loading overlay smooth for a minimum period
      setTimeout(() => {
        setIsScanning(false);
      }, 1600);
    }
  };

  const handleScanZip = async (file: File) => {
    setIsScanning(true);
    const cleanName = file.name.replace(/\.zip$/i, '');
    setScanProjectName(cleanName);
    try {
      const scanRes = await uploadZipScan(file);
      setScan(scanRes);

      const [graphRes, findingsRes] = await Promise.all([
        getScanGraph(scanRes.scan_id),
        getScanFindings(scanRes.scan_id)
      ]);

      setGraphData(graphRes);
      setFindings(findingsRes);
      setSelectedNode(null);
      setSimulation(null);
      setActiveTab('graph');
      setCurrentView('dashboard');
    } catch (err: any) {
      console.error('ZIP scan failed:', err);
    } finally {
      setTimeout(() => {
        setIsScanning(false);
      }, 1600);
    }
  };

  const handleStartScan = (projectName: string) => {
    setIsScanning(true);
    setScanProjectName(projectName);
  };

  const handleScanFiles = async (projectName: string, files: Record<string, string>) => {
    setIsScanning(true);
    setScanProjectName(projectName);
    try {
      const scanRes = await scanUploadedFiles(projectName, files);
      setScan(scanRes);

      const [graphRes, findingsRes] = await Promise.all([
        getScanGraph(scanRes.scan_id),
        getScanFindings(scanRes.scan_id)
      ]);

      setGraphData(graphRes);
      setFindings(findingsRes);
      setSelectedNode(null);
      setSimulation(null);
      setActiveTab('graph');
      setCurrentView('dashboard');
    } catch (err: any) {
      console.error('File scan failed:', err);
    } finally {
      setTimeout(() => {
        setIsScanning(false);
      }, 1600);
    }
  };

  const handleSimulateOutage = async (targetNodeId: string, hours: number = durationHours) => {
    try {
      const scanId = scan?.scan_id || 'default-scan';
      const simRes = await simulateFailure(scanId, targetNodeId, hours);
      setSimulation(simRes);
      const targetNode = graphData?.nodes.find((n) => n.id === targetNodeId);
      if (targetNode) {
        setSelectedNode(targetNode);
      }
      setActiveTab('graph');
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

  const blastRadiusIds = simulation?.impact_results.impacted_node_ids || [];

  if (currentView === 'landing') {
    return (
      <LandingPage
        onScanFiles={handleScanFiles}
        onScanZip={handleScanZip}
        onStartScan={handleStartScan}
        isScanning={isScanning}
      />
    );
  }

  return (
    <div className="h-screen w-screen bg-[#050205] text-slate-100 flex overflow-hidden font-sans">
      {/* 1. Cinematic Loading Overlay during Scan */}
      {isScanning && (
        <AnalysisLoadingOverlay projectName={scanProjectName || scan?.project_name || 'Target Codebase'} />
      )}

      {/* 2. Transparent Collapsible Sidebar */}
      <AppSidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isCollapsed={isSidebarCollapsed}
        setIsCollapsed={setIsSidebarCollapsed}
        graphNodeCount={graphData?.nodes.length || 0}
        findingsCount={findings.length}
        hasActiveSimulation={simulation !== null}
        onOpenKnowledgeModal={() => setIsKnowledgeModalOpen(true)}
        onGoToLanding={() => setCurrentView('landing')}
      />

      {/* 3. Main Full Screen Area */}
      <div className="flex-1 flex flex-col min-w-0 bg-[#060205] relative overflow-hidden h-full">
        {/* Minimal Floating Header Strip (Only: Selected folder name/path + Upload other folder icon) */}
        <AppHeaderStrip
          projectName={scanProjectName || scan?.project_name || targetPath}
          targetPath={targetPath}
          onScanFiles={async (name, files) => {
            await handleScanFiles(name, files);
          }}
          onScanZip={handleScanZip}
          onStartScan={handleStartScan}
          filterLayer={filterLayer}
          setFilterLayer={setFilterLayer}
          activeTab={activeTab}
          isScanning={isScanning}
          mode={mode}
          setMode={setMode}
        />

        {/* Content View Canvas */}
        <main className="flex-1 relative overflow-hidden w-full h-[calc(100vh-56px)]">
          {/* Tab 1: Graph Canvas (Default View) */}
          {activeTab === 'graph' && (
            <div className="w-full h-full relative">
              <GraphExplorer
                graphData={graphData}
                onSelectNode={setSelectedNode}
                selectedNodeId={selectedNode?.id || null}
                blastRadiusIds={blastRadiusIds}
                filterLayer={filterLayer}
              />

              {/* Slide-in Node Inspector Drawer */}
              <NodeInspectorDrawer
                node={selectedNode}
                onClose={() => setSelectedNode(null)}
                onSimulateNodeOutage={handleSimulateOutage}
                onClearSimulation={() => setSimulation(null)}
                simulation={simulation}
                onExplainAI={setSelectedFindingForAI}
                associatedFindings={findings.filter((f) => f.target_node_id === selectedNode?.id)}
                graphData={graphData}
              />
            </div>
          )}

          {/* Tab 2: Live Radar (Vulnerabilities & Drift) */}
          {activeTab === 'findings' && (
            <LiveRadarView
              findings={findings}
              graphData={graphData}
              onTraceInGraph={(nodeId) => {
                setActiveTab('graph');
                const targetNode = graphData?.nodes.find((n) => n.id === nodeId);
                if (targetNode) {
                  setSelectedNode(targetNode);
                }
                handleSimulateOutage(nodeId, 4);
              }}
              onExplainAI={(finding) => setSelectedFindingForAI(finding)}
            />
          )}
          {/* Tab 4: Vendor Passports */}
          {activeTab === 'passports' && (
            <VendorPassportsView
              graphData={graphData}
              onSimulateOutage={handleSimulateOutage}
              onSelectNode={(node) => {
                setSelectedNode(node);
                setActiveTab('graph');
              }}
            />
          )}
          {/* Tab 5: Third-Party Intelligence */}
          {activeTab === 'third-party' && (
            <div className="p-8 max-w-7xl mx-auto space-y-6 overflow-y-auto h-full">
              <ThirdPartyIntelligenceView scanId={scan?.scan_id || ''} />
            </div>
          )}
        </main>
      </div>

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

      {/* Global Ask BlindSpot Copilot */}
      <AskBlindSpot
        scanId={scan?.scan_id}
        projectName={scanProjectName}
        selectedFinding={selectedFindingForAI}
        selectedNode={selectedNode}
        simulation={simulation}
        mode={mode}
        findings={findings}
        onSelectFinding={(f) => setSelectedFindingForAI(f)}
        onSelectNode={(nodeId) => {
          const found = graphData?.nodes.find((n) => n.id === nodeId);
          if (found) {
            setSelectedNode(found);
            setActiveTab('graph');
          }
        }}
      />
    </div>
  );
};

export default App;
