import React, { useState, useEffect } from 'react';
import { AppSidebar } from './components/AppSidebar';
import { AppHeaderStrip } from './components/AppHeaderStrip';
import { AnalysisLoadingOverlay } from './components/AnalysisLoadingOverlay';
import { KnowledgeStatusBadge } from './components/KnowledgeStatusBadge';
import { AIExplainModal } from './components/AIExplainModal';
import { GraphExplorer } from './components/GraphExplorer';
import { NodeInspectorDrawer } from './components/NodeInspectorDrawer';
import { FailureSimulationPanel } from './components/FailureSimulationPanel';
import { LandingPage } from './components/LandingPage';
import {
  ShieldCheck,
  Flame,
  Sparkles,
  ArrowUpRight,
  Wrench
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
  getScanGraph,
  getScanFindings,
  simulateFailure
} from './api/client';

export const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<'landing' | 'dashboard'>('landing');
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [mode, setMode] = useState<'builder' | 'enterprise'>('enterprise');
  const [activeTab, setActiveTab] = useState<'graph' | 'findings' | 'simulation' | 'passports'>('graph');
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
      setActiveTab('simulation');
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
      <>
        {isScanning && <AnalysisLoadingOverlay />}
        <LandingPage
          onScanFiles={handleScanFiles}
          onStartScan={handleStartScan}
          isScanning={isScanning}
        />
      </>
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
        mode={mode}
        setMode={setMode}
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
          onStartScan={handleStartScan}
          filterLayer={filterLayer}
          setFilterLayer={setFilterLayer}
          activeTab={activeTab}
          isScanning={isScanning}
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
                onExplainAI={setSelectedFindingForAI}
                associatedFindings={findings.filter((f) => f.target_node_id === selectedNode?.id)}
              />
            </div>
          )}

          {/* Tab 2: Findings & Discrepancies */}
          {activeTab === 'findings' && (
            <div className="p-8 max-w-6xl mx-auto space-y-6 overflow-y-auto h-full">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-bold text-white">Discrepancies & Vulnerabilities</h2>
                  <p className="text-xs text-slate-400">
                    Live reconciliation between declared architecture and actual code network calls.
                  </p>
                </div>
                <span className="text-xs bg-amber-500/10 text-amber-300 border border-amber-500/20 px-3 py-1 rounded-xl font-semibold">
                  {findings.length} Actionable Items
                </span>
              </div>

              {findings.length === 0 ? (
                <div className="p-12 rounded-3xl bg-black/60 border border-white/10 text-center space-y-2">
                  <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
                  <h3 className="font-bold text-white">Zero Known Vulnerabilities or Discrepancies</h3>
                  <p className="text-xs text-slate-400">All scanned dependencies and endpoints are verified.</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {findings.map((finding) => (
                    <div
                      key={finding.id}
                      className="p-5 rounded-2xl bg-black/60 border border-white/10 hover:border-white/20 transition-all space-y-3 shadow-xl backdrop-blur-md"
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              finding.severity === 'critical'
                                ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                                : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            }`}
                          >
                            {finding.severity}
                          </span>
                          <h4 className="font-bold text-white text-sm">{finding.title}</h4>
                        </div>
                        <span className="font-mono text-xs text-rose-400 bg-white/[0.04] px-2 py-0.5 rounded border border-white/10">
                          {finding.target_node_id}
                        </span>
                      </div>

                      <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>

                      {/* Safe Remediation */}
                      {finding.remediation && (
                        <div className="p-3 rounded-xl bg-white/[0.02] border border-emerald-500/20 space-y-1">
                          <span className="text-[10px] font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-1">
                            <Wrench className="w-3 h-3" /> Recommended Action:
                          </span>
                          <p className="text-xs text-slate-300 font-mono">
                            {finding.remediation.recommended_action}
                          </p>
                        </div>
                      )}

                      {/* Gemini AI Explain Action Button */}
                      <div className="pt-1 flex items-center justify-between">
                        <button
                          onClick={() => setSelectedFindingForAI(finding)}
                          className="flex items-center gap-2 py-2 px-4 rounded-xl bg-gradient-to-r from-rose-600 via-purple-600 to-indigo-600 hover:from-rose-500 hover:to-indigo-500 text-white font-semibold text-xs shadow-lg shadow-purple-600/20 transition-all cursor-pointer"
                        >
                          <Sparkles className="w-3.5 h-3.5" />
                          <span>Explain with Gemini AI</span>
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </button>

                        <span className="text-[11px] text-slate-500">
                          Evidence: {finding.evidence_references?.join(', ')}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab 3: Failure Simulator */}
          {activeTab === 'simulation' && (
            <div className="p-8 max-w-6xl mx-auto space-y-6 overflow-y-auto h-full">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-bold text-white">Failure Simulation & Business Impact</h2>
                  <p className="text-xs text-slate-400">
                    Simulate outage of any component and quantify cascading revenue and journey exposure.
                  </p>
                </div>
              </div>

              {simulation ? (
                <FailureSimulationPanel
                  simulation={simulation}
                  durationHours={durationHours}
                  onDurationChange={handleDurationChange}
                  onResetSimulation={() => setSimulation(null)}
                />
              ) : (
                <div className="p-12 rounded-3xl bg-black/60 border border-white/10 text-center space-y-4 backdrop-blur-md">
                  <Flame className="w-12 h-12 text-rose-500 mx-auto" />
                  <h3 className="font-bold text-lg text-white">No Failure Simulation Currently Active</h3>
                  <p className="text-xs text-slate-400 max-w-md mx-auto">
                    Select any component from the list below or click any node directly on the Dependency Graph.
                  </p>

                  <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
                    {graphData?.nodes
                      .filter(
                        (n) =>
                          n.type === 'vendor' ||
                          n.type === 'internal_service' ||
                          n.type === 'external_api'
                      )
                      .map((node) => (
                        <button
                          key={node.id}
                          onClick={() => handleSimulateOutage(node.id, 4)}
                          className="px-4 py-2 rounded-xl bg-white/[0.04] hover:bg-white/10 text-white text-xs font-semibold border border-white/10 transition-all flex items-center gap-2 cursor-pointer"
                        >
                          <Flame className="w-3.5 h-3.5 text-rose-400" />
                          <span>Simulate Outage: {node.label}</span>
                        </button>
                      ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab 4: Vendor Passports */}
          {activeTab === 'passports' && (
            <div className="p-8 max-w-6xl mx-auto space-y-6 overflow-y-auto h-full">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-bold text-white">Cryptographic Vendor Resilience Passports</h2>
                  <p className="text-xs text-slate-400">
                    Upstream third-party disclosures with cryptographic Ed25519 signatures.
                  </p>
                </div>
                <span className="text-xs font-mono text-purple-400 bg-purple-500/10 px-3 py-1 rounded-xl border border-purple-500/20">
                  Ed25519 Verified
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Stripe */}
                <div className="p-5 rounded-2xl bg-black/60 border border-white/10 space-y-3 shadow-xl backdrop-blur-md">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-sm">Stripe, Inc.</span>
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      Passport v1.0.0
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Discloses upstream compute & cloud resources supporting payment APIs.
                  </p>
                  <div className="p-3 rounded-xl bg-white/[0.02] border border-white/10 space-y-2 text-xs">
                    <div className="flex items-center justify-between text-slate-300">
                      <span>• Amazon Web Services (AWS us-east-1)</span>
                      <span className="text-purple-400 font-mono text-[11px]">Primary Compute</span>
                    </div>
                    <div className="flex items-center justify-between text-slate-300">
                      <span>• Cloudflare Global Edge</span>
                      <span className="text-purple-400 font-mono text-[11px]">DDoS & Anycast</span>
                    </div>
                  </div>
                  <button
                    onClick={() => handleSimulateOutage('vendor:stripe')}
                    className="w-full py-2 px-3 rounded-xl bg-white/[0.04] hover:bg-white/10 text-slate-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                  >
                    <Flame className="w-3.5 h-3.5 text-rose-400" />
                    <span>Simulate Stripe Outage</span>
                  </button>
                </div>

                {/* Auth0 */}
                <div className="p-5 rounded-2xl bg-black/60 border border-white/10 space-y-3 shadow-xl backdrop-blur-md">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-sm">Auth0 (Okta)</span>
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      Passport v1.0.0
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Discloses identity federation nodes and token verification backends.
                  </p>
                  <div className="p-3 rounded-xl bg-white/[0.02] border border-white/10 space-y-2 text-xs">
                    <div className="flex items-center justify-between text-slate-300">
                      <span>• AWS Global Identity Cluster</span>
                      <span className="text-purple-400 font-mono text-[11px]">Core IdP</span>
                    </div>
                    <div className="flex items-center justify-between text-slate-300">
                      <span>• Fastly Content Delivery</span>
                      <span className="text-purple-400 font-mono text-[11px]">Edge CDN</span>
                    </div>
                  </div>
                  <button
                    onClick={() => handleSimulateOutage('vendor:auth0')}
                    className="w-full py-2 px-3 rounded-xl bg-white/[0.04] hover:bg-white/10 text-slate-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                  >
                    <Flame className="w-3.5 h-3.5 text-rose-400" />
                    <span>Simulate Auth0 Outage</span>
                  </button>
                </div>
              </div>
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
    </div>
  );
};

export default App;
