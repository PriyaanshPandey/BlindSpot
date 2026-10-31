import React, { useState } from 'react';
import { Layers, ShieldAlert, Cpu, Filter, Flame, FileText, ChevronRight } from 'lucide-react';
import { GraphData, Finding, GraphNode, SimulationResult } from '../types';
import { GraphExplorer } from '../components/GraphExplorer';
import { DiscrepancyViewer } from '../components/DiscrepancyViewer';
import { FailureSimulationPanel } from '../components/FailureSimulationPanel';
import { NodeInspectorDrawer } from '../components/NodeInspectorDrawer';

interface EnterpriseDashboardProps {
  graphData: GraphData | null;
  findings: Finding[];
  selectedNode: GraphNode | null;
  onSelectNode: (node: GraphNode | null) => void;
  onSimulateOutage: (nodeId: string, durationHours?: number) => void;
  simulation: SimulationResult | null;
  durationHours: number;
  onDurationChange: (hours: number) => void;
  onResetSimulation: () => void;
  onExplainAI: (finding: Finding) => void;
}

export const EnterpriseDashboard: React.FC<EnterpriseDashboardProps> = ({
  graphData,
  findings,
  selectedNode,
  onSelectNode,
  onSimulateOutage,
  simulation,
  durationHours,
  onDurationChange,
  onResetSimulation,
  onExplainAI
}) => {
  const [filterLayer, setFilterLayer] = useState<string>('all');
  const [activeTab, setActiveTab] = useState<'graph' | 'discrepancies' | 'passports'>('graph');

  const blastRadiusIds = simulation?.impact_results.impacted_node_ids || [];

  return (
    <div className="relative flex flex-col h-[calc(100vh-64px-37px)] overflow-hidden bg-[#080C14]">
      {/* Top Filter & Layer Bar */}
      <div className="h-12 border-b border-slate-800 bg-slate-900/60 px-6 flex items-center justify-between z-20">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5 text-blue-400" />
            <span>Layer Filter:</span>
          </div>
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
            {[
              { id: 'all', label: 'All Layers' },
              { id: 'declared_only', label: 'Declared (Manifests)' },
              { id: 'observed_only', label: 'Observed (Traces)' },
              { id: 'discrepancies_only', label: 'Discrepancies Only' }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setFilterLayer(tab.id)}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                  filterLayer === tab.id
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Quick Tabs: Graph / Discrepancy Table / Vendor Passports */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('graph')}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition-all ${
              activeTab === 'graph' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            Topology Canvas
          </button>
          <button
            onClick={() => setActiveTab('discrepancies')}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
              activeTab === 'discrepancies' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            <span>Discrepancy Findings</span>
            <span className="w-4 h-4 rounded-full bg-amber-500/30 text-[10px] flex items-center justify-center font-bold">1</span>
          </button>
          <button
            onClick={() => setActiveTab('passports')}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
              activeTab === 'passports' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            <span>Vendor Passports</span>
            <span className="w-4 h-4 rounded-full bg-purple-500/30 text-[10px] flex items-center justify-center font-bold">2</span>
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="relative flex-1 overflow-hidden">
        {activeTab === 'graph' && (
          <div className="w-full h-full relative">
            <GraphExplorer
              graphData={graphData}
              onSelectNode={onSelectNode}
              selectedNodeId={selectedNode?.id || null}
              blastRadiusIds={blastRadiusIds}
              filterLayer={filterLayer}
            />

            {/* Slide-in Node Inspector */}
            <NodeInspectorDrawer
              node={selectedNode}
              onClose={() => onSelectNode(null)}
              onSimulateNodeOutage={onSimulateOutage}
              onExplainAI={onExplainAI}
              associatedFindings={findings.filter(f => f.target_node_id === selectedNode?.id)}
            />
          </div>
        )}

        {activeTab === 'discrepancies' && (
          <div className="p-8 max-w-5xl mx-auto overflow-y-auto h-full">
            <DiscrepancyViewer
              findings={findings}
              onSelectFinding={onExplainAI}
            />
          </div>
        )}

        {activeTab === 'passports' && (
          <div className="p-8 max-w-5xl mx-auto overflow-y-auto h-full space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-white">Cryptographic Vendor Dependency Passports</h3>
                <p className="text-xs text-slate-400">Voluntary signed disclosures identifying nested upstream sub-processors</p>
              </div>
              <span className="text-xs font-mono text-purple-400 bg-purple-500/10 px-2.5 py-1 rounded-lg border border-purple-500/20">
                Ed25519 Verified
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Stripe Passport */}
              <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3 shadow-xl">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white text-sm">Stripe, Inc.</span>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                    Passport v1.0.0
                  </span>
                </div>
                <p className="text-xs text-slate-400">
                  Discloses nested cloud dependencies supporting checkout and payment webhooks.
                </p>
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs">
                  <span className="text-[10px] text-slate-500 uppercase font-semibold block">Disclosed Upstream Infrastructure:</span>
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
                  onClick={() => onSimulateOutage('vendor:aws-us-east-1')}
                  className="w-full py-2 px-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all"
                >
                  <Flame className="w-3.5 h-3.5 text-rose-400" />
                  <span>Simulate Nested Failure (AWS US-East-1)</span>
                </button>
              </div>

              {/* Auth0 Passport */}
              <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3 shadow-xl">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white text-sm">Auth0 (Okta)</span>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                    Passport v1.0.0
                  </span>
                </div>
                <p className="text-xs text-slate-400">
                  Discloses identity federation nodes and token verification backends.
                </p>
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs">
                  <span className="text-[10px] text-slate-500 uppercase font-semibold block">Disclosed Upstream Infrastructure:</span>
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
                  onClick={() => onSimulateOutage('vendor:auth0')}
                  className="w-full py-2 px-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all"
                >
                  <Flame className="w-3.5 h-3.5 text-rose-400" />
                  <span>Simulate Auth0 Outage</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Bottom Failure Simulation Bar */}
      {simulation && (
        <FailureSimulationPanel
          simulation={simulation}
          durationHours={durationHours}
          onDurationChange={onDurationChange}
          onResetSimulation={onResetSimulation}
        />
      )}
    </div>
  );
};

