import React from 'react';
import { Shield, Sparkles, CheckCircle2, AlertTriangle, ArrowUpRight, Wrench, Play } from 'lucide-react';
import { GraphData, Finding, GraphNode, ScanSummary } from '../types';
import { GraphExplorer } from '../components/GraphExplorer';

interface BuilderDashboardProps {
  scan: ScanSummary | null;
  graphData: GraphData | null;
  findings: Finding[];
  onTriggerScan: () => void;
  isScanning: boolean;
  onSelectFinding: (finding: Finding) => void;
  onSelectNode: (node: GraphNode | null) => void;
}

export const BuilderDashboard: React.FC<BuilderDashboardProps> = ({
  scan,
  graphData,
  findings,
  onTriggerScan,
  isScanning,
  onSelectFinding,
  onSelectNode
}) => {
  const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
  const healthyCount = (scan?.summary.declared_dependencies || 18) - findings.length;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Hero / Quick Status */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Project Health Score */}
        <div className="p-5 rounded-2xl bg-gradient-to-br from-blue-900/30 via-slate-900 to-slate-950 border border-blue-500/20 shadow-xl flex items-center justify-between">
          <div>
            <span className="text-xs text-blue-400 font-semibold uppercase tracking-wider block">Dependency Health</span>
            <div className="text-3xl font-black text-white mt-1">78<span className="text-sm font-normal text-slate-400">/100</span></div>
            <span className="text-xs text-amber-400 mt-1 block">2 Actionable Issues Found</span>
          </div>
          <div className="w-14 h-14 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
            <Shield className="w-7 h-7" />
          </div>
        </div>

        {/* Clean Dependencies */}
        <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl">
          <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider block">Secure Packages</span>
          <div className="text-3xl font-black text-emerald-400 mt-1">{healthyCount}</div>
          <span className="text-xs text-slate-500 mt-1 block">Verified against public advisories</span>
        </div>

        {/* Actionable Findings */}
        <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl">
          <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider block">Security Alerts</span>
          <div className="text-3xl font-black text-rose-400 mt-1">{findings.length}</div>
          <span className="text-xs text-slate-500 mt-1 block">1 compromised package, 1 unknown endpoint</span>
        </div>

        {/* Scan Target */}
        <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl flex flex-col justify-between">
          <div>
            <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider block">Target Project</span>
            <div className="text-base font-bold text-white mt-1 truncate">Nexus Commerce</div>
            <span className="text-[11px] font-mono text-slate-500 block">./demo/nexus-commerce</span>
          </div>
          <button
            onClick={onTriggerScan}
            disabled={isScanning}
            className="mt-2 text-xs font-semibold text-blue-400 hover:text-blue-300 flex items-center gap-1"
          >
            <Play className="w-3 h-3 fill-current" />
            <span>Re-scan now</span>
          </button>
        </div>
      </div>

      {/* Main Grid: Visual Map + Beginner-Friendly Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Interactive Dependency Map */}
        <div className="lg:col-span-7 bg-slate-900/80 border border-slate-800 rounded-2xl p-4 shadow-xl flex flex-col h-[520px]">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <h3 className="font-bold text-white text-sm">Visual Dependency Ecosystem</h3>
              <p className="text-xs text-slate-400">Click any component to inspect details or simulate failures</p>
            </div>
            <span className="text-xs text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
              Interactive Graph
            </span>
          </div>

          <div className="flex-1 relative mt-2 rounded-xl overflow-hidden border border-slate-800/80">
            <GraphExplorer
              graphData={graphData}
              onSelectNode={onSelectNode}
              selectedNodeId={null}
              blastRadiusIds={[]}
              filterLayer="all"
            />
          </div>
        </div>

        {/* Right: Plain-English Vulnerabilities & Safe Patches */}
        <div className="lg:col-span-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-bold text-white text-sm flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-purple-400" />
              <span>Beginner-Friendly Action Items</span>
            </h3>
            <span className="text-xs text-slate-500">Sorted by risk</span>
          </div>

          <div className="space-y-3">
            {findings.map(finding => (
              <div
                key={finding.id}
                className="p-4 rounded-2xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all space-y-3 shadow-lg"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className={`w-2.5 h-2.5 rounded-full ${
                      finding.severity === 'critical' ? 'bg-rose-500 animate-pulse' : 'bg-amber-500'
                    }`} />
                    <h4 className="font-semibold text-white text-xs">{finding.title}</h4>
                  </div>
                  <span className="font-mono text-[10px] text-slate-400 px-2 py-0.5 rounded bg-slate-800">
                    {finding.target_node_id}
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {finding.description}
                </p>

                {/* Safe Recommendation Box */}
                {finding.remediation && (
                  <div className="p-3 rounded-xl bg-slate-950 border border-emerald-500/20 space-y-1">
                    <span className="text-[10px] font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-1">
                      <Wrench className="w-3 h-3" /> Safe Fix:
                    </span>
                    <p className="text-xs text-slate-300 font-mono">
                      {finding.remediation.recommended_action}
                    </p>
                  </div>
                )}

                {/* AI Explanation Action */}
                <button
                  onClick={() => onSelectFinding(finding)}
                  className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-xl bg-gradient-to-r from-blue-600/20 to-purple-600/20 hover:from-blue-600/30 hover:to-purple-600/30 border border-blue-500/30 text-blue-300 hover:text-white transition-all text-xs font-semibold"
                >
                  <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                  <span>Ask Gemini: Explain in Plain English</span>
                  <ArrowUpRight className="w-3.5 h-3.5 ml-auto" />
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

