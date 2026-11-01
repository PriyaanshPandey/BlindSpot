import React, { useEffect, useState } from 'react';
import {
  X,
  Flame,
  Sparkles,
  Package,
  Layers,
  ArrowRight,
  RefreshCw,
  Clock,
  ShieldAlert,
  Sliders
} from 'lucide-react';
import { GraphNode, Finding, SimulationResult, GraphData } from '../types';

interface NodeInspectorDrawerProps {
  node: GraphNode | null;
  onClose: () => void;
  onSimulateNodeOutage: (nodeId: string, hours?: number) => void;
  onClearSimulation?: () => void;
  simulation?: SimulationResult | null;
  isSimulating?: boolean;
  onExplainAI: (finding: Finding) => void;
  associatedFindings: Finding[];
  graphData?: GraphData | null;
}

export const NodeInspectorDrawer: React.FC<NodeInspectorDrawerProps> = ({
  node,
  onClose,
  onSimulateNodeOutage,
  onClearSimulation,
  simulation,
  isSimulating = false,
  onExplainAI,
  associatedFindings,
  graphData
}) => {
  const [durationHours, setDurationHours] = useState<number>(4);

  // Automatically trigger simulation when a new node is selected
  useEffect(() => {
    if (node && (!simulation || simulation.target_node_id !== node.id)) {
      onSimulateNodeOutage(node.id, durationHours);
    }
  }, [node?.id]);

  if (!node) return null;

  // Calculate upstream and downstream connections from graphData
  const upstreamCallers = graphData?.edges.filter((e) => e.target === node.id) || [];
  const downstreamDependencies = graphData?.edges.filter((e) => e.source === node.id) || [];

  const isCurrentSimTarget = simulation?.target_node_id === node.id;
  const impactScore = isCurrentSimTarget
    ? Math.round(simulation?.impact_results.architecture_impact_score || 0)
    : null;
  const blastCount = isCurrentSimTarget
    ? simulation?.impact_results.blast_radius_node_count || 0
    : 0;
  const impactedJourneys = isCurrentSimTarget
    ? simulation?.impact_results.impacted_journeys || []
    : [];

  const handleDurationChange = (hours: number) => {
    setDurationHours(hours);
    onSimulateNodeOutage(node.id, hours);
  };

  const getScoreSeverity = (score: number) => {
    if (score >= 60) {
      return {
        label: 'High Severity',
        badgeClass: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
        barClass: 'bg-gradient-to-r from-orange-500 to-rose-500',
        dotClass: 'bg-rose-500'
      };
    }
    if (score >= 30) {
      return {
        label: 'Moderate Impact',
        badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
        barClass: 'bg-gradient-to-r from-amber-400 to-orange-500',
        dotClass: 'bg-amber-400'
      };
    }
    return {
      label: 'Low Risk',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      barClass: 'bg-gradient-to-r from-emerald-500 to-teal-400',
      dotClass: 'bg-emerald-400'
    };
  };

  const severityStyle = impactScore !== null ? getScoreSeverity(impactScore) : null;

  return (
    <div className="absolute top-0 right-0 h-full w-[410px] max-w-[calc(100vw-64px)] bg-slate-950/80 backdrop-blur-3xl border-l border-white/[0.06] shadow-2xl z-30 flex flex-col transition-all duration-300 select-none animate-in fade-in slide-in-from-right-4">
      {/* Top Header */}
      <div className="p-4 sm:p-5 border-b border-white/[0.06] flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-white/[0.04] border border-white/[0.08] text-indigo-400 shadow-sm">
            <Package className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-bold text-white text-sm tracking-tight">{node.label}</h3>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="font-mono text-[10px] text-slate-400 truncate max-w-[170px]">{node.id}</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded-md bg-white/[0.06] text-slate-300 font-medium capitalize">
                {node.type.replace('_', ' ')}
              </span>
            </div>
          </div>
        </div>

        <button
          onClick={onClose}
          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/[0.06] transition-colors cursor-pointer"
          title="Close Inspector"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Body Area */}
      <div className="p-5 flex-1 overflow-y-auto space-y-4 text-xs">
        {/* Failure Simulation Score Widget */}
        <div className="p-4 rounded-2xl bg-white/[0.03] hover:bg-white/[0.05] border border-white/[0.08] space-y-3.5 transition-all shadow-lg">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Flame className="w-4 h-4 text-rose-400" />
              <span className="font-semibold text-white text-xs tracking-wide">
                Failure Impact Score
              </span>
            </div>

            {severityStyle && impactScore !== null && (
              <span
                className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${severityStyle.badgeClass}`}
              >
                {severityStyle.label}
              </span>
            )}
          </div>

          {isSimulating ? (
            <div className="py-4 flex items-center justify-center gap-2 text-slate-400">
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-rose-400" />
              <span className="text-xs">Computing cascading blast radius...</span>
            </div>
          ) : impactScore !== null ? (
            <>
              {/* Large Score Display */}
              <div className="flex items-baseline justify-between pt-1">
                <div className="flex items-baseline gap-1.5">
                  <span className="text-3xl font-extrabold text-white tracking-tight">
                    {impactScore}
                  </span>
                  <span className="text-xs text-slate-400 font-medium">/ 100 Impact Score</span>
                </div>

                <span className="text-[11px] font-mono text-slate-400">
                  {blastCount} {blastCount === 1 ? 'component' : 'components'} disabled
                </span>
              </div>

              {/* Score Progress Bar */}
              <div className="h-2 rounded-full bg-white/10 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${severityStyle?.barClass}`}
                  style={{ width: `${Math.min(100, Math.max(5, impactScore))}%` }}
                />
              </div>

              {/* Impacted Journeys (if any) */}
              {impactedJourneys.length > 0 && (
                <div className="pt-1 text-[11px] text-slate-300 space-y-1">
                  <span className="text-[10px] uppercase font-bold text-slate-500 block">
                    Disrupted Business Flow:
                  </span>
                  {impactedJourneys.map((j) => (
                    <div
                      key={j.journey_id}
                      className="flex items-center justify-between px-2.5 py-1 rounded-lg bg-black/40 border border-white/5"
                    >
                      <span className="truncate max-w-[200px] text-rose-200">{j.name}</span>
                      <span className="font-mono text-rose-400 font-bold text-[10px]">
                        100% Disrupted
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {/* Outage Duration Controls */}
              <div className="pt-2 border-t border-white/[0.06] flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-slate-400">
                  <Clock className="w-3.5 h-3.5 text-slate-400" />
                  <span className="text-[11px]">Outage Window:</span>
                </div>

                <div className="flex items-center gap-1">
                  {[1, 4, 8, 24].map((h) => (
                    <button
                      key={h}
                      onClick={() => handleDurationChange(h)}
                      className={`px-2 py-0.5 rounded-lg text-[10px] font-mono transition-all duration-200 ease-out hover:scale-105 active:scale-95 cursor-pointer ${
                        durationHours === h
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold shadow-sm shadow-rose-500/20'
                          : 'bg-white/[0.04] text-slate-400 hover:text-white hover:bg-white/[0.08] hover:border-white/10'
                      }`}
                    >
                      {h}h
                    </button>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="py-3 text-center">
              <button
                onClick={() => onSimulateNodeOutage(node.id, durationHours)}
                className="w-full py-2 rounded-xl bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 text-xs font-semibold transition-all cursor-pointer flex items-center justify-center gap-2"
              >
                <Flame className="w-3.5 h-3.5 text-rose-400" />
                <span>Simulate Node Failure</span>
              </button>
            </div>
          )}
        </div>

        {/* Clear Utility Info: Architecture Connections */}
        <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/[0.06] space-y-3">
          <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400 block">
            Graph Topology & Utility
          </span>

          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="p-2.5 rounded-xl bg-white/[0.02] border border-white/5 space-y-0.5">
              <span className="text-[10px] text-slate-500 block">Upstream Callers</span>
              <span className="font-semibold text-slate-200 text-sm">
                {upstreamCallers.length} {upstreamCallers.length === 1 ? 'caller' : 'callers'}
              </span>
            </div>

            <div className="p-2.5 rounded-xl bg-white/[0.02] border border-white/5 space-y-0.5">
              <span className="text-[10px] text-slate-500 block">Dependencies</span>
              <span className="font-semibold text-slate-200 text-sm">
                {downstreamDependencies.length} {downstreamDependencies.length === 1 ? 'downstream' : 'downstream'}
              </span>
            </div>
          </div>

          <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
            <span>Evidence Provenance:</span>
            <span className="font-mono text-slate-200 capitalize bg-white/[0.04] px-2 py-0.5 rounded">
              {node.provenance || 'Declared'}
            </span>
          </div>
        </div>

        {/* Associated Security Findings (Streamlined & Clean) */}
        {associatedFindings.length > 0 && (
          <div className="space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                Security Findings ({associatedFindings.length})
              </span>
            </div>

            <div className="space-y-2">
              {associatedFindings.map((finding) => (
                <div
                  key={finding.id}
                  className="p-3 rounded-xl bg-white/[0.02] hover:bg-white/[0.05] border border-white/[0.08] space-y-2 transition-all"
                >
                  <div className="flex items-start justify-between gap-2">
                    <p className="font-medium text-slate-200 text-xs leading-snug">
                      {finding.title}
                    </p>
                    {finding.security_details?.cve_id && (
                      <span className="font-mono text-[10px] text-slate-400 shrink-0">
                        {finding.security_details.cve_id}
                      </span>
                    )}
                  </div>

                  <button
                    onClick={() => onExplainAI(finding)}
                    className="w-full flex items-center justify-center gap-1.5 py-1.5 px-3 rounded-lg bg-gradient-to-r from-indigo-600/30 to-purple-600/30 hover:from-indigo-600/50 hover:to-purple-600/50 border border-indigo-500/30 text-indigo-200 hover:text-white transition-all text-[11px] font-medium cursor-pointer"
                  >
                    <Sparkles className="w-3 h-3 text-purple-300" />
                    <span>Explain Risk with Gemini AI</span>
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Bottom Footer Actions */}
      <div className="p-4 border-t border-white/[0.06] bg-slate-950/60 flex items-center gap-2">
        {onClearSimulation && simulation && (
          <button
            onClick={onClearSimulation}
            className="flex-1 py-2 px-3 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] text-slate-300 hover:text-white border border-white/10 text-xs font-medium transition-all cursor-pointer text-center"
          >
            Clear Graph Highlight
          </button>
        )}
        <button
          onClick={onClose}
          className="flex-1 py-2 px-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-md transition-all cursor-pointer text-center"
        >
          Done
        </button>
      </div>
    </div>
  );
};
