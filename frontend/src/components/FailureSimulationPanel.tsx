import React from 'react';
import { Flame, Clock, ShieldAlert, CheckCircle, Activity, Layers, Server, Box, Database, Globe } from 'lucide-react';
import { SimulationResult } from '../types';

interface FailureSimulationPanelProps {
  simulation: SimulationResult | null;
  onDurationChange: (hours: number) => void;
  durationHours: number;
  onResetSimulation: () => void;
}

export const FailureSimulationPanel: React.FC<FailureSimulationPanelProps> = ({
  simulation,
  onDurationChange,
  durationHours,
  onResetSimulation
}) => {
  if (!simulation) return null;

  const results = simulation.impact_results;
  const impactPct = results.impact_percentage !== undefined 
    ? results.impact_percentage 
    : (results.blast_radius_node_count && results.total_system_nodes 
        ? Math.round((results.blast_radius_node_count / results.total_system_nodes) * 100) 
        : Math.min(100, results.blast_radius_node_count * 12));

  return (
    <div className="bg-slate-950/95 border-t border-rose-500/30 p-5 shadow-2xl backdrop-blur-xl">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row gap-6 items-start justify-between">
        {/* Left: Summary & Duration Slider */}
        <div className="space-y-3 min-w-[280px]">
          <div className="flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-rose-500/20 text-rose-400 border border-rose-500/30">
              <Flame className="w-4 h-4 animate-bounce" />
            </span>
            <div>
              <h3 className="font-bold text-white text-sm">Failure Simulation Active</h3>
              <p className="text-xs text-slate-400">Target: <code className="text-rose-300 font-mono">{simulation.target_node_id}</code></p>
            </div>
          </div>

          {/* Outage Duration Slider */}
          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-blue-400" /> Simulated Outage Window:
              </span>
              <span className="font-bold text-white">{durationHours} Hours</span>
            </div>
            <input
              type="range"
              min="1"
              max="24"
              step="1"
              value={durationHours}
              onChange={(e) => onDurationChange(Number(e.target.value))}
              className="w-full h-1.5 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-rose-500"
            />
          </div>

          <button
            onClick={onResetSimulation}
            className="text-xs text-slate-400 hover:text-white underline block cursor-pointer"
          >
            Clear Simulation & Restore Graph
          </button>
        </div>

        {/* Center: Architecture Impact Percentage */}
        <div className="p-4 rounded-2xl bg-gradient-to-br from-rose-950/50 via-slate-900 to-black border border-rose-500/40 min-w-[320px]">
          <span className="text-xs text-rose-400 font-semibold uppercase tracking-wider flex items-center gap-1.5">
            <ShieldAlert className="w-4 h-4 text-rose-400" /> Architecture Impact
          </span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-4xl font-black text-rose-400 tracking-tight">
              {impactPct}%
            </span>
            <span className="text-xs text-slate-400">of system compromised</span>
          </div>
          <p className="text-[12px] text-slate-300 mt-2 font-medium">
            {results.blast_radius_node_count} component{results.blast_radius_node_count !== 1 ? 's' : ''} disabled across cascading dependency paths.
          </p>

          {/* Breakdown Pills */}
          <div className="grid grid-cols-2 gap-2 mt-3 pt-3 border-t border-white/10 text-[11px]">
            <div className="flex items-center gap-1.5 text-slate-300">
              <Server className="w-3 h-3 text-purple-400" />
              <span>Services: <strong className="text-white">{results.impacted_services_count ?? 1}</strong></span>
            </div>
            <div className="flex items-center gap-1.5 text-slate-300">
              <Box className="w-3 h-3 text-cyan-400" />
              <span>Packages: <strong className="text-white">{results.impacted_packages_count ?? 0}</strong></span>
            </div>
            <div className="flex items-center gap-1.5 text-slate-300">
              <Database className="w-3 h-3 text-emerald-400" />
              <span>Databases: <strong className="text-white">{results.impacted_infra_count ?? 0}</strong></span>
            </div>
            <div className="flex items-center gap-1.5 text-slate-300">
              <Globe className="w-3 h-3 text-rose-400" />
              <span>Vendors/APIs: <strong className="text-white">{results.impacted_vendor_count ?? 1}</strong></span>
            </div>
          </div>
        </div>

        {/* Right: Blast Radius & Remediation */}
        <div className="flex-1 space-y-3 min-w-[320px]">
          <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-amber-400" />
            Recommended Resilience Strategies
          </h4>
          <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
            {results.mitigation_strategies?.map((strat, idx) => (
              <div key={idx} className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white flex items-center gap-1.5">
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                    {strat.title}
                  </span>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
                    -{strat.estimated_risk_reduction_pct}% Risk
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  {strat.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
