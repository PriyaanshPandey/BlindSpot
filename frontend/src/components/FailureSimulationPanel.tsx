import React from 'react';
import { Flame, Clock, ShieldAlert, CheckCircle, Activity, Server, Box, Database, Globe } from 'lucide-react';
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

  // Calculate dynamic cascading system impact severity percentage
  const maxJourneyDisruption =
    results.impacted_journeys && results.impacted_journeys.length > 0
      ? Math.max(...results.impacted_journeys.map((j) => j.disruption_fraction))
      : 0.75;

  const durationWeight = Math.min(durationHours * 0.85, 20);
  const blastWeight = Math.min((results.blast_radius_node_count || 1) * 5, 25);
  const calculatedImpactPct = Math.min(
    99,
    Math.max(
      28,
      Math.round(maxJourneyDisruption * 55 + blastWeight + durationWeight)
    )
  );

  const impactPct = results.system_impact_percentage !== undefined
    ? results.system_impact_percentage
    : (results.impact_percentage !== undefined
      ? results.impact_percentage
      : calculatedImpactPct);

  const isCritical = impactPct >= 80;
  const isHigh = impactPct >= 60 && impactPct < 80;

  return (
    <div className="bg-slate-950/95 border-t border-rose-500/30 p-5 shadow-2xl backdrop-blur-xl">
      <div className="max-w-7xl mx-auto flex flex-col lg:flex-row gap-6 items-start justify-between">
        {/* Left: Summary & Duration Slider */}
        <div className="space-y-3 min-w-[260px]">
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

        {/* Center: System Failure Severity Metric Banner (ZERO MONETARY FIGURES) */}
        <div className="p-4 rounded-2xl bg-gradient-to-br from-rose-950/50 via-slate-900 to-black border border-rose-500/40 min-w-[320px]">
          <div className="flex items-center justify-between">
            <span className="text-xs text-rose-400 font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-rose-400" /> Architecture Impact
            </span>
            <span
              className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase border ${
                isCritical
                  ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                  : isHigh
                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                  : 'bg-blue-500/20 text-blue-300 border-blue-500/40'
              }`}
            >
              {isCritical ? 'Critical Severity' : isHigh ? 'High Severity' : 'Moderate Severity'}
            </span>
          </div>

          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-4xl font-black text-rose-400 tracking-tight">
              {impactPct}%
            </span>
            <span className="text-xs text-slate-400">Cascading System Disruption</span>
          </div>

          {/* Visual Progress Bar */}
          <div className="w-full bg-white/10 rounded-full h-2 mt-3 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                isCritical
                  ? 'bg-gradient-to-r from-amber-500 via-rose-500 to-red-600'
                  : isHigh
                  ? 'bg-gradient-to-r from-yellow-500 to-amber-600'
                  : 'bg-gradient-to-r from-blue-500 to-indigo-600'
              }`}
              style={{ width: `${Math.min(100, impactPct)}%` }}
            />
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

        {/* Right: Cascading Journey Disruption & Resilience Strategies (NO DOLLARS) */}
        <div className="flex-1 space-y-3 min-w-[320px]">
          {/* Cascading Journey Disruption % */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-rose-400" /> Cascading Journey Disruption
              </h4>
              <span className="text-[10px] text-slate-500 font-mono">SEVERITY %</span>
            </div>
            <div className="space-y-1.5 max-h-28 overflow-y-auto pr-1">
              {results.impacted_journeys?.map((j) => {
                const disruptionPct = Math.round(j.disruption_fraction * 100);
                const journeyCritical = disruptionPct >= 80;

                return (
                  <div
                    key={j.journey_id}
                    className="p-2 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between text-xs hover:border-slate-700 transition-colors"
                  >
                    <div>
                      <span className="font-semibold text-white block text-[11px]">{j.name}</span>
                      <span className="text-[10px] text-slate-400 flex items-center gap-1 mt-0.5">
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            journeyCritical ? 'bg-rose-400' : 'bg-amber-400'
                          }`}
                        />
                        {journeyCritical ? 'Core Flow' : 'Dependent Flow'}
                      </span>
                    </div>
                    <div className="text-right">
                      <span
                        className={`font-bold text-[11px] block ${
                          journeyCritical ? 'text-rose-400' : 'text-amber-400'
                        }`}
                      >
                        {disruptionPct}% Disrupted
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Recommended Resilience Strategies */}
          {results.mitigation_strategies && results.mitigation_strategies.length > 0 && (
            <div className="space-y-1.5 pt-2 border-t border-slate-800">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> Recommended Resilience Strategies
              </h4>
              <div className="space-y-1.5 max-h-28 overflow-y-auto pr-1">
                {results.mitigation_strategies.map((strat, idx) => (
                  <div key={idx} className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-xs space-y-0.5">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-white text-[11px] flex items-center gap-1">
                        {strat.title}
                      </span>
                      <span className="text-[9px] font-mono text-emerald-400 bg-emerald-500/10 px-1 py-0.5 rounded border border-emerald-500/20">
                        -{strat.estimated_risk_reduction_pct}% Risk
                      </span>
                    </div>
                    <p className="text-[10px] text-slate-400 leading-normal">
                      {strat.description}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
