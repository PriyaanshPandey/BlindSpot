import React from 'react';
import { Flame, Clock, ShieldAlert, AlertTriangle, Layers, Activity } from 'lucide-react';
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

  // Duration scales cumulative outage exposure (+0.8% per hour up to 20%)
  const durationWeight = Math.min(durationHours * 0.85, 20);
  // Node blast radius factor
  const blastWeight = Math.min((results.blast_radius_node_count || 1) * 5, 25);

  const calculatedImpactPct = Math.min(
    99,
    Math.max(
      28,
      Math.round(maxJourneyDisruption * 55 + blastWeight + durationWeight)
    )
  );

  const isCritical = calculatedImpactPct >= 80;
  const isHigh = calculatedImpactPct >= 60 && calculatedImpactPct < 80;

  return (
    <div className="bg-slate-900 border-t border-slate-800 p-5 shadow-2xl">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row gap-6 items-start justify-between">
        {/* Left: Summary & Duration Slider */}
        <div className="space-y-3 min-w-[280px]">
          <div className="flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-rose-500/20 text-rose-400 border border-rose-500/30">
              <Flame className="w-4 h-4 animate-bounce" />
            </span>
            <div>
              <h3 className="font-bold text-white text-sm">Failure Simulation Active</h3>
              <p className="text-xs text-slate-400">
                Target: <code className="text-rose-300 font-mono">{simulation.target_node_id}</code>
              </p>
            </div>
          </div>

          {/* Duration Slider */}
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-blue-400" /> Outage Duration:
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
            <div className="flex justify-between text-[10px] text-slate-500 font-mono">
              <span>1h Transient</span>
              <span>12h Outage</span>
              <span>24h Extended</span>
            </div>
          </div>

          <button
            onClick={onResetSimulation}
            className="text-xs text-slate-400 hover:text-white underline block cursor-pointer"
          >
            Clear Simulation
          </button>
        </div>

        {/* Center: System Severity Metric Banner (NO MONETARY ASPECT) */}
        <div className="p-5 rounded-2xl bg-gradient-to-br from-rose-950/50 via-slate-950 to-orange-950/30 border border-rose-500/40 min-w-[320px] shadow-xl backdrop-blur-md">
          <div className="flex items-center justify-between">
            <span className="text-xs text-rose-400 font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-rose-400" /> System Failure Severity
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

          <div className="text-4xl font-black text-white tracking-tight mt-2 flex items-baseline gap-2">
            <span>{calculatedImpactPct}%</span>
            <span className="text-xs font-semibold text-rose-300 uppercase tracking-normal">
              Cascading Impact
            </span>
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
              style={{ width: `${calculatedImpactPct}%` }}
            />
          </div>

          <p className="text-[11px] text-slate-400 mt-2.5">
            Impacting <strong className="text-white">{results.impacted_journeys?.length || 0} business flows</strong> across <strong className="text-white">{results.blast_radius_node_count} downstream architecture components</strong>.
          </p>
        </div>

        {/* Right: Cascading Journey Disruption % (NO DOLLAR VALUES) */}
        <div className="flex-1 space-y-3 min-w-[320px]">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-rose-400" /> Cascading Journey Disruption
            </h4>
            <span className="text-[10px] text-slate-500 font-mono">OPERATIONAL SEVERITY %</span>
          </div>

          <div className="space-y-2 max-h-36 overflow-y-auto pr-2">
            {results.impacted_journeys?.map((j) => {
              const disruptionPct = Math.round(j.disruption_fraction * 100);
              const journeyCritical = disruptionPct >= 80;

              return (
                <div
                  key={j.journey_id}
                  className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between text-xs hover:border-slate-700 transition-colors"
                >
                  <div>
                    <span className="font-semibold text-white block">{j.name}</span>
                    <span className="text-[10px] text-slate-400 flex items-center gap-1.5 mt-0.5">
                      <span
                        className={`w-1.5 h-1.5 rounded-full ${
                          journeyCritical ? 'bg-rose-400' : 'bg-amber-400'
                        }`}
                      />
                      {journeyCritical ? 'Tier 0 Core Operation' : 'Tier 1 Dependent Flow'}
                    </span>
                  </div>
                  <div className="text-right">
                    <span
                      className={`font-bold block ${
                        journeyCritical ? 'text-rose-400' : 'text-amber-400'
                      }`}
                    >
                      {disruptionPct}% Severed
                    </span>
                    <span className="text-[10px] text-slate-500 font-medium">
                      {disruptionPct >= 100
                        ? 'Complete Failure'
                        : disruptionPct >= 70
                        ? 'Severely Impaired'
                        : 'Partial Degradation'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
