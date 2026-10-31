import React from 'react';
import { Flame, DollarSign, Clock, ShieldAlert, CheckCircle, ArrowRight } from 'lucide-react';
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
  const formattedExposure = new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: results.exposure_currency || 'USD',
    maximumFractionDigits: 0
  }).format(results.total_estimated_gross_exposure);

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
              <p className="text-xs text-slate-400">Target: <code className="text-rose-300 font-mono">{simulation.target_node_id}</code></p>
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
              className="w-full h-1.5 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-blue-500"
            />
          </div>

          <button
            onClick={onResetSimulation}
            className="text-xs text-slate-400 hover:text-white underline block"
          >
            Clear Simulation
          </button>
        </div>

        {/* Center: Exposure Metric Banner */}
        <div className="p-4 rounded-2xl bg-gradient-to-br from-rose-950/40 via-slate-950 to-orange-950/20 border border-rose-500/30 min-w-[300px]">
          <span className="text-xs text-rose-400 font-semibold uppercase tracking-wider flex items-center gap-1.5">
            <ShieldAlert className="w-4 h-4" /> Estimated Financial Exposure
          </span>
          <div className="text-3xl font-black text-white tracking-tight mt-1">
            {formattedExposure}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Across {results.impacted_journeys?.length || 0} business operations & {results.blast_radius_node_count} dependent components.
          </p>
        </div>

        {/* Right: Affected Journeys & Mitigations */}
        <div className="flex-1 space-y-3 min-w-[320px]">
          <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Cascading Journey Disruption
          </h4>
          <div className="space-y-2 max-h-36 overflow-y-auto pr-2">
            {results.impacted_journeys?.map((j) => (
              <div key={j.journey_id} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs">
                <div>
                  <span className="font-semibold text-white block">{j.name}</span>
                  <span className="text-[10px] text-slate-400">
                    {j.hourly_transactions.toLocaleString()} tx/hr @ ${j.average_transaction_value}/tx
                  </span>
                </div>
                <div className="text-right">
                  <span className="font-bold text-rose-400 block">
                    ${(j.financial_exposure).toLocaleString()}
                  </span>
                  <span className="text-[10px] text-slate-500">
                    {(j.disruption_fraction * 100).toFixed(0)}% Disruption
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

