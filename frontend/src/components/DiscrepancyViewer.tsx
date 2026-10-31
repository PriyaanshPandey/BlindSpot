import React from 'react';
import { AlertCircle, FileSearch, ArrowRight, CheckCircle2, ShieldX } from 'lucide-react';
import { Finding } from '../types';

interface DiscrepancyViewerProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
}

export const DiscrepancyViewer: React.FC<DiscrepancyViewerProps> = ({ findings, onSelectFinding }) => {
  const discrepancyFindings = findings.filter(f => f.type.includes('discrepancy'));

  if (discrepancyFindings.length === 0) {
    return (
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center gap-3 text-xs text-slate-400">
        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
        <span>No architectural discrepancies detected. Declared manifests match runtime traces.</span>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldX className="w-4 h-4 text-amber-400" />
          <h3 className="font-semibold text-white text-xs uppercase tracking-wider">
            Declared vs. Observed Discrepancies ({discrepancyFindings.length})
          </h3>
        </div>
        <span className="text-[10px] text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
          Runtime Conflict Detected
        </span>
      </div>

      <div className="grid grid-cols-1 gap-3">
        {discrepancyFindings.map(find => (
          <div
            key={find.id}
            onClick={() => onSelectFinding(find)}
            className="p-4 rounded-xl bg-slate-900 hover:bg-slate-850 border border-amber-500/30 hover:border-amber-500/60 cursor-pointer transition-all space-y-2 shadow-lg"
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-white text-sm">{find.title}</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300">
                {find.target_node_id}
              </span>
            </div>

            <p className="text-xs text-slate-300">{find.description}</p>

            <div className="flex items-center gap-4 text-[11px] text-slate-400 pt-1">
              <div className="flex items-center gap-1">
                <FileSearch className="w-3.5 h-3.5 text-blue-400" />
                <span>Evidence: {find.evidence_references?.join(', ')}</span>
              </div>
              <span className="text-slate-500">•</span>
              <span className="text-amber-400">High Risk (Undocumented Attack Surface)</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

