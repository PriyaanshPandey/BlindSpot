import React from 'react';
import { X, AlertTriangle, ShieldCheck, Flame, Sparkles, ExternalLink, Activity, Info } from 'lucide-react';
import { GraphNode, Finding } from '../types';

interface NodeInspectorDrawerProps {
  node: GraphNode | null;
  onClose: () => void;
  onSimulateNodeOutage: (nodeId: string) => void;
  onExplainAI: (finding: Finding) => void;
  associatedFindings: Finding[];
}

export const NodeInspectorDrawer: React.FC<NodeInspectorDrawerProps> = ({
  node,
  onClose,
  onSimulateNodeOutage,
  onExplainAI,
  associatedFindings
}) => {
  if (!node) return null;

  return (
    <div className="absolute top-0 right-0 h-full w-96 bg-slate-900/95 border-l border-slate-800 backdrop-blur-md shadow-2xl z-30 flex flex-col transition-all">
      {/* Header */}
      <div className="p-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Info className="w-4 h-4 text-blue-400" />
          <h3 className="font-semibold text-white text-sm">Dependency Inspector</h3>
        </div>
        <button onClick={onClose} className="p-1 rounded-lg text-slate-400 hover:text-white">
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Body */}
      <div className="p-5 flex-1 overflow-y-auto space-y-5 text-xs">
        {/* Node Name & Badges */}
        <div>
          <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400 block mb-1">
            {node.type.replace('_', ' ')}
          </span>
          <h2 className="text-base font-bold text-white break-words">{node.label}</h2>
          <span className="font-mono text-[11px] text-slate-500">{node.id}</span>
        </div>

        {/* Provenance & Criticality */}
        <div className="grid grid-cols-2 gap-2">
          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase block">Evidence Source</span>
            <span className={`font-semibold capitalize ${
              node.provenance === 'observed' ? 'text-amber-400' : 'text-blue-400'
            }`}>
              {node.provenance}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase block">Criticality</span>
            <span className="font-semibold text-purple-400 capitalize">{node.criticality}</span>
          </div>
        </div>

        {/* Subsystem / Domain Cluster Description */}
        {node.metadata?.description && (
          <div className="p-3 rounded-xl bg-cyan-950/20 border border-cyan-800/30">
            <span className="text-[10px] text-cyan-400 uppercase font-semibold block mb-1">Architecture Subsystem</span>
            <p className="text-slate-300 text-xs leading-relaxed">{String(node.metadata.description)}</p>
          </div>
        )}

        {/* Bundled Packages List */}
        {node.metadata?.bundled_packages && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-white text-xs">Included Packages</span>
              <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-mono">
                {Object.keys(node.metadata.bundled_packages as any).length} packages
              </span>
            </div>
            <div className="max-h-48 overflow-y-auto space-y-1.5 p-2 rounded-xl bg-slate-950 border border-slate-800">
              {Object.entries(node.metadata.bundled_packages as Record<string, string>).map(([name, ver]) => (
                <div key={name} className="flex items-center justify-between text-[11px] py-1 border-b border-slate-900 last:border-0">
                  <span className="font-mono text-slate-200">{name}</span>
                  <span className="font-mono text-slate-400 text-[10px] bg-slate-900 px-1.5 py-0.5 rounded">{ver}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Associated Findings */}
        {associatedFindings.length > 0 && (
          <div className="space-y-3">
            <h4 className="font-semibold text-white text-xs flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              <span>Associated Security Findings ({associatedFindings.length})</span>
            </h4>

            {associatedFindings.map(find => (
              <div key={find.id} className="p-3 rounded-xl bg-slate-950 border border-amber-500/20 space-y-2">
                <div className="flex items-center justify-between">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    find.severity === 'critical' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                  }`}>
                    {find.severity}
                  </span>
                  {find.security_details?.cve_id && (
                    <span className="font-mono text-[10px] text-slate-400">
                      {find.security_details.cve_id}
                    </span>
                  )}
                </div>

                <p className="font-medium text-slate-200 text-xs">{find.title}</p>
                <p className="text-slate-400 text-[11px]">{find.description}</p>

                {/* AI Explain Button */}
                <button
                  onClick={() => onExplainAI(find)}
                  className="w-full flex items-center justify-center gap-1.5 py-1.5 px-3 rounded-lg bg-gradient-to-r from-blue-600/30 to-purple-600/30 border border-blue-500/30 hover:border-blue-400 text-blue-300 hover:text-white transition-all text-[11px] font-medium"
                >
                  <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                  <span>Explain Risk with Gemini AI</span>
                </button>
              </div>
            ))}
          </div>
        )}

        {/* Action Button: Simulate Outage */}
        <div className="pt-2">
          <button
            onClick={() => onSimulateNodeOutage(node.id)}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl bg-gradient-to-r from-rose-600 to-orange-600 hover:from-rose-500 hover:to-orange-500 text-white font-semibold text-xs shadow-lg shadow-rose-600/20 transition-all active:scale-95"
          >
            <Flame className="w-4 h-4" />
            <span>Simulate Node Failure</span>
          </button>
          <p className="text-[10px] text-slate-500 text-center mt-2">
            Computes upstream blast radius and cascading system failure impact percentage.
          </p>
        </div>
      </div>
    </div>
  );
};

