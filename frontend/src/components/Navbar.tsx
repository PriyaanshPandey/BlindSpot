import React from 'react';
import { Shield, Sparkles, Building2, Play, Lock, RefreshCw, Cpu } from 'lucide-react';

interface NavbarProps {
  mode: 'builder' | 'enterprise';
  setMode: (mode: 'builder' | 'enterprise') => void;
  onTriggerScan: () => void;
  isScanning: boolean;
  onOpenKnowledgeModal: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  mode,
  setMode,
  onTriggerScan,
  isScanning,
  onOpenKnowledgeModal
}) => {
  return (
    <header className="h-16 border-b border-slate-800 bg-[#0B0F19]/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Brand */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 via-indigo-600 to-purple-600 flex items-center justify-center shadow-lg shadow-blue-500/20">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
              Hidden Dependency X-Ray
            </span>
            <span className="text-[10px] uppercase font-bold tracking-widest px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
              HDX 1.0
            </span>
          </div>
          <p className="text-xs text-slate-400">Know what you depend on. Know what breaks. Know what it costs.</p>
        </div>
      </div>

      {/* Mode Switcher & Actions */}
      <div className="flex items-center gap-4">
        {/* Builder vs Enterprise Mode Toggle */}
        <div className="bg-slate-900/90 p-1 rounded-xl border border-slate-800 flex items-center shadow-inner">
          <button
            onClick={() => setMode('builder')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              mode === 'builder'
                ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Builder Mode</span>
          </button>
          <button
            onClick={() => setMode('enterprise')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              mode === 'enterprise'
                ? 'bg-gradient-to-r from-purple-600 to-indigo-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Building2 className="w-3.5 h-3.5" />
            <span>Enterprise Mode</span>
          </button>
        </div>

        {/* Trigger Scan Button */}
        <button
          onClick={onTriggerScan}
          disabled={isScanning}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 text-white px-4 py-2 rounded-xl text-xs font-semibold shadow-lg shadow-blue-600/20 transition-all active:scale-95"
        >
          {isScanning ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              <span>Scanning Nexus Commerce...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Run HDX Scan</span>
            </>
          )}
        </button>

        {/* Trust & Knowledge Plane Modal Trigger */}
        <button
          onClick={onOpenKnowledgeModal}
          className="flex items-center gap-2 bg-slate-800/80 hover:bg-slate-700 border border-slate-700/60 text-slate-200 px-3 py-2 rounded-xl text-xs font-medium transition-all"
          title="Inspect Signed Knowledge Bundles & Solana Devnet Status"
        >
          <Cpu className="w-3.5 h-3.5 text-purple-400" />
          <span>Trust & Proof</span>
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
        </button>
      </div>
    </header>
  );
};

