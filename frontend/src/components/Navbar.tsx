import React, { useState } from 'react';
import { Shield, Sparkles, Building2, Play, Lock, RefreshCw, Cpu, FolderOpen, ChevronDown } from 'lucide-react';

interface NavbarProps {
  mode: 'builder' | 'enterprise';
  setMode: (mode: 'builder' | 'enterprise') => void;
  targetPath: string;
  setTargetPath: (path: string) => void;
  onTriggerScan: (customPath?: string) => void;
  isScanning: boolean;
  onOpenKnowledgeModal: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  mode,
  setMode,
  targetPath,
  setTargetPath,
  onTriggerScan,
  isScanning,
  onOpenKnowledgeModal
}) => {
  const [isFolderOpen, setIsFolderOpen] = useState(false);

  const presets = [
    { label: 'Nexus Commerce (Demo App)', path: './demo/nexus-commerce' },
    { label: 'CAREER PILOT (Desktop App)', path: 'C:/Users/Priyansh Pandey/OneDrive/Desktop/CAREER PILOT' },
    { label: 'SampleShop (Desktop Test Website)', path: 'C:/Users/Priyansh Pandey/OneDrive/Desktop/SampleShop' }
  ];

  return (
    <header className="h-16 border-b border-slate-800 bg-[#0B0F19]/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Brand */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 via-indigo-600 to-purple-600 flex items-center justify-center shadow-lg shadow-blue-500/20 shrink-0">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold text-base tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
              Hidden Dependency X-Ray
            </span>
            <span className="text-[10px] uppercase font-bold tracking-widest px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
              HDX 1.0
            </span>
          </div>
          <p className="text-[11px] text-slate-400 hidden sm:block">Know what you depend on. Know what breaks. Know what it costs.</p>
        </div>
      </div>

      {/* Target Folder Selector Dropdown / Input */}
      <div className="relative flex items-center gap-2">
        <div className="flex items-center bg-slate-900 border border-slate-700/80 rounded-xl px-2.5 py-1 text-xs shadow-inner">
          <FolderOpen className="w-3.5 h-3.5 text-blue-400 mr-2 shrink-0" />
          <input
            type="text"
            value={targetPath}
            onChange={(e) => setTargetPath(e.target.value)}
            placeholder="Enter local folder path..."
            className="bg-transparent text-white font-mono text-[11px] w-64 md:w-80 focus:outline-none"
          />
          <button
            onClick={() => setIsFolderOpen(!isFolderOpen)}
            className="p-1 text-slate-400 hover:text-white"
            title="Choose Preset Target"
          >
            <ChevronDown className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Preset Menu */}
        {isFolderOpen && (
          <div className="absolute top-12 left-0 w-80 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl p-2 z-50 space-y-1">
            <span className="text-[10px] uppercase font-bold text-slate-400 px-2 py-1 block">Quick Select Project:</span>
            {presets.map((preset) => (
              <button
                key={preset.path}
                onClick={() => {
                  setTargetPath(preset.path);
                  setIsFolderOpen(false);
                  onTriggerScan(preset.path);
                }}
                className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-800 text-xs text-slate-200 flex flex-col"
              >
                <span className="font-semibold text-white">{preset.label}</span>
                <span className="text-[10px] text-slate-400 font-mono truncate">{preset.path}</span>
              </button>
            ))}
          </div>
        )}

        {/* Trigger Scan Button */}
        <button
          onClick={() => onTriggerScan(targetPath)}
          disabled={isScanning}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 text-white px-3.5 py-2 rounded-xl text-xs font-semibold shadow-lg shadow-blue-600/20 transition-all active:scale-95 shrink-0"
        >
          {isScanning ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              <span>Scanning...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Scan Folder</span>
            </>
          )}
        </button>
      </div>

      {/* Mode Switcher & Trust Modal */}
      <div className="flex items-center gap-3">
        {/* Builder vs Enterprise Mode Toggle */}
        <div className="bg-slate-900/90 p-1 rounded-xl border border-slate-800 flex items-center shadow-inner">
          <button
            onClick={() => setMode('builder')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              mode === 'builder'
                ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Builder Mode</span>
          </button>
          <button
            onClick={() => setMode('enterprise')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              mode === 'enterprise'
                ? 'bg-gradient-to-r from-purple-600 to-indigo-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Building2 className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Enterprise Mode</span>
          </button>
        </div>

        {/* Trust & Knowledge Modal Trigger */}
        <button
          onClick={onOpenKnowledgeModal}
          className="flex items-center gap-1.5 bg-slate-800/80 hover:bg-slate-700 border border-slate-700/60 text-slate-200 px-3 py-2 rounded-xl text-xs font-medium transition-all"
          title="Inspect Signed Knowledge Bundles & Solana Devnet Status"
        >
          <Cpu className="w-3.5 h-3.5 text-purple-400" />
          <span className="hidden md:inline">Trust Proof</span>
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
        </button>
      </div>
    </header>
  );
};
