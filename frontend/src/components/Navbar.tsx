import React, { useState } from 'react';
import { Shield, Play, Lock, RefreshCw, Cpu, FolderOpen, ChevronDown } from 'lucide-react';

interface NavbarProps {
  mode?: 'builder' | 'enterprise';
  setMode?: (mode: 'builder' | 'enterprise') => void;
  targetPath: string;
  setTargetPath: (path: string) => void;
  onTriggerScan: (customPath?: string) => void;
  isScanning: boolean;
  onOpenKnowledgeModal: () => void;
  onGoToLanding?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  mode,
  setMode,
  targetPath,
  setTargetPath,
  onTriggerScan,
  isScanning,
  onOpenKnowledgeModal,
  onGoToLanding
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
      <div 
        onClick={onGoToLanding}
        className="flex items-center gap-3 cursor-pointer group hover:opacity-90 transition-opacity"
        title="Return to Landing Page"
      >
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-violet-600 via-purple-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-purple-500/20 shrink-0 group-hover:scale-105 transition-transform">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold text-base tracking-tight bg-gradient-to-r from-white via-violet-200 to-purple-300 bg-clip-text text-transparent">
              BlindSpot
            </span>
            <span className="text-[10px] uppercase font-bold tracking-widest px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20">
              HDX
            </span>
            {onGoToLanding && (
              <span className="text-[10px] text-slate-400 border border-slate-700/60 rounded px-1.5 py-0.5 hover:bg-slate-800">
                ← Landing
              </span>
            )}
          </div>
          <p className="text-[11px] text-slate-400 hidden sm:block">You protect your code, we protect your blindspot.</p>
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

      {/* Trust & Knowledge Modal Trigger */}
      <div className="flex items-center gap-3">
        <button
          onClick={onOpenKnowledgeModal}
          className="flex items-center gap-1.5 bg-slate-800/80 hover:bg-slate-700 border border-slate-700/60 text-slate-200 px-3 py-2 rounded-xl text-xs font-medium transition-all"
          title="Inspect Signed Knowledge Bundles & Cryptographic Trust Proof"
        >
          <Cpu className="w-3.5 h-3.5 text-purple-400" />
          <span className="hidden md:inline">Trust Proof</span>
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
        </button>
      </div>
    </header>
  );
};
