import React, { useState, useEffect } from 'react';
import { Shield, Sparkles, CheckCircle2, Cpu, Network, Search, Lock } from 'lucide-react';

interface AnalysisLoadingOverlayProps {
  projectName: string;
  onComplete?: () => void;
}

const PHASES = [
  { step: '01', title: 'Parsing Codebase Manifests', desc: 'Discovered direct & transitive package manifests...' },
  { step: '02', title: 'Extracting Network Endpoints', desc: 'Analyzing API calls, webhooks, and environment credentials...' },
  { step: '03', title: 'Querying Google OSV Database', desc: 'Matching live CVEs & GHSA security advisories...' },
  { step: '04', title: 'Synthesizing Dependency Graph', desc: 'Calculating blast radius & cascading failure paths...' }
];

export const AnalysisLoadingOverlay: React.FC<AnalysisLoadingOverlayProps> = ({
  projectName
}) => {
  const [phaseIndex, setPhaseIndex] = useState(0);
  const [progress, setProgress] = useState(15);

  useEffect(() => {
    const timer1 = setTimeout(() => { setPhaseIndex(1); setProgress(42); }, 650);
    const timer2 = setTimeout(() => { setPhaseIndex(2); setProgress(74); }, 1350);
    const timer3 = setTimeout(() => { setPhaseIndex(3); setProgress(96); }, 2050);

    return () => {
      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);
    };
  }, []);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#050205]/95 backdrop-blur-2xl text-white select-none overflow-hidden font-sans">
      {/* Background Animated Radar Grid */}
      <div className="absolute inset-0 pointer-events-none opacity-20">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_rgba(244,63,94,0.25)_0%,_transparent_65%)]" />
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#ffffff08_1px,transparent_1px),linear-gradient(to_bottom,#ffffff08_1px,transparent_1px)] bg-[size:3rem_3rem]" />
      </div>

      {/* Center Holographic Scanning Card */}
      <div className="relative z-10 max-w-lg w-full mx-4 p-8 sm:p-10 rounded-3xl bg-black/80 border border-white/10 shadow-[0_0_80px_rgba(244,63,94,0.25)] flex flex-col items-center text-center">
        {/* Pulsing Concentric Scan Rings */}
        <div className="relative w-28 h-28 mb-8 flex items-center justify-center">
          <div className="absolute inset-0 rounded-full border-2 border-rose-500/20 animate-ping opacity-60" />
          <div className="absolute inset-2 rounded-full border border-purple-500/40 animate-pulse" />
          <div className="absolute inset-4 rounded-full border border-rose-400/30" />
          
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-rose-600 via-purple-600 to-indigo-600 flex items-center justify-center shadow-[0_0_30px_rgba(244,63,94,0.6)]">
            <Network className="w-8 h-8 text-white animate-spin-slow" />
          </div>

          {/* Orbiting Scanning Dot */}
          <div className="absolute inset-0 animate-spin">
            <div className="w-3 h-3 rounded-full bg-rose-400 shadow-[0_0_12px_#f43f5e] -top-1.5 left-1/2 -translate-x-1/2" />
          </div>
        </div>

        {/* Project Name Header */}
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.05] border border-white/10 text-xs font-semibold text-rose-300 uppercase tracking-wider mb-2">
          <Cpu className="w-3.5 h-3.5" />
          <span>Analyzing {projectName}</span>
        </div>

        <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight mb-2">
          X-Raying Dependencies
        </h2>
        <p className="text-sm text-slate-400 mb-8 max-w-xs">
          Discovering undocumented connections and querying live vulnerability databases...
        </p>

        {/* Dynamic Progress Bar */}
        <div className="w-full bg-white/[0.06] rounded-full h-2 mb-6 overflow-hidden p-0.5 border border-white/10">
          <div
            className="h-full rounded-full bg-gradient-to-r from-rose-500 via-purple-500 to-indigo-400 transition-all duration-500 ease-out shadow-[0_0_12px_rgba(244,63,94,0.8)]"
            style={{ width: `${progress}%` }}
          />
        </div>

        {/* Progressive Phases Checklist */}
        <div className="w-full space-y-2.5 text-left">
          {PHASES.map((p, idx) => {
            const isDone = idx < phaseIndex;
            const isCurrent = idx === phaseIndex;
            return (
              <div
                key={p.step}
                className={`flex items-center justify-between p-2.5 rounded-xl transition-all duration-300 ${
                  isCurrent
                    ? 'bg-rose-500/10 border border-rose-500/30 text-white'
                    : isDone
                    ? 'bg-white/[0.02] border border-transparent text-slate-400'
                    : 'opacity-40 text-slate-600'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className="w-5 h-5 rounded-full flex items-center justify-center shrink-0">
                    {isDone ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : isCurrent ? (
                      <div className="w-3.5 h-3.5 border-2 border-rose-400 border-t-transparent rounded-full animate-spin" />
                    ) : (
                      <span className="text-[10px] text-slate-500 font-bold">{p.step}</span>
                    )}
                  </div>
                  <div>
                    <p className="text-xs font-semibold">{p.title}</p>
                    {isCurrent && <p className="text-[11px] text-rose-300/80">{p.desc}</p>}
                  </div>
                </div>
                {isDone && <span className="text-[10px] uppercase font-bold text-emerald-400">Done</span>}
              </div>
            );
          })}
        </div>

        {/* Privacy Note */}
        <div className="mt-8 flex items-center gap-2 text-[11px] text-slate-500">
          <Lock className="w-3.5 h-3.5 text-slate-400" />
          <span>Local processing: zero proprietary source code leaves this device</span>
        </div>
      </div>
    </div>
  );
};

