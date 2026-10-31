import React from 'react';

interface AnalysisLoadingOverlayProps {
  projectName?: string;
}

export const AnalysisLoadingOverlay: React.FC<AnalysisLoadingOverlayProps> = () => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#050205]/95 backdrop-blur-2xl text-white select-none overflow-hidden font-sans">
      {/* Background subtle radial glow */}
      <div className="absolute inset-0 pointer-events-none opacity-20">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_rgba(244,63,94,0.18)_0%,_transparent_60%)]" />
      </div>

      {/* Centered Minimalist Scanning Visual */}
      <div className="relative z-10 flex flex-col items-center text-center px-6">
        {/* Sleek Pulse Loader */}
        <div className="relative w-20 h-20 mb-6 flex items-center justify-center">
          <div className="absolute inset-0 rounded-full border border-rose-500/20 animate-ping opacity-75" />
          <div className="absolute inset-2 rounded-full border border-purple-500/30 animate-pulse" />
          <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-rose-600 to-purple-600 shadow-[0_0_24px_rgba(244,63,94,0.5)] flex items-center justify-center">
            <div className="w-3.5 h-3.5 rounded-full bg-white animate-pulse" />
          </div>
        </div>

        {/* Pure Single Title */}
        <h2 className="text-xl sm:text-2xl font-medium text-slate-100 tracking-tight flex items-center gap-1">
          <span>Scanning codebase</span>
          <span className="inline-flex">
            <span className="animate-[pulse_1.4s_infinite_200ms]">.</span>
            <span className="animate-[pulse_1.4s_infinite_400ms]">.</span>
            <span className="animate-[pulse_1.4s_infinite_600ms]">.</span>
          </span>
        </h2>
      </div>
    </div>
  );
};
