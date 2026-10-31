import React from 'react';
import { ShieldCheck, Lock, ExternalLink } from 'lucide-react';

export const PrivacyBanner: React.FC = () => {
  return (
    <div className="bg-gradient-to-r from-blue-950/40 via-indigo-950/20 to-slate-900/60 border-y border-blue-900/30 px-6 py-2.5 flex items-center justify-between text-xs">
      <div className="flex items-center gap-3">
        <span className="flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          <ShieldCheck className="w-3.5 h-3.5" />
        </span>
        <span className="text-slate-300">
          <strong className="text-white font-semibold">Local-First Privacy Guarantee:</strong> Your proprietary source code, internal traces, and dependency graphs remain 100% within your local environment.
        </span>
      </div>

      <div className="flex items-center gap-4 text-slate-400">
        <span className="flex items-center gap-1.5 font-mono text-[11px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
          <Lock className="w-3 h-3" /> 0 Bytes Exfiltrated
        </span>
        <span className="text-slate-500">|</span>
        <span className="text-slate-400 text-[11px]">
          Knowledge Plane: <strong>DigitalOcean (Public Ingress Only)</strong>
        </span>
      </div>
    </div>
  );
};

