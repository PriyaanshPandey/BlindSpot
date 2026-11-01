import React from 'react';
import {
  Network,
  Radar,
  Flame,
  FileCheck2,
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
  ArrowLeft,
  KeyRound
} from 'lucide-react';

interface AppSidebarProps {
  activeTab: 'graph' | 'findings' | 'simulation' | 'passports' | 'third-party';
  setActiveTab: (tab: 'graph' | 'findings' | 'simulation' | 'passports' | 'third-party') => void;
  isCollapsed: boolean;
  setIsCollapsed: (collapsed: boolean) => void;
  graphNodeCount: number;
  findingsCount: number;
  hasActiveSimulation: boolean;
  mode?: 'builder' | 'enterprise';
  setMode?: (mode: 'builder' | 'enterprise') => void;
  onOpenKnowledgeModal: () => void;
  onGoToLanding: () => void;
}

export const AppSidebar: React.FC<AppSidebarProps> = ({
  activeTab,
  setActiveTab,
  isCollapsed,
  setIsCollapsed,
  graphNodeCount,
  findingsCount,
  hasActiveSimulation,
  mode,
  setMode,
  onOpenKnowledgeModal,
  onGoToLanding
}) => {
  const navItems = [
    {
      id: 'graph' as const,
      label: 'Dependency Graph',
      shortLabel: 'Graph',
      icon: Network,
      badge: graphNodeCount > 0 ? `${graphNodeCount}` : null,
      badgeColor: 'bg-rose-500/20 text-rose-300 border-rose-500/30'
    },
    {
      id: 'findings' as const,
      label: 'Live Radar',
      shortLabel: 'Radar',
      icon: Radar,
      badge: findingsCount > 0 ? `${findingsCount}` : 'CLEAR',
      badgeColor: findingsCount > 0 ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
    },
    {
      id: 'simulation' as const,
      label: 'Failure Simulator',
      shortLabel: 'Simulator',
      icon: Flame,
      badge: hasActiveSimulation ? 'ACTIVE' : null,
      badgeColor: 'bg-rose-600/30 text-rose-200 border-rose-500/40'
    },
    {
      id: 'third-party' as const,
      label: 'Third-Party Intelligence',
      shortLabel: '3rd-Party',
      icon: ShieldCheck,
      badge: 'PRO',
      badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
    },
    {
      id: 'passports' as const,
      label: 'Vendor Passports',
      shortLabel: 'Passports',
      icon: FileCheck2,
      badge: 'VERIFIED',
      badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/30'
    }
  ];

  return (
    <aside
      className={`relative z-30 h-full transition-all duration-300 ease-in-out flex flex-col justify-between bg-black/65 backdrop-blur-2xl border-r border-white/10 select-none ${
        isCollapsed ? 'w-16' : 'w-64'
      }`}
    >
      {/* Top Header & Brand */}
      <div>
        <div className="h-16 px-4 flex items-center justify-between border-b border-white/[0.08]">
          {!isCollapsed && (
            <div
              onClick={onGoToLanding}
              className="flex items-center gap-2.5 cursor-pointer group"
              title="Return to Landing"
            >
              <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-rose-600 via-purple-600 to-indigo-600 flex items-center justify-center shadow-[0_0_15px_rgba(244,63,94,0.4)] group-hover:scale-105 transition-transform">
                <ShieldCheck className="w-4 h-4 text-white" />
              </div>
              <div>
                <span className="font-extrabold text-sm tracking-tight text-white block">
                  BLINDSPOT
                </span>
                <span className="text-[10px] text-rose-400 font-semibold tracking-wider uppercase block -mt-1">
                  HDX ENGINE
                </span>
              </div>
            </div>
          )}

          {isCollapsed && (
            <div
              onClick={onGoToLanding}
              className="w-8 h-8 rounded-xl bg-gradient-to-tr from-rose-600 to-purple-600 flex items-center justify-center mx-auto cursor-pointer shadow-md"
              title="Return to Landing"
            >
              <ShieldCheck className="w-4 h-4 text-white" />
            </div>
          )}

          {/* Collapse Toggle */}
          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="w-7 h-7 rounded-lg bg-white/[0.04] hover:bg-white/10 border border-white/10 text-slate-400 hover:text-white flex items-center justify-center transition-colors"
            title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Feature Navigation List */}
        <nav className="p-2 space-y-1.5 mt-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center rounded-xl transition-all duration-200 group relative ${
                  isCollapsed ? 'justify-center p-3' : 'justify-between px-3.5 py-3'
                } ${
                  isActive
                    ? 'bg-rose-500/15 border border-rose-500/40 text-white shadow-[0_0_20px_rgba(244,63,94,0.2)]'
                    : 'text-slate-400 hover:text-white hover:bg-white/[0.05] border border-transparent'
                }`}
                title={isCollapsed ? item.label : undefined}
              >
                <div className="flex items-center gap-3">
                  <Icon
                    className={`w-4 h-4 transition-transform group-hover:scale-110 ${
                      isActive ? 'text-rose-400' : 'text-slate-400 group-hover:text-slate-200'
                    }`}
                  />
                  {!isCollapsed && (
                    <span className="text-xs font-semibold tracking-wide">{item.label}</span>
                  )}
                </div>

                {!isCollapsed && item.badge && (
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${item.badgeColor}`}
                  >
                    {item.badge}
                  </span>
                )}

                {/* Collapsed Active Indicator Pill */}
                {isCollapsed && isActive && (
                  <div className="absolute right-1 w-1 h-5 rounded-full bg-rose-500 shadow-[0_0_8px_#f43f5e]" />
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Controls */}
      <div className="p-3 border-t border-white/[0.08] space-y-2">
        {/* Cryptographic Trust Proof Modal Button */}
        <button
          onClick={onOpenKnowledgeModal}
          className={`w-full flex items-center rounded-xl bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30 text-purple-200 transition-all cursor-pointer ${
            isCollapsed ? 'justify-center p-3' : 'px-3 py-2.5 gap-2.5 text-xs font-semibold'
          }`}
          title="Cryptographic Ed25519 Trust Proof"
        >
          <KeyRound className="w-4 h-4 text-purple-400 shrink-0" />
          {!isCollapsed && <span>Trust Proof</span>}
        </button>

        {/* Return to Landing Button */}
        <button
          onClick={onGoToLanding}
          className={`w-full flex items-center rounded-xl text-slate-400 hover:text-white hover:bg-white/[0.05] transition-all cursor-pointer ${
            isCollapsed ? 'justify-center p-3' : 'px-3 py-2 gap-2 text-xs font-medium'
          }`}
          title="Return to Landing Page"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          {!isCollapsed && <span>Return to Home</span>}
        </button>
      </div>
    </aside>
  );
};

