import React from 'react';
import {
  Network,
  Radar,
  Flame,
  FileCheck2,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
  Cpu
} from 'lucide-react';

interface AppSidebarProps {
  activeTab: 'graph' | 'findings' | 'passports' | 'third-party';
  setActiveTab: (tab: 'graph' | 'findings' | 'passports' | 'third-party') => void;
  isCollapsed: boolean;
  setIsCollapsed: (collapsed: boolean) => void;
  graphNodeCount?: number;
  findingsCount?: number;
  hasActiveSimulation?: boolean;
  mode?: 'builder' | 'enterprise';
  setMode?: (mode: 'builder' | 'enterprise') => void;
  onOpenKnowledgeModal?: () => void;
  onGoToLanding?: () => void;
}

export const AppSidebar: React.FC<AppSidebarProps> = ({
  activeTab,
  setActiveTab,
  isCollapsed,
  setIsCollapsed,
  onOpenKnowledgeModal,
  onGoToLanding
}) => {
  const navItems = [
    {
      id: 'graph' as const,
      label: 'Dependency Graph',
      shortLabel: 'Graph',
      icon: Network
    },
    {
      id: 'findings' as const,
      label: 'Live Radar',
      shortLabel: 'Radar',
      icon: Radar
    },
    {
      id: 'third-party' as const,
      label: 'Third-Party Intelligence',
      shortLabel: '3rd-Party',
      icon: ShieldCheck
    },
    {
      id: 'passports' as const,
      label: 'Vendor Passports',
      shortLabel: 'Passports',
      icon: FileCheck2
    }
  ];

  return (
    <aside
      className={`relative z-30 h-full transition-all duration-300 ease-in-out flex flex-col justify-between bg-slate-950/70 backdrop-blur-3xl border-r border-white/[0.06] shadow-2xl select-none ${
        isCollapsed ? 'w-16' : 'w-64'
      }`}
    >
      {/* Top Header & Brand */}
      <div>
        <div className="h-16 px-4 flex items-center justify-between border-b border-white/[0.06]">
          {!isCollapsed && (
            <div
              onClick={onGoToLanding}
              className="flex items-center gap-2.5 cursor-pointer group"
              title="Return to Landing"
            >
              <div className="h-10 flex items-center gap-2 group-hover:scale-105 transition-transform">
                <img src="/logo.png" alt="BlindSpot Logo" className="h-8 w-auto object-contain rounded-lg" />
                <span className="font-extrabold text-sm tracking-tight text-white block">
                  BLINDSPOT
                </span>
              </div>
            </div>
          )}

          {isCollapsed && (
            <div
              onClick={onGoToLanding}
              className="w-9 h-9 flex items-center justify-center mx-auto cursor-pointer"
              title="Return to Landing"
            >
              <img src="/logo.png" alt="BlindSpot Logo" className="w-7 h-7 object-contain rounded-lg" />
            </div>
          )}

          {/* Collapse Toggle */}
          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="w-7 h-7 rounded-lg bg-white/[0.03] hover:bg-white/10 border border-white/10 text-slate-400 hover:text-white flex items-center justify-center transition-colors cursor-pointer"
            title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Feature Navigation List */}
        <nav className="p-2 space-y-1 mt-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center rounded-xl transition-all duration-200 ease-out group relative cursor-pointer active:scale-[0.98] ${
                  isCollapsed ? 'justify-center p-3' : 'justify-start px-3.5 py-2.5'
                } ${
                  isActive
                    ? 'bg-white/[0.08] border border-white/15 text-white shadow-[0_4px_24px_rgba(99,102,241,0.2)] backdrop-blur-md font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] hover:translate-x-0.5 border border-transparent font-medium'
                }`}
                title={isCollapsed ? item.label : undefined}
              >
                <div className="flex items-center gap-3">
                  <Icon
                    className={`w-4 h-4 transition-all duration-200 group-hover:scale-110 ${
                      isActive ? 'text-indigo-400' : 'text-slate-400 group-hover:text-white'
                    }`}
                  />
                  {!isCollapsed && (
                    <span className="text-xs tracking-wide">{item.label}</span>
                  )}
                </div>

                {/* Collapsed Active Indicator Pill */}
                {isCollapsed && isActive && (
                  <div className="absolute right-1 w-1 h-5 rounded-full bg-white/80 shadow-[0_0_8px_rgba(255,255,255,0.4)]" />
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Controls */}
      <div className="p-3 border-t border-white/[0.06] space-y-2">
        {/* Cryptographic Trust Proof Modal Button */}
        <button
          onClick={onOpenKnowledgeModal}
          className={`w-full flex items-center rounded-xl bg-white/[0.02] hover:bg-white/[0.07] border border-white/[0.08] hover:border-white/20 text-slate-300 hover:text-white transition-all duration-200 ease-out hover:scale-[1.02] active:scale-[0.98] cursor-pointer shadow-sm hover:shadow-[0_0_16px_rgba(168,85,247,0.15)] ${
            isCollapsed ? 'justify-center p-3' : 'justify-start px-3 py-2.5 gap-2.5'
          }`}
          title="Verify Cryptographic Knowledge Manifest & Trust Anchors"
        >
          <Cpu className="w-4 h-4 text-purple-300 shrink-0" />
          {!isCollapsed && (
            <div className="flex items-center justify-between flex-1">
              <span className="text-xs font-medium">Trust Proof</span>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            </div>
          )}
        </button>
      </div>
    </aside>
  );
};
