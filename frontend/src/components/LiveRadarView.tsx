import React, { useState, useMemo } from 'react';
import {
  Radar,
  Sparkles,
  Search,
  ArrowUpRight,
  ShieldCheck,
  Package,
  Cloud,
  X,
  Filter
} from 'lucide-react';
import { Finding, GraphData } from '../types';

interface LiveRadarViewProps {
  findings: Finding[];
  graphData: GraphData | null;
  onTraceInGraph: (nodeId: string) => void;
  onExplainAI: (finding: Finding) => void;
}

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';
type CategoryFilter = 'all' | 'packages' | 'third-party';

const normalizeSeverity = (sev: string): 'critical' | 'high' | 'medium' | 'low' => {
  const s = sev?.toLowerCase() || '';
  if (s.includes('crit')) return 'critical';
  if (s.includes('high')) return 'high';
  if (s.includes('med') || s.includes('mod')) return 'medium';
  return 'low';
};

export const LiveRadarView: React.FC<LiveRadarViewProps> = ({
  findings,
  onTraceInGraph,
  onExplainAI
}) => {
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Counts by severity
  const counts = useMemo(() => {
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let packages = 0;
    let thirdParty = 0;

    findings.forEach((f) => {
      const norm = normalizeSeverity(f.severity);
      if (norm === 'critical') critical++;
      else if (norm === 'high') high++;
      else if (norm === 'medium') medium++;
      else low++;

      const isPkg = f.target_node_id?.startsWith('pkg:') || f.type === 'vulnerability';
      if (isPkg) packages++;
      else thirdParty++;
    });

    return {
      total: findings.length,
      critical,
      high,
      medium,
      low,
      packages,
      thirdParty
    };
  }, [findings]);

  // Filtered findings
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      // Severity filter
      if (severityFilter !== 'all') {
        const norm = normalizeSeverity(f.severity);
        if (norm !== severityFilter) return false;
      }

      // Category filter
      if (categoryFilter === 'packages') {
        const isPkg = f.target_node_id?.startsWith('pkg:') || f.type === 'vulnerability';
        if (!isPkg) return false;
      } else if (categoryFilter === 'third-party') {
        const isPkg = f.target_node_id?.startsWith('pkg:') || f.type === 'vulnerability';
        if (isPkg) return false;
      }

      // Search query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesTitle = f.title?.toLowerCase().includes(q);
        const matchesDesc = f.description?.toLowerCase().includes(q);
        const matchesTarget = f.target_node_id?.toLowerCase().includes(q);
        if (!matchesTitle && !matchesDesc && !matchesTarget) return false;
      }

      return true;
    });
  }, [findings, severityFilter, categoryFilter, searchQuery]);

  return (
    <div className="p-6 sm:p-8 max-w-6xl mx-auto space-y-5 overflow-y-auto h-full">
      {/* Header Row */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2.5">
            <Radar className="w-5 h-5 text-rose-500 animate-pulse" />
            <span>Live Radar</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time security alerts across dependencies, cloud vendors, and third-party APIs.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs bg-rose-500/10 text-rose-300 border border-rose-500/20 px-3 py-1 rounded-xl font-semibold flex items-center gap-1.5 shadow-sm">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
            {filteredFindings.length} of {findings.length} Alerts
          </span>
        </div>
      </div>

      {/* Top Bar: Severity Pills, Category Focus & Search */}
      <div className="p-3 rounded-2xl bg-[#0f172a]/80 border border-white/10 shadow-xl backdrop-blur-xl flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3 select-none">
        {/* Severity Filter Pills */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {/* All */}
          <button
            onClick={() => setSeverityFilter('all')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
              severityFilter === 'all'
                ? 'bg-white/15 text-white border border-white/25 shadow-sm'
                : 'bg-white/[0.03] hover:bg-white/[0.08] text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            <span>All</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-white/10 text-slate-300">
              {counts.total}
            </span>
          </button>

          {/* Critical */}
          <button
            onClick={() => setSeverityFilter('critical')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
              severityFilter === 'critical'
                ? 'bg-rose-500/25 text-rose-200 border border-rose-500/50 shadow-sm'
                : 'bg-white/[0.03] hover:bg-rose-500/10 text-slate-400 hover:text-rose-300 border border-transparent'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-rose-500 shadow-[0_0_6px_#f43f5e]" />
            <span>Critical</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-rose-500/20 text-rose-300">
              {counts.critical}
            </span>
          </button>

          {/* High */}
          {counts.high > 0 && (
            <button
              onClick={() => setSeverityFilter('high')}
              className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
                severityFilter === 'high'
                  ? 'bg-orange-500/25 text-orange-200 border border-orange-500/50 shadow-sm'
                  : 'bg-white/[0.03] hover:bg-orange-500/10 text-slate-400 hover:text-orange-300 border border-transparent'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-orange-500 shadow-[0_0_6px_#f97316]" />
              <span>High</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-orange-500/20 text-orange-300">
                {counts.high}
              </span>
            </button>
          )}

          {/* Medium / Moderate */}
          <button
            onClick={() => setSeverityFilter('medium')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
              severityFilter === 'medium'
                ? 'bg-amber-500/25 text-amber-200 border border-amber-500/50 shadow-sm'
                : 'bg-white/[0.03] hover:bg-amber-500/10 text-slate-400 hover:text-amber-300 border border-transparent'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-amber-400 shadow-[0_0_6px_#fbbf24]" />
            <span>Medium</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-amber-500/20 text-amber-300">
              {counts.medium}
            </span>
          </button>

          {/* Low */}
          <button
            onClick={() => setSeverityFilter('low')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
              severityFilter === 'low'
                ? 'bg-sky-500/25 text-sky-200 border border-sky-500/50 shadow-sm'
                : 'bg-white/[0.03] hover:bg-sky-500/10 text-slate-400 hover:text-sky-300 border border-transparent'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-sky-400 shadow-[0_0_6px_#38bdf8]" />
            <span>Low</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-sky-500/20 text-sky-300">
              {counts.low}
            </span>
          </button>
        </div>

        {/* Center/Right: Category Focus Tabs & Search */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Category Toggle Tabs */}
          <div className="flex items-center p-1 rounded-xl bg-slate-950/60 border border-white/10">
            <button
              onClick={() => setCategoryFilter('all')}
              className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                categoryFilter === 'all'
                  ? 'bg-white/15 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All Sources
            </button>
            <button
              onClick={() => setCategoryFilter('packages')}
              className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer flex items-center gap-1 ${
                categoryFilter === 'packages'
                  ? 'bg-white/15 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Package className="w-3 h-3 text-cyan-400" />
              <span>Packages ({counts.packages})</span>
            </button>
            <button
              onClick={() => setCategoryFilter('third-party')}
              className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer flex items-center gap-1 ${
                categoryFilter === 'third-party'
                  ? 'bg-white/15 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Cloud className="w-3 h-3 text-purple-400" />
              <span>3rd-Party ({counts.thirdParty})</span>
            </button>
          </div>

          {/* Quick Search Input */}
          <div className="relative flex items-center min-w-[170px]">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search alerts..."
              className="w-full bg-slate-950/80 border border-white/10 rounded-xl pl-8 pr-7 py-1 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500/60 transition-colors"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2 text-slate-400 hover:text-white"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Findings List */}
      {filteredFindings.length === 0 ? (
        <div className="p-12 rounded-3xl bg-[#0f172a]/70 border border-white/10 text-center space-y-3">
          <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
          <h3 className="font-bold text-white text-base">No Matching Vulnerabilities</h3>
          <p className="text-xs text-slate-400 max-w-sm mx-auto">
            {findings.length === 0
              ? 'All scanned dependencies and endpoints are currently healthy.'
              : 'No alerts match your current filter criteria.'}
          </p>
          {(severityFilter !== 'all' || categoryFilter !== 'all' || searchQuery) && (
            <button
              onClick={() => {
                setSeverityFilter('all');
                setCategoryFilter('all');
                setSearchQuery('');
              }}
              className="px-3.5 py-1.5 rounded-xl bg-white/10 hover:bg-white/15 text-white text-xs font-semibold cursor-pointer transition-colors"
            >
              Clear Filters
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {filteredFindings.map((finding) => {
            const normSeverity = normalizeSeverity(finding.severity);

            // Severity visual indicators
            const severityStyles = {
              critical: {
                borderAccent: 'border-l-4 border-l-rose-500',
                dotColor: 'bg-rose-500 shadow-[0_0_8px_#f43f5e]',
                cardHover: 'hover:border-rose-500/30'
              },
              high: {
                borderAccent: 'border-l-4 border-l-orange-500',
                dotColor: 'bg-orange-500 shadow-[0_0_8px_#f97316]',
                cardHover: 'hover:border-orange-500/30'
              },
              medium: {
                borderAccent: 'border-l-4 border-l-amber-500',
                dotColor: 'bg-amber-400 shadow-[0_0_8px_#fbbf24]',
                cardHover: 'hover:border-amber-500/30'
              },
              low: {
                borderAccent: 'border-l-4 border-l-sky-500',
                dotColor: 'bg-sky-400 shadow-[0_0_8px_#38bdf8]',
                cardHover: 'hover:border-sky-500/30'
              }
            }[normSeverity];

            return (
              <div
                key={finding.id}
                className={`p-4 sm:p-5 rounded-2xl bg-[#111928] hover:bg-[#152033] border border-white/[0.08] ${severityStyles.borderAccent} ${severityStyles.cardHover} transition-all duration-200 space-y-3 shadow-lg hover:shadow-xl backdrop-blur-md`}
              >
                {/* Header: Glowing indicator dot + Clean Title (NO high/low badge, NO right-side pkg tag) */}
                <div className="flex items-center gap-2.5">
                  <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${severityStyles.dotColor}`} />
                  <h4 className="font-semibold text-white text-sm sm:text-base tracking-tight leading-snug">
                    {finding.title}
                  </h4>
                </div>

                {/* Description: Clean, readable text */}
                <p className="text-xs text-slate-300 leading-relaxed pl-5">
                  {finding.description}
                </p>

                {/* Action Buttons: Trace in Graph & Explain with Gemini AI (NO right-side evidence tag) */}
                <div className="pt-2 pl-5 flex items-center gap-2.5 border-t border-white/[0.05]">
                  <button
                    onClick={() => onTraceInGraph(finding.target_node_id)}
                    className="flex items-center gap-1.5 py-1.5 px-3 rounded-xl bg-white/[0.05] hover:bg-white/12 border border-white/10 text-slate-300 hover:text-white font-medium text-xs transition-all cursor-pointer"
                  >
                    <Radar className="w-3.5 h-3.5 text-rose-400" />
                    <span>Trace in Graph</span>
                  </button>

                  <button
                    onClick={() => onExplainAI(finding)}
                    className="flex items-center gap-1.5 py-1.5 px-3.5 rounded-xl bg-gradient-to-r from-indigo-600 via-indigo-500 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-medium text-xs shadow-md shadow-indigo-600/20 transition-all cursor-pointer"
                  >
                    <Sparkles className="w-3.5 h-3.5 text-amber-200" />
                    <span>Explain with Gemini AI</span>
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

