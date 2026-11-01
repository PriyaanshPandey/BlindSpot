import React, { useState, useEffect } from 'react';
import {
  X,
  Sparkles,
  Shield,
  CheckSquare,
  Square,
  RefreshCw,
  Key,
  AlertTriangle,
  WifiOff,
  Clock,
  ShieldAlert,
  HelpCircle,
  RotateCcw
} from 'lucide-react';
import { Finding, AIExplanation, AIStatusResponse } from '../types';
import { previewAIPayload, explainFindingAI, getAIStatus } from '../api/client';

interface AIExplainModalProps {
  finding: Finding | null;
  mode?: string;
  isOpen: boolean;
  onClose: () => void;
}

export const AIExplainModal: React.FC<AIExplainModalProps> = ({
  finding,
  mode = 'builder',
  isOpen,
  onClose
}) => {
  const [sanitizedPreview, setSanitizedPreview] = useState<any>(null);
  const [explanation, setExplanation] = useState<AIExplanation | null>(null);
  const [hasApproved, setHasApproved] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [aiStatus, setAiStatus] = useState<AIStatusResponse | null>(null);
  const [apiKey, setApiKey] = useState<string>(() => localStorage.getItem('blindspot_gemini_key') || '');

  const effectiveAudience = mode === 'enterprise' ? 'enterprise' : 'builder';

  useEffect(() => {
    if (finding && isOpen) {
      setExplanation(null);
      setError(null);
      setHasApproved(false);

      // Check backend AI readiness status
      getAIStatus()
        .then((status) => setAiStatus(status))
        .catch(() => {
          setAiStatus({
            status: 'AI_UNAVAILABLE_OFFLINE',
            configured: false,
            model: 'gemini-3.6-flash',
            message: 'Backend AI status check failed'
          });
        });

      // Load pre-sanitized context
      previewAIPayload(finding, effectiveAudience)
        .then((data) => {
          setSanitizedPreview(data.payload_to_send);
        })
        .catch(() => {
          setError('Failed to sanitize payload preview.');
        });
    }
  }, [finding, isOpen, effectiveAudience]);

  const handleApiKeyChange = (val: string) => {
    setApiKey(val);
    localStorage.setItem('blindspot_gemini_key', val.trim());
  };

  const handleExecuteExplain = async () => {
    if (!finding || !hasApproved) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await explainFindingAI(
        finding,
        effectiveAudience,
        true,
        apiKey.trim() || undefined
      );
      setExplanation(res);
    } catch (err: any) {
      setError(err.message || 'AI request failed');
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen || !finding) return null;

  // Visual status pill helper
  const renderStatusBadge = (status?: string) => {
    switch (status) {
      case 'AI_READY':
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            AI Ready
          </span>
        );
      case 'AI_NOT_CONFIGURED':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-amber-500/10 text-amber-300 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            Not Configured (Using Local Rules)
          </span>
        );
      case 'AI_AUTH_FAILED':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-rose-500/15 text-rose-300 border border-rose-500/30">
            <ShieldAlert className="w-3 h-3 text-rose-400" />
            Auth Failed (Invalid Key)
          </span>
        );
      case 'AI_QUOTA_EXCEEDED':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-purple-500/15 text-purple-300 border border-purple-500/30">
            <Clock className="w-3 h-3 text-purple-400" />
            Rate Limit / Quota
          </span>
        );
      case 'AI_UNAVAILABLE_OFFLINE':
        return (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-slate-800 text-slate-300 border border-slate-700">
            <WifiOff className="w-3 h-3 text-slate-400" />
            Offline / Unreachable
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-slate-800 text-slate-400 border border-slate-700">
            {status || 'Local Analysis'}
          </span>
        );
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0B1120] border border-slate-800 w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800/80 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-rose-500 to-purple-600 flex items-center justify-center text-white shadow-[0_0_15px_rgba(244,63,94,0.4)]">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-semibold text-white text-sm">
                  Gemini AI Security & Dependency Analysis
                </h3>
                {renderStatusBadge(aiStatus?.status)}
              </div>
              <p className="text-xs text-slate-400">
                Target Finding: <strong className="text-rose-400">{finding.title}</strong>
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-white rounded-lg cursor-pointer transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 overflow-y-auto max-h-[75vh] text-xs">
          {/* Online Requirement Notice */}
          <div className="p-3 rounded-xl bg-purple-950/25 border border-purple-500/25 flex items-start gap-2.5 text-purple-200">
            <HelpCircle className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
            <div className="space-y-0.5 leading-relaxed text-[11px]">
              <span className="font-semibold text-purple-300">Online Intelligence Notice:</span>
              <p className="text-slate-300">
                Local project scanning, dependency graph, and vulnerability reconciliation run 100% locally.
                Gemini AI analysis is an optional cloud feature requiring outbound internet connectivity and a configured Gemini API key.
              </p>
            </div>
          </div>

          {/* Optional API Key Input */}
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800/90 space-y-2">
            <div className="flex items-center justify-between text-slate-300">
              <span className="flex items-center gap-1.5 font-semibold text-xs">
                <Key className="w-3.5 h-3.5 text-purple-400" />
                Gemini API Key (Optional Override)
              </span>
              <span className="text-[10px] text-slate-500">Stored locally in your browser</span>
            </div>
            <input
              type="password"
              placeholder="AIzaSy... (leave blank to use backend environment GEMINI_API_KEY)"
              value={apiKey}
              onChange={(e) => handleApiKeyChange(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-purple-500 transition-colors"
            />
          </div>

          {/* Step 1: Pre-Transmission Sanitized Payload Preview */}
          {!explanation && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-slate-300 font-semibold text-xs">
                    <Shield className="w-4 h-4 text-emerald-400" />
                    <span>Privacy Verification: Sanitized Payload Preview</span>
                  </div>
                  <span className="text-[10px] text-emerald-400 font-mono bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
                    Zero Secrets Transmitted
                  </span>
                </div>
                <p className="text-slate-400 text-[11px]">
                  BlindSpot strictly sanitizes all requests: proprietary source code, passwords, internal hostnames, and file paths are excluded.
                </p>
                <pre className="p-3 rounded-lg bg-slate-900 text-slate-300 font-mono text-[11px] overflow-x-auto border border-slate-800">
                  {JSON.stringify(sanitizedPreview, null, 2)}
                </pre>
              </div>

              {/* User Consent Checkbox */}
              <div
                onClick={() => setHasApproved(!hasApproved)}
                className="flex items-center gap-3 p-3 rounded-xl bg-slate-900 border border-slate-800 cursor-pointer hover:bg-slate-850 transition-colors"
              >
                {hasApproved ? (
                  <CheckSquare className="w-5 h-5 text-rose-500 shrink-0" />
                ) : (
                  <Square className="w-5 h-5 text-slate-500 shrink-0" />
                )}
                <span className="text-xs text-slate-300">
                  I give explicit consent to transmit this sanitized public vulnerability metadata to the Google Gemini API for live analysis.
                </span>
              </div>

              {error && (
                <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center justify-between">
                  <span>{error}</span>
                  <button
                    onClick={handleExecuteExplain}
                    className="flex items-center gap-1 px-2 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 text-[11px] font-semibold cursor-pointer"
                  >
                    <RotateCcw className="w-3 h-3" /> Retry
                  </button>
                </div>
              )}

              <button
                disabled={!hasApproved || isLoading}
                onClick={handleExecuteExplain}
                className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-gradient-to-r from-rose-600 via-purple-600 to-indigo-600 hover:from-rose-500 hover:to-indigo-500 disabled:opacity-40 text-white font-semibold text-xs shadow-lg transition-all cursor-pointer"
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Querying Google Gemini Model...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4" />
                    <span>Generate Architectural Explanation</span>
                  </>
                )}
              </button>
            </div>
          )}

          {/* Step 2: Render Structured Explanation */}
          {explanation && (
            <div className="space-y-4">
              {/* Status & Diagnostic Banner */}
              <div className="flex items-center justify-between p-3 rounded-xl bg-slate-900 border border-slate-800">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400">Analysis Source:</span>
                  <span
                    className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                      explanation.is_ai_generated
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                    }`}
                  >
                    {explanation.is_ai_generated ? 'Live Gemini AI' : 'Deterministic Local Rules'}
                  </span>
                </div>
                {renderStatusBadge(explanation.ai_status || (explanation.is_ai_generated ? 'AI_READY' : 'AI_NOT_CONFIGURED'))}
              </div>

              {/* Error Callout if fallback was used due to failure */}
              {explanation.is_fallback && explanation.error_message && (
                <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/25 text-amber-200 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                      Gemini Diagnostics ({explanation.ai_status})
                    </span>
                    <button
                      onClick={handleExecuteExplain}
                      className="flex items-center gap-1 text-[10px] text-amber-300 underline cursor-pointer hover:text-white"
                    >
                      <RotateCcw className="w-3 h-3" /> Retry Request
                    </button>
                  </div>
                  <p className="text-[11px] text-slate-300">
                    {explanation.error_message}
                  </p>
                </div>
              )}

              {/* Summary */}
              <div className="p-4 rounded-xl bg-slate-950 border border-purple-500/30 space-y-2">
                <span className="font-semibold text-white text-xs block">Vulnerability Summary</span>
                <p className="text-slate-300 leading-relaxed text-xs">{explanation.summary}</p>
              </div>

              {/* Architectural Impact */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <span className="font-semibold text-white text-xs block">
                  {explanation.audience === 'enterprise' ? 'SRE & Business Continuity Blast Radius' : 'Runtime & Dependency Impact'}
                </span>
                <p className="text-slate-300 text-xs leading-relaxed">{explanation.why_it_matters}</p>
              </div>

              {/* Technical Impact */}
              {explanation.technical_impact && (
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                  <span className="font-semibold text-slate-300 text-xs block">Technical Root Cause</span>
                  <p className="text-slate-400 text-xs">{explanation.technical_impact}</p>
                </div>
              )}

              {/* Safe Remediation Steps */}
              <div className="p-4 rounded-xl bg-slate-950 border border-emerald-500/20 space-y-2.5">
                <span className="font-semibold text-emerald-400 text-xs block">
                  Safe Remediation Steps ({explanation.audience.toUpperCase()} PERSPECTIVE)
                </span>
                <ul className="space-y-2 text-slate-300 text-xs">
                  {explanation.safe_remediation_steps.map((step, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="font-mono text-rose-400 text-[11px] shrink-0 mt-0.5">[{idx + 1}]</span>
                      <span className="leading-relaxed">{step}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
                <span>{explanation.notice}</span>
                <button
                  onClick={() => setExplanation(null)}
                  className="text-purple-400 hover:text-purple-300 underline cursor-pointer"
                >
                  Inspect Sanitized Payload Again
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800/80 bg-slate-900/40 flex justify-between items-center">
          <span className="text-[11px] text-slate-500">
            BlindSpot Privacy Protocol: Local-first scanning with explicit consent.
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium cursor-pointer transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
