import React, { useState, useEffect } from 'react';
import { X, Sparkles, Shield, CheckSquare, Square, RefreshCw, Key } from 'lucide-react';
import { Finding, AIExplanation } from '../types';
import { previewAIPayload, explainFindingAI } from '../api/client';

interface AIExplainModalProps {
  finding: Finding | null;
  mode?: string;
  isOpen: boolean;
  onClose: () => void;
}

export const AIExplainModal: React.FC<AIExplainModalProps> = ({
  finding,
  isOpen,
  onClose
}) => {
  const [sanitizedPreview, setSanitizedPreview] = useState<any>(null);
  const [explanation, setExplanation] = useState<AIExplanation | null>(null);
  const [hasApproved, setHasApproved] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState<string>(() => localStorage.getItem('blindspot_gemini_key') || '');

  useEffect(() => {
    if (finding && isOpen) {
      setExplanation(null);
      setError(null);
      setHasApproved(false);
      previewAIPayload(finding, 'developer' as any).then(data => {
        setSanitizedPreview(data.payload_to_send);
      }).catch(() => {
        setError('Failed to sanitize payload preview.');
      });
    }
  }, [finding, isOpen]);

  const handleApiKeyChange = (val: string) => {
    setApiKey(val);
    localStorage.setItem('blindspot_gemini_key', val.trim());
  };

  const handleExecuteExplain = async () => {
    if (!finding || !hasApproved) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await explainFindingAI(finding, 'developer', true, apiKey.trim());
      setExplanation(res);
    } catch (err: any) {
      setError(err.message || 'AI request failed');
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen || !finding) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0F172A] border border-slate-700 w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-rose-500 to-purple-600 flex items-center justify-center text-white shadow-[0_0_15px_rgba(244,63,94,0.4)]">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-white text-sm">
                Gemini AI Security & Dependency Analysis
              </h3>
              <p className="text-xs text-slate-400">
                Finding: <strong className="text-rose-400">{finding.title}</strong>
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 text-slate-400 hover:text-white rounded-lg cursor-pointer">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 overflow-y-auto max-h-[75vh] text-xs">
          {/* Optional API Key Input */}
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-slate-300">
              <span className="flex items-center gap-1.5 font-semibold text-xs">
                <Key className="w-3.5 h-3.5 text-purple-400" />
                Gemini API Key (Optional)
              </span>
              <span className="text-[10px] text-slate-500">Stored locally in your browser</span>
            </div>
            <input
              type="password"
              placeholder="AIzaSy... (leave blank to use server environment key)"
              value={apiKey}
              onChange={(e) => handleApiKeyChange(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-purple-500 transition-colors"
            />
          </div>

          {/* Step 1: Pre-Transmission Sanitized Payload Preview */}
          {!explanation && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-center gap-2 text-slate-300 font-semibold text-xs">
                  <Shield className="w-4 h-4 text-emerald-400" />
                  <span>Privacy Verification: Sanitized Payload Preview</span>
                </div>
                <p className="text-slate-400 text-[11px]">
                  Blindspot strictly sanitizes every request: zero source code, passwords, or internal hostnames are transmitted.
                </p>
                <pre className="p-3 rounded-lg bg-slate-900 text-slate-300 font-mono text-[11px] overflow-x-auto border border-slate-800">
                  {JSON.stringify(sanitizedPreview, null, 2)}
                </pre>
              </div>

              {/* User Consent Checkbox */}
              <div
                onClick={() => setHasApproved(!hasApproved)}
                className="flex items-center gap-3 p-3 rounded-xl bg-slate-900 border border-slate-800 cursor-pointer hover:bg-slate-850"
              >
                {hasApproved ? (
                  <CheckSquare className="w-5 h-5 text-rose-500 shrink-0" />
                ) : (
                  <Square className="w-5 h-5 text-slate-500 shrink-0" />
                )}
                <span className="text-xs text-slate-300">
                  I approve transmitting this sanitized public vulnerability metadata to the Gemini API for live analysis.
                </span>
              </div>

              {error && (
                <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
                  {error}
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
                    <span>Querying Gemini Model...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4" />
                    <span>Generate Live Architectural Explanation</span>
                  </>
                )}
              </button>
            </div>
          )}

          {/* Step 2: Render Structured Explanation */}
          {explanation && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-purple-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white text-sm">Summary</span>
                  <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                    {explanation.is_ai_generated ? 'Live Gemini AI' : 'Rule-Based Engine'}
                  </span>
                </div>
                <p className="text-slate-300 leading-relaxed text-xs">{explanation.summary}</p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <span className="font-semibold text-white text-xs">Architectural Impact</span>
                <p className="text-slate-400 text-xs">{explanation.why_it_matters}</p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <span className="font-semibold text-emerald-400 text-xs">Safe Remediation Steps</span>
                <ul className="space-y-2 text-slate-300 text-xs">
                  {explanation.safe_remediation_steps.map((step, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="font-mono text-rose-400 text-[11px] shrink-0 mt-0.5">[{idx + 1}]</span>
                      <span>{step}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <p className="text-[10px] text-slate-500 text-center italic">
                {explanation.notice}
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-900/40 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
