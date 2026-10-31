import React, { useState, useEffect } from 'react';
import { X, Sparkles, Shield, CheckSquare, Square, RefreshCw, AlertCircle, ArrowRight } from 'lucide-react';
import { Finding, AIExplanation } from '../types';
import { previewAIPayload, explainFindingAI } from '../api/client';

interface AIExplainModalProps {
  finding: Finding | null;
  mode: 'builder' | 'enterprise';
  isOpen: boolean;
  onClose: () => void;
}

export const AIExplainModal: React.FC<AIExplainModalProps> = ({
  finding,
  mode,
  isOpen,
  onClose
}) => {
  const [sanitizedPreview, setSanitizedPreview] = useState<any>(null);
  const [explanation, setExplanation] = useState<AIExplanation | null>(null);
  const [hasApproved, setHasApproved] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (finding && isOpen) {
      setExplanation(null);
      setError(null);
      setHasApproved(false);
      // Fetch preview
      previewAIPayload(finding, mode).then(data => {
        setSanitizedPreview(data.payload_to_send);
      }).catch(err => {
        setError('Failed to sanitize payload preview.');
      });
    }
  }, [finding, isOpen, mode]);

  const handleExecuteExplain = async () => {
    if (!finding || !hasApproved) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await explainFindingAI(finding, mode, true);
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
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-blue-500 to-purple-600 flex items-center justify-center text-white">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-white text-sm">
                Gemini AI Security & Dependency Explanation
              </h3>
              <p className="text-xs text-slate-400">
                Audience: <strong className="text-blue-400 capitalize">{mode}</strong> • Finding: {finding.title}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 text-slate-400 hover:text-white rounded-lg">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 overflow-y-auto max-h-[75vh] text-xs">
          {/* Step 1: Pre-Transmission Sanitized Payload Preview */}
          {!explanation && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-center gap-2 text-slate-300 font-semibold text-xs">
                  <Shield className="w-4 h-4 text-emerald-400" />
                  <span>Privacy Verification: Sanitized Payload Preview</span>
                </div>
                <p className="text-slate-400 text-[11px]">
                  To protect your privacy, HDX strips all source code, file paths, credentials, and internal hostnames.
                  Verify the exact metadata payload below before approving transmission:
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
                  <CheckSquare className="w-5 h-5 text-blue-500 shrink-0" />
                ) : (
                  <Square className="w-5 h-5 text-slate-500 shrink-0" />
                )}
                <span className="text-xs text-slate-300">
                  I approve transmitting this sanitized public vulnerability metadata to the Gemini API for explanation.
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
                className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 disabled:opacity-40 text-white font-semibold text-xs shadow-lg transition-all"
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Querying Gemini Model...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4" />
                    <span>Generate Structured Explanation</span>
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
                    {explanation.is_ai_generated ? 'Live Gemini AI' : 'Rule-Based Fallback'}
                  </span>
                </div>
                <p className="text-slate-300 leading-relaxed text-xs">{explanation.summary}</p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <span className="font-semibold text-white text-xs">Why It Matters</span>
                <p className="text-slate-400 text-xs">{explanation.why_it_matters}</p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <span className="font-semibold text-emerald-400 text-xs">Safe Remediation Steps</span>
                <ul className="space-y-2 text-slate-300 text-xs">
                  {explanation.safe_remediation_steps.map((step, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="font-mono text-blue-400 text-[11px] shrink-0 mt-0.5">[{idx + 1}]</span>
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
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

