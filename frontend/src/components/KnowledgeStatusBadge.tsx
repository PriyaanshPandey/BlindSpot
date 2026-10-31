import React, { useState, useEffect } from 'react';
import { X, CheckCircle2, AlertTriangle, Shield, Cpu, RefreshCw, ExternalLink, Hash, Lock } from 'lucide-react';
import { BundleVerificationSummary, KnowledgeManifest } from '../types';
import { getKnowledgeManifest, verifyKnowledgeBundle } from '../api/client';

interface KnowledgeStatusBadgeProps {
  isOpen: boolean;
  onClose: () => void;
}

export const KnowledgeStatusBadge: React.FC<KnowledgeStatusBadgeProps> = ({ isOpen, onClose }) => {
  const [manifest, setManifest] = useState<KnowledgeManifest | null>(null);
  const [verification, setVerification] = useState<BundleVerificationSummary | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isTampering, setIsTampering] = useState(false);

  useEffect(() => {
    if (isOpen) {
      loadData(false);
    }
  }, [isOpen]);

  const loadData = async (simulateTamper: boolean) => {
    setIsLoading(true);
    try {
      const [m, v] = await Promise.all([
        getKnowledgeManifest(),
        verifyKnowledgeBundle(simulateTamper)
      ]);
      setManifest(m);
      setVerification(v);
    } catch (err) {
      console.error('Failed to load knowledge status:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleToggleTamper = async () => {
    const nextState = !isTampering;
    setIsTampering(nextState);
    await loadData(nextState);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0F172A] border border-slate-700 w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
              <Cpu className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-white text-sm">Verifiable Knowledge Plane & Cryptographic Anchoring</h3>
              <p className="text-xs text-slate-400">Ed25519 Signatures + Solana Devnet Ledger Verification</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded-lg">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 overflow-y-auto max-h-[75vh]">
          {/* Status Alert Banner */}
          {verification?.overall_status === 'verified' ? (
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-start gap-3">
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-sm font-semibold text-emerald-300">Knowledge Bundle Authenticity Confirmed</h4>
                <p className="text-xs text-emerald-400/80 mt-1">
                  Bundle was cryptographically signed by the HDX Authority using Ed25519 and independently anchored to the Solana Devnet blockchain.
                </p>
              </div>
            </div>
          ) : (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-sm font-semibold text-rose-300">Cryptographic Integrity Alert: Tamper Detected</h4>
                <p className="text-xs text-rose-400/80 mt-1">
                  Signature verification rejected the bundle. The contents were altered after publication, preventing rogue advisory injection.
                </p>
              </div>
            </div>
          )}

          {/* Details Grid */}
          <div className="grid grid-cols-2 gap-4 text-xs">
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
              <div className="flex items-center gap-2 text-slate-400 font-medium">
                <Lock className="w-4 h-4 text-blue-400" />
                <span>Ed25519 Cryptographic Signature</span>
              </div>
              <div className="pt-1">
                <span className="text-slate-500 block">Status:</span>
                <span className={`font-semibold ${verification?.ed25519_verification.is_valid ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {verification?.ed25519_verification.is_valid ? 'Valid Signature' : 'Signature Mismatch / Rejected'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Signing Key ID:</span>
                <span className="font-mono text-[11px] text-slate-300 truncate block">
                  {verification?.ed25519_verification.signing_key_id?.slice(0, 24)}...
                </span>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
              <div className="flex items-center gap-2 text-slate-400 font-medium">
                <Cpu className="w-4 h-4 text-purple-400" />
                <span>Solana Devnet Memo Anchor</span>
              </div>
              <div className="pt-1">
                <span className="text-slate-500 block">Cluster & Slot:</span>
                <span className="text-slate-300 font-medium">
                  {verification?.solana_verification.cluster} (Slot #{verification?.solana_verification.slot})
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Anchor Transaction:</span>
                <a
                  href={verification?.solana_verification.explorer_url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-purple-400 hover:text-purple-300 flex items-center gap-1 font-mono text-[11px] truncate"
                >
                  <span>{verification?.solana_verification.tx_signature?.slice(0, 18)}...</span>
                  <ExternalLink className="w-3 h-3 shrink-0" />
                </a>
              </div>
            </div>
          </div>

          {/* Bundle SHA-256 Hash */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="flex items-center gap-2 text-slate-400 text-xs mb-2">
              <Hash className="w-4 h-4 text-slate-400" />
              <span>Canonical SHA-256 Bundle Digest</span>
            </div>
            <code className="text-xs font-mono text-blue-300 bg-slate-950 px-3 py-2 rounded-lg block overflow-x-auto border border-slate-800">
              {verification?.bundle_sha256}
            </code>
          </div>

          {/* Tamper Test Toggle */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-sm font-medium text-white block">Test Tamper Detection</span>
              <span className="text-xs text-slate-400">
                Inject malicious byte alteration to prove rejection of compromised bundles
              </span>
            </div>
            <button
              onClick={handleToggleTamper}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                isTampering
                  ? 'bg-rose-600 text-white shadow-lg shadow-rose-600/30'
                  : 'bg-slate-800 hover:bg-slate-700 text-slate-200'
              }`}
            >
              {isTampering ? 'Tampering Active (Reset)' : 'Inject Tamper Test'}
            </button>
          </div>
        </div>

        {/* Modal Footer */}
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

