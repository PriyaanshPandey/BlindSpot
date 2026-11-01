import React, { useState, useEffect, useRef } from 'react';
import {
  Sparkles,
  Send,
  X,
  Minimize2,
  RotateCcw,
  ShieldCheck,
  AlertTriangle,
  Check,
  Copy,
  RefreshCw,
  Terminal,
  Layers,
  Flame,
  ArrowRight,
  ShieldAlert,
  Bot
} from 'lucide-react';
import {
  Finding,
  GraphNode,
  SimulationResult,
  AIStatusResponse,
  ChatMessage,
  ChatReference
} from '../types';
import { sendAIChat, getAIStatus } from '../api/client';

interface AskBlindSpotProps {
  scanId?: string;
  projectName?: string;
  selectedFinding?: Finding | null;
  selectedNode?: GraphNode | null;
  simulation?: SimulationResult | null;
  mode: 'builder' | 'enterprise';
  findings?: Finding[];
  onSelectFinding?: (finding: Finding) => void;
  onSelectNode?: (nodeId: string) => void;
}

const SUGGESTED_QUESTIONS = [
  'Why is this dependency risky?',
  'Which vulnerability should I fix first?',
  'What happens if this service fails?',
  'Explain my dependency graph.',
  'What is the difference between declared and observed dependencies?',
  'How should I secure my payment integration?'
];

export const AskBlindSpot: React.FC<AskBlindSpotProps> = ({
  scanId,
  projectName = 'Nexus Commerce',
  selectedFinding,
  selectedNode,
  simulation,
  mode,
  findings = [],
  onSelectFinding,
  onSelectNode
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [hasApproved, setHasApproved] = useState(false);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [aiStatus, setAiStatus] = useState<AIStatusResponse | null>(null);
  const [isStatusChecking, setIsStatusChecking] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [conversationId] = useState<string>(() => `session-${Date.now().toString(36)}`);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Load status on mount and when panel opens
  useEffect(() => {
    checkStatus(false);
  }, [isOpen]);

  // Scroll to bottom when messages change
  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isLoading, isOpen]);

  const checkStatus = async (forceRefresh = false) => {
    setIsStatusChecking(true);
    try {
      const res = await getAIStatus(forceRefresh);
      setAiStatus(res);
    } catch {
      setAiStatus({
        status: 'BACKEND_UNAVAILABLE',
        configured: false,
        model: 'gemini-3.6-flash',
        message: 'Backend server is unreachable.'
      });
    } finally {
      setIsStatusChecking(false);
    }
  };

  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || inputMessage).trim();
    if (!text || isLoading || !hasApproved) return;

    const userMsg: ChatMessage = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content: text,
      timestamp: Date.now()
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputMessage('');
    setIsLoading(true);

    try {
      const historyPayload = messages.map((m) => ({
        role: m.role,
        content: m.content
      }));

      const res = await sendAIChat({
        message: text,
        conversation_id: conversationId,
        scan_id: scanId,
        finding_id: selectedFinding?.id,
        graph_node_id: selectedNode?.id,
        audience: mode,
        user_approved_transmission: true,
        history: historyPayload
      });

      const assistantMsg: ChatMessage = {
        id: `msg-${Date.now()}`,
        role: 'assistant',
        content: res.answer,
        timestamp: Date.now(),
        references: res.references,
        isAiGenerated: res.is_ai_generated,
        status: res.ai_status
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      const errorMsg: ChatMessage = {
        id: `msg-${Date.now()}`,
        role: 'assistant',
        content: `**Request Notice**: ${err.message || 'Unable to complete AI analysis.'}`,
        timestamp: Date.now(),
        isError: true,
        status: 'AI_REQUEST_FAILED'
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleCopyCode = (code: string, blockId: string) => {
    navigator.clipboard.writeText(code);
    setCopiedId(blockId);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleClearChat = () => {
    setMessages([]);
  };

  const renderStatusBadge = () => {
    if (isStatusChecking) {
      return (
        <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/30">
          <RefreshCw className="w-2.5 h-2.5 animate-spin" /> Checking
        </span>
      );
    }

    switch (aiStatus?.status) {
      case 'AI_READY':
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> Gemini Online
          </span>
        );
      case 'AI_QUOTA_EXCEEDED':
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400" /> Quota Exceeded (Local)
          </span>
        );
      case 'AI_NOT_CONFIGURED':
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-500/10 text-slate-400 border border-slate-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-400" /> Not Configured
          </span>
        );
      case 'AI_AUTH_FAILED':
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400" /> Auth Failed
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-500/10 text-slate-400 border border-slate-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-400" /> Local Fallback
          </span>
        );
    }
  };

  const renderMessageContent = (content: string, msgId: string) => {
    // Process markdown code blocks
    const parts = content.split(/(```[\s\S]*?```)/g);

    return parts.map((part, index) => {
      if (part.startsWith('```')) {
        const lines = part.slice(3, -3).trim().split('\n');
        const lang = lines[0].match(/^[a-zA-Z0-9_-]+$/) ? lines[0] : '';
        const code = lang ? lines.slice(1).join('\n') : lines.join('\n');
        const blockId = `${msgId}-block-${index}`;

        return (
          <div key={index} className="my-2 rounded-xl bg-slate-950 border border-white/10 overflow-hidden font-mono text-xs">
            <div className="flex items-center justify-between px-3 py-1.5 bg-white/[0.03] border-b border-white/5 text-[11px] text-slate-400">
              <span className="flex items-center gap-1">
                <Terminal className="w-3 h-3 text-purple-400" />
                {lang || 'command'}
              </span>
              <button
                onClick={() => handleCopyCode(code, blockId)}
                className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-white transition-colors cursor-pointer"
              >
                {copiedId === blockId ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-3 text-emerald-300 overflow-x-auto whitespace-pre-wrap">{code}</pre>
          </div>
        );
      }

      // Inline markdown: bold, inline code, list items
      const formattedLines = part.split('\n').map((line, lIdx) => {
        // Headers
        if (line.startsWith('### ')) {
          return <h4 key={lIdx} className="font-bold text-white text-xs mt-2 mb-1">{line.replace('### ', '')}</h4>;
        }
        if (line.startsWith('## ')) {
          return <h3 key={lIdx} className="font-bold text-white text-sm mt-2 mb-1">{line.replace('## ', '')}</h3>;
        }
        if (line.startsWith('> [!NOTE]') || line.startsWith('> [!WARNING]')) {
          return null; // Alerts parsed visually
        }

        // Parse bold and inline code
        const formattedText = line.split(/(\*\*.*?\*\*|`.*?`)/g).map((sub, sIdx) => {
          if (sub.startsWith('**') && sub.endsWith('**')) {
            return <strong key={sIdx} className="font-semibold text-white">{sub.slice(2, -2)}</strong>;
          }
          if (sub.startsWith('`') && sub.endsWith('`')) {
            return (
              <code key={sIdx} className="px-1 py-0.5 rounded bg-white/10 text-rose-300 font-mono text-[11px]">
                {sub.slice(1, -1)}
              </code>
            );
          }
          return sub;
        });

        if (line.startsWith('- ') || line.startsWith('* ')) {
          return (
            <li key={lIdx} className="ml-3 list-disc text-slate-300 my-0.5 text-xs">
              {formattedText}
            </li>
          );
        }

        return <p key={lIdx} className="my-1 text-slate-300 text-xs leading-relaxed">{formattedText}</p>;
      });

      return <div key={index}>{formattedLines}</div>;
    });
  };

  return (
    <>
      {/* Floating Sparkle Bubble */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 z-40 group flex items-center gap-2.5 p-3 rounded-2xl bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600 text-white shadow-2xl hover:scale-105 active:scale-95 transition-all duration-300 border border-white/20 cursor-pointer"
          title="Open Ask BlindSpot"
        >
          <div className="relative">
            <Sparkles className="w-5 h-5 animate-pulse text-amber-200" />
            <span
              className={`absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full border-2 border-slate-900 ${
                aiStatus?.status === 'AI_READY'
                  ? 'bg-emerald-400'
                  : aiStatus?.status === 'AI_QUOTA_EXCEEDED'
                  ? 'bg-amber-400'
                  : 'bg-blue-400'
              }`}
            />
          </div>
          <span className="font-semibold text-xs tracking-wide pr-1">Ask BlindSpot</span>
        </button>
      )}

      {/* Expanded Chat Drawer / Window */}
      {isOpen && (
        <div className="fixed bottom-6 right-6 z-50 w-[420px] max-w-[calc(100vw-32px)] h-[580px] max-h-[calc(100vh-96px)] flex flex-col rounded-3xl bg-slate-950/95 border border-white/15 shadow-2xl backdrop-blur-2xl overflow-hidden animate-in fade-in slide-in-from-bottom-4 duration-300">
          {/* Header */}
          <div className="p-4 border-b border-white/10 bg-gradient-to-r from-slate-900/90 via-indigo-950/40 to-slate-900/90 flex items-center justify-between select-none">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-xl bg-gradient-to-tr from-blue-500 to-purple-600 text-white shadow-sm">
                <Sparkles className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-white tracking-tight">Ask BlindSpot</h3>
                  {renderStatusBadge()}
                </div>
                <div className="flex items-center gap-1.5 text-[10px] text-slate-400 mt-0.5">
                  <span className="text-slate-300 font-medium truncate max-w-[130px]">{projectName}</span>
                  <span>•</span>
                  <span className="capitalize font-mono text-indigo-300">{mode} Mode</span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <button
                onClick={() => checkStatus(true)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors cursor-pointer"
                title="Refresh Gemini Status"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isStatusChecking ? 'animate-spin text-blue-400' : ''}`} />
              </button>
              <button
                onClick={handleClearChat}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors cursor-pointer"
                title="Clear Conversation"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors cursor-pointer"
                title="Minimize Chat"
              >
                <Minimize2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Active Context Banner (Finding / Node / Simulation) */}
          {(selectedFinding || selectedNode || simulation) && (
            <div className="px-3.5 py-1.5 bg-white/[0.02] border-b border-white/5 flex items-center justify-between text-[11px] overflow-x-auto whitespace-nowrap">
              <div className="flex items-center gap-2 text-slate-300">
                <span className="text-[10px] uppercase font-bold text-slate-500">Context:</span>
                {selectedFinding && (
                  <span className="px-2 py-0.5 rounded-md bg-rose-500/10 text-rose-300 border border-rose-500/20 font-mono text-[10px]">
                    Finding: {selectedFinding.security_details?.cve_id || selectedFinding.target_node_id}
                  </span>
                )}
                {selectedNode && (
                  <span className="px-2 py-0.5 rounded-md bg-purple-500/10 text-purple-300 border border-purple-500/20 font-mono text-[10px]">
                    Node: {selectedNode.label}
                  </span>
                )}
                {simulation && (
                  <span className="px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-300 border border-amber-500/20 font-mono text-[10px] flex items-center gap-1">
                    <Flame className="w-2.5 h-2.5" /> Sim: Score {Math.round(simulation.impact_results.architecture_impact_score || 0)}
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Chat Messages Scrollable Area */}
          <div className="flex-1 overflow-y-auto p-4 space-y-3.5">
            {/* Welcome Greeting */}
            {messages.length === 0 && (
              <div className="space-y-4 pt-2">
                <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 space-y-2">
                  <div className="flex items-center gap-2 text-purple-400 font-semibold text-xs">
                    <Bot className="w-4 h-4" />
                    <span>BlindSpot Security Copilot</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Hello! I'm your BlindSpot assistant. I can help you investigate vulnerabilities, understand dependencies, explore architecture risks and interpret your scan results.
                  </p>
                </div>

                {/* Consent Gate Checklist if not approved */}
                {!hasApproved && (
                  <div className="p-3.5 rounded-2xl bg-gradient-to-br from-indigo-950/40 to-slate-900 border border-indigo-500/30 space-y-2.5">
                    <div className="flex items-center gap-2 text-xs font-semibold text-indigo-300">
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      <span>Privacy & Context Authorization</span>
                    </div>
                    <p className="text-[11px] text-slate-300 leading-normal">
                      To provide grounded answers, sanitized metadata (package names, versions, advisory IDs) will be transmitted to Google Gemini ({aiStatus?.model || 'gemini-3.6-flash'}).
                    </p>
                    <div className="text-[10px] text-slate-400 space-y-1 bg-black/40 p-2 rounded-lg border border-white/5 font-mono">
                      <p className="text-emerald-400">✓ No source files, tokens, or credentials are sent.</p>
                      <p className="text-emerald-400">✓ BlindSpot scanner remains local-first.</p>
                    </div>
                    <label className="flex items-start gap-2 pt-1 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={hasApproved}
                        onChange={(e) => setHasApproved(e.target.checked)}
                        className="mt-0.5 rounded border-slate-700 text-blue-500 focus:ring-blue-400"
                      />
                      <span className="text-[11px] text-slate-200 select-none">
                        I approve transmitting sanitized project metadata for this session.
                      </span>
                    </label>
                  </div>
                )}

                {/* Suggested Questions Chips */}
                <div className="space-y-2 pt-1">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block">
                    Suggested Questions:
                  </span>
                  <div className="flex flex-col gap-1.5">
                    {SUGGESTED_QUESTIONS.map((q, idx) => (
                      <button
                        key={idx}
                        disabled={!hasApproved}
                        onClick={() => handleSendMessage(q)}
                        className={`text-left text-xs p-2.5 rounded-xl border transition-all flex items-center justify-between group ${
                          hasApproved
                            ? 'bg-white/[0.02] hover:bg-white/[0.07] border-white/10 hover:border-white/20 text-slate-300 cursor-pointer'
                            : 'bg-white/[0.01] border-white/5 text-slate-500 cursor-not-allowed opacity-60'
                        }`}
                      >
                        <span>{q}</span>
                        <ArrowRight className="w-3 h-3 text-slate-500 group-hover:text-white transition-transform group-hover:translate-x-0.5" />
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Conversation Messages */}
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}
              >
                <div
                  className={`max-w-[88%] p-3.5 rounded-2xl text-xs space-y-1.5 ${
                    msg.role === 'user'
                      ? 'bg-blue-600 text-white rounded-tr-sm shadow-md'
                      : msg.isError
                      ? 'bg-rose-950/40 border border-rose-500/30 text-rose-200 rounded-tl-sm'
                      : 'bg-slate-900 border border-white/10 text-slate-200 rounded-tl-sm shadow-lg'
                  }`}
                >
                  {renderMessageContent(msg.content, msg.id)}

                  {/* Verified References Chips */}
                  {msg.references && msg.references.length > 0 && (
                    <div className="pt-2 mt-2 border-t border-white/10 flex flex-wrap gap-1.5">
                      <span className="text-[9px] uppercase font-bold text-slate-500 self-center">Verified Refs:</span>
                      {msg.references.map((ref, idx) => (
                        <button
                          key={idx}
                          onClick={() => {
                            if (ref.type === 'finding') {
                              const found = findings.find((f) => f.id === ref.id);
                              if (found && onSelectFinding) onSelectFinding(found);
                            } else if (ref.type === 'node' && onSelectNode) {
                              onSelectNode(ref.id);
                            }
                          }}
                          className="px-2 py-0.5 rounded text-[10px] font-mono bg-white/[0.05] hover:bg-white/10 border border-white/10 text-indigo-300 flex items-center gap-1 transition-colors cursor-pointer"
                        >
                          <span>{ref.label}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                <span className="text-[9px] text-slate-500 mt-1 px-1">
                  {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
            ))}

            {/* Loading Indicator */}
            {isLoading && (
              <div className="flex items-center gap-2 p-3 rounded-2xl bg-slate-900 border border-white/10 text-xs text-slate-400 w-fit">
                <Sparkles className="w-3.5 h-3.5 text-purple-400 animate-spin" />
                <span>Consulting Gemini ({aiStatus?.model || 'gemini-3.6-flash'})...</span>
                <span className="flex gap-1 ml-1">
                  <span className="w-1.5 h-1.5 bg-blue-400 rounded-full animate-bounce [animation-delay:-0.3s]" />
                  <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce [animation-delay:-0.15s]" />
                  <span className="w-1.5 h-1.5 bg-purple-400 rounded-full animate-bounce" />
                </span>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input Area */}
          <div className="p-3 border-t border-white/10 bg-slate-900/80 space-y-2">
            {!hasApproved && (
              <div className="flex items-center justify-between text-[11px] text-amber-400 bg-amber-500/10 px-2.5 py-1.5 rounded-lg border border-amber-500/20">
                <span className="flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  Consent required before transmitting questions.
                </span>
                <button
                  onClick={() => setHasApproved(true)}
                  className="underline font-semibold cursor-pointer"
                >
                  Approve
                </button>
              </div>
            )}

            <div className="relative flex items-center">
              <textarea
                ref={textareaRef}
                rows={2}
                disabled={!hasApproved || isLoading}
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder={
                  !hasApproved
                    ? 'Check consent above to start asking BlindSpot...'
                    : `Ask about dependencies, ${selectedFinding ? 'this finding' : 'architecture risks'}, or mitigations...`
                }
                className="w-full bg-slate-950 border border-white/10 rounded-2xl px-3 py-2 pr-12 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors resize-none disabled:opacity-50"
              />

              <button
                disabled={!hasApproved || !inputMessage.trim() || isLoading}
                onClick={() => handleSendMessage()}
                className="absolute right-2 p-2 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 text-white disabled:opacity-30 disabled:cursor-not-allowed hover:scale-105 active:scale-95 transition-all cursor-pointer shadow-md"
                title="Send Message (Enter)"
              >
                <Send className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="flex items-center justify-between text-[10px] text-slate-500 px-1 font-mono">
              <span>Shift + Enter for new line</span>
              <span>{inputMessage.length} / 2000</span>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
