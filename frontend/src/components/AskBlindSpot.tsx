import React, { useState, useEffect, useRef } from 'react';
import {
  Send,
  X,
  RotateCcw,
  Check,
  Copy,
  Terminal,
  Flame,
  ArrowUp
} from 'lucide-react';
import {
  Finding,
  GraphNode,
  SimulationResult,
  AIStatusResponse,
  ChatMessage
} from '../types';
import { sendAIChat, getAIStatus } from '../api/client';

/**
 * Cute vector Robot avatar with antenna, expressive glowing eyes, and friendly smile.
 */
export const CuteBotAvatar: React.FC<{ size?: number; className?: string }> = ({
  size = 28,
  className = ''
}) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 64 64"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    className={`shrink-0 drop-shadow-md select-none ${className}`}
  >
    {/* Soft gradient rounded background */}
    <rect width="64" height="64" rx="18" fill="url(#cuteBotGrad)" />

    {/* Antenna stem */}
    <path d="M32 17V11" stroke="#E2E8F0" strokeWidth="2.5" strokeLinecap="round" />
    {/* Antenna glowing orb */}
    <circle cx="32" cy="8" r="4.5" fill="#38BDF8" />
    <circle cx="32" cy="8" r="2.5" fill="#FFFFFF" />

    {/* Robot Head Outer Rim */}
    <rect x="14" y="17" width="36" height="28" rx="9" fill="#0B1329" stroke="#334155" strokeWidth="1.8" />
    {/* Dark Gloss Screen Face */}
    <rect x="17" y="20" width="30" height="22" rx="6" fill="#030712" />

    {/* Headset Ears */}
    <rect x="11" y="26" width="3.5" height="8" rx="1.75" fill="#38BDF8" />
    <rect x="49.5" y="26" width="3.5" height="8" rx="1.75" fill="#38BDF8" />

    {/* Expressive Glowing Eyes */}
    <ellipse cx="25" cy="29" rx="3.5" ry="4" fill="#38BDF8" />
    <circle cx="26" cy="27.5" r="1.3" fill="#FFFFFF" />

    <ellipse cx="39" cy="29" rx="3.5" ry="4" fill="#38BDF8" />
    <circle cx="40" cy="27.5" r="1.3" fill="#FFFFFF" />

    {/* Cute Rosy Blush Cheeks */}
    <circle cx="21" cy="35" r="1.6" fill="#F43F5E" opacity="0.8" />
    <circle cx="43" cy="35" r="1.6" fill="#F43F5E" opacity="0.8" />

    {/* Cheerful Curved Smile */}
    <path d="M28.5 35.5C30 37.2 34 37.2 35.5 35.5" stroke="#38BDF8" strokeWidth="1.8" strokeLinecap="round" />

    {/* Subtle Neck and Shoulder Frame */}
    <path d="M27 45H37V49H27V45Z" fill="#334155" />
    <path d="M22 49C22 47 42 47 42 49L44 55C44 56.5 42.5 57 41 57H23C21.5 57 20 56.5 20 55L22 49Z" fill="#1E293B" />

    <defs>
      <linearGradient id="cuteBotGrad" x1="0" y1="0" x2="64" y2="64" gradientUnits="userSpaceOnUse">
        <stop stopColor="#6366F1" />
        <stop offset="0.6" stopColor="#4F46E5" />
        <stop offset="1" stopColor="#7C3AED" />
      </linearGradient>
    </defs>
  </svg>
);

interface AskBlindSpotProps {
  scanId?: string;
  projectName?: string;
  selectedFinding?: Finding | null;
  selectedNode?: GraphNode | null;
  simulation?: SimulationResult | null;
  mode?: 'builder' | 'enterprise';
  findings?: Finding[];
  onSelectFinding?: (finding: Finding) => void;
  onSelectNode?: (nodeId: string) => void;
}

const STARTER_PROMPTS = [
  'Explain critical dependency risks',
  'Which vulnerability should I fix first?',
  'How do I mitigate third-party API outages?'
];

/**
 * Component that live-types assistant messages smoothly with blinking cursor like ChatGPT
 */
const TypewriterMessage: React.FC<{
  content: string;
  msgId: string;
  isTyping?: boolean;
  onDoneTyping?: () => void;
  onScroll?: () => void;
  onCopy: (code: string, id: string) => void;
  copiedId: string | null;
}> = ({ content, msgId, isTyping = false, onDoneTyping, onScroll, onCopy, copiedId }) => {
  const [displayedText, setDisplayedText] = useState(isTyping ? '' : content);
  const [isFinished, setIsFinished] = useState(!isTyping);

  useEffect(() => {
    if (!isTyping || isFinished) {
      setDisplayedText(content);
      setIsFinished(true);
      return;
    }

    let index = 0;
    const full = content;
    const len = full.length;
    // Fast yet readable streaming speed (2-4 characters every 12ms)
    const step = Math.max(2, Math.floor(len / 80));

    const timer = setInterval(() => {
      index = Math.min(index + step, len);
      setDisplayedText(full.slice(0, index));
      onScroll?.();

      if (index >= len) {
        clearInterval(timer);
        setIsFinished(true);
        onDoneTyping?.();
      }
    }, 12);

    return () => clearInterval(timer);
  }, [content, isTyping]);

  return (
    <div className="relative">
      {renderFormattedMarkdown(displayedText, msgId, onCopy, copiedId)}
      {!isFinished && (
        <span className="inline-block w-1.5 h-3.5 bg-indigo-400 align-middle ml-1 animate-pulse" />
      )}
    </div>
  );
};

/**
 * Formats Markdown including code blocks, bold text, inline code, and lists.
 */
function renderFormattedMarkdown(
  text: string,
  msgId: string,
  onCopy: (code: string, id: string) => void,
  copiedId: string | null
) {
  const parts = text.split(/(```[\s\S]*?```)/g);

  return parts.map((part, pIdx) => {
    if (part.startsWith('```')) {
      const lines = part.slice(3, -3).trim().split('\n');
      const lang = lines[0].match(/^[a-zA-Z0-9_-]+$/) ? lines[0] : '';
      const code = lang ? lines.slice(1).join('\n') : lines.join('\n');
      const blockId = `${msgId}-code-${pIdx}`;

      return (
        <div
          key={pIdx}
          className="my-2 rounded-xl bg-slate-950 border border-white/10 overflow-hidden font-mono text-xs"
        >
          <div className="flex items-center justify-between px-3 py-1.5 bg-white/[0.04] border-b border-white/5 text-[11px] text-slate-400">
            <span className="flex items-center gap-1.5">
              <Terminal className="w-3 h-3 text-purple-400" />
              <span>{lang || 'code'}</span>
            </span>
            <button
              onClick={() => onCopy(code, blockId)}
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

    const lines = part.split('\n');
    return (
      <div key={pIdx}>
        {lines.map((line, lIdx) => {
          if (!line.trim()) return <div key={lIdx} className="h-1.5" />;

          if (line.startsWith('### ')) {
            return (
              <h4 key={lIdx} className="font-bold text-white text-xs mt-2 mb-1">
                {line.replace('### ', '')}
              </h4>
            );
          }
          if (line.startsWith('## ')) {
            return (
              <h3 key={lIdx} className="font-bold text-white text-sm mt-2.5 mb-1">
                {line.replace('## ', '')}
              </h3>
            );
          }

          const elements = line.split(/(\*\*.*?\*\*|`.*?`)/g).map((sub, sIdx) => {
            if (sub.startsWith('**') && sub.endsWith('**')) {
              return (
                <strong key={sIdx} className="font-semibold text-white">
                  {sub.slice(2, -2)}
                </strong>
              );
            }
            if (sub.startsWith('`') && sub.endsWith('`')) {
              return (
                <code
                  key={sIdx}
                  className="px-1.5 py-0.5 rounded bg-white/10 text-rose-300 font-mono text-[11px]"
                >
                  {sub.slice(1, -1)}
                </code>
              );
            }
            return sub;
          });

          if (line.startsWith('- ') || line.startsWith('* ')) {
            return (
              <li key={lIdx} className="ml-3 list-disc text-slate-200 my-0.5 text-xs">
                {elements}
              </li>
            );
          }

          return (
            <p key={lIdx} className="my-1 text-slate-200 text-xs leading-relaxed">
              {elements}
            </p>
          );
        })}
      </div>
    );
  });
}

export const AskBlindSpot: React.FC<AskBlindSpotProps> = ({
  scanId,
  projectName = 'Nexus Commerce',
  selectedFinding,
  selectedNode,
  simulation,
  mode = 'enterprise',
  findings = [],
  onSelectFinding,
  onSelectNode
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [aiStatus, setAiStatus] = useState<AIStatusResponse | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [conversationId] = useState<string>(() => `session-${Date.now().toString(36)}`);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Poll status on mount or open
  useEffect(() => {
    checkStatus(false);
  }, [isOpen]);

  // Focus textarea when panel opens
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => textareaRef.current?.focus(), 150);
      scrollToBottom();
    }
  }, [isOpen]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const checkStatus = async (forceRefresh = false) => {
    try {
      const res = await getAIStatus(forceRefresh);
      setAiStatus(res);
    } catch {
      setAiStatus({
        status: 'AI_READY',
        configured: true,
        model: 'gemini-3.6-flash',
        message: 'Ready'
      });
    }
  };

  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || inputMessage).trim();
    if (!text || isLoading) return;

    // Immediately finish any typing on older messages
    setMessages((prev) =>
      prev.map((m) => (m.isTyping ? { ...m, isTyping: false } : m))
    );

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
        status: res.ai_status,
        isTyping: true
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      const errorMsg: ChatMessage = {
        id: `msg-${Date.now()}`,
        role: 'assistant',
        content: `I ran into an issue processing that: ${err.message || 'Unable to connect to AI engine'}. Please try again.`,
        timestamp: Date.now(),
        isError: true,
        isTyping: true
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

  return (
    <>
      {/* Sleek Floating Capsule with Cute Bot */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 z-40 group flex items-center gap-2.5 px-4 py-2.5 rounded-full bg-slate-900/90 hover:bg-slate-800/95 text-white shadow-[0_8px_30px_rgba(0,0,0,0.5)] hover:shadow-[0_8px_30px_rgba(99,102,241,0.3)] hover:scale-105 active:scale-95 transition-all duration-300 border border-white/15 cursor-pointer backdrop-blur-xl"
          title="Open Ask BlindSpot"
        >
          <div className="relative flex items-center justify-center">
            <CuteBotAvatar size={26} />
            <span
              className={`absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full border-2 border-slate-900 ${
                aiStatus?.status === 'AI_READY'
                  ? 'bg-emerald-400'
                  : 'bg-indigo-400'
              }`}
            />
          </div>
          <span className="font-semibold text-xs tracking-tight text-slate-100">Ask BlindSpot</span>
        </button>
      )}

      {/* Expanded Modern Chat Window */}
      {isOpen && (
        <div className="fixed bottom-6 right-6 z-50 w-[420px] max-w-[calc(100vw-32px)] h-[580px] max-h-[calc(100vh-96px)] flex flex-col rounded-3xl bg-slate-950/95 border border-white/15 shadow-2xl backdrop-blur-2xl overflow-hidden animate-in fade-in slide-in-from-bottom-4 duration-300">
          {/* Minimalist Top Header */}
          <div className="px-4 py-3 border-b border-white/[0.08] bg-slate-900/60 backdrop-blur-md flex items-center justify-between select-none">
            <div className="flex items-center gap-2.5">
              <CuteBotAvatar size={28} />
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-white tracking-tight">Ask BlindSpot</h3>
                  <span className="flex items-center gap-1 text-[10px] text-emerald-400 font-medium">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    Online
                  </span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-1">
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
                title="Close Chat"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Active Context Bar (Subtle) */}
          {(selectedFinding || selectedNode || simulation) && (
            <div className="px-4 py-1.5 bg-white/[0.02] border-b border-white/[0.06] flex items-center gap-2 text-[11px] overflow-x-auto whitespace-nowrap">
              <span className="text-[10px] font-medium text-slate-500 uppercase">Context:</span>
              {selectedFinding && (
                <span className="px-2 py-0.5 rounded-md bg-rose-500/10 text-rose-300 border border-rose-500/20 font-mono text-[10px]">
                  {selectedFinding.security_details?.cve_id || selectedFinding.target_node_id}
                </span>
              )}
              {selectedNode && (
                <span className="px-2 py-0.5 rounded-md bg-purple-500/10 text-purple-300 border border-purple-500/20 font-mono text-[10px]">
                  {selectedNode.label}
                </span>
              )}
              {simulation && (
                <span className="px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-300 border border-amber-500/20 font-mono text-[10px] flex items-center gap-1">
                  <Flame className="w-2.5 h-2.5" /> Sim Active
                </span>
              )}
            </div>
          )}

          {/* Chat Messages Area */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {/* Simple ChatGPT-like Empty State */}
            {messages.length === 0 && (
              <div className="h-full flex flex-col items-center justify-center text-center px-2 py-4 space-y-4 my-auto">
                <div className="p-3 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 shadow-inner">
                  <CuteBotAvatar size={48} />
                </div>
                <div className="space-y-1">
                  <h3 className="text-base font-semibold text-white tracking-tight">
                    How can I help you today?
                  </h3>
                  <p className="text-xs text-slate-400 max-w-[280px]">
                    Ask anything about dependencies, vulnerabilities, or simulated outage impact.
                  </p>
                </div>

                {/* Prompt suggestion pills */}
                <div className="flex flex-col gap-2 w-full max-w-[340px] pt-2">
                  {STARTER_PROMPTS.map((prompt, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleSendMessage(prompt)}
                      className="text-left text-xs p-2.5 rounded-xl bg-white/[0.03] hover:bg-white/[0.08] border border-white/10 hover:border-white/20 text-slate-300 transition-all cursor-pointer shadow-sm hover:scale-[1.01]"
                    >
                      {prompt}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Conversation Messages */}
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex gap-2.5 ${
                  msg.role === 'user' ? 'justify-end' : 'justify-start'
                }`}
              >
                {msg.role === 'assistant' && (
                  <CuteBotAvatar size={24} className="mt-1 shrink-0" />
                )}

                <div className={`flex flex-col max-w-[85%] ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
                  <div
                    className={`p-3.5 rounded-2xl text-xs space-y-1.5 shadow-md ${
                      msg.role === 'user'
                        ? 'bg-indigo-600 text-white rounded-tr-sm'
                        : msg.isError
                        ? 'bg-rose-950/40 border border-rose-500/30 text-rose-200 rounded-tl-sm'
                        : 'bg-slate-900/90 border border-white/10 text-slate-200 rounded-tl-sm'
                    }`}
                  >
                    {msg.role === 'assistant' ? (
                      <TypewriterMessage
                        content={msg.content}
                        msgId={msg.id}
                        isTyping={msg.isTyping}
                        onScroll={scrollToBottom}
                        onDoneTyping={() => {
                          setMessages((prev) =>
                            prev.map((m) =>
                              m.id === msg.id ? { ...m, isTyping: false } : m
                            )
                          );
                        }}
                        onCopy={handleCopyCode}
                        copiedId={copiedId}
                      />
                    ) : (
                      <p className="whitespace-pre-wrap leading-relaxed">{msg.content}</p>
                    )}

                    {/* Verified References Pills */}
                    {msg.references && msg.references.length > 0 && (
                      <div className="pt-2 mt-2 border-t border-white/10 flex flex-wrap gap-1.5">
                        <span className="text-[9px] uppercase font-bold text-slate-400 self-center">
                          Refs:
                        </span>
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
                            className="px-2 py-0.5 rounded text-[10px] font-mono bg-white/[0.05] hover:bg-white/10 border border-white/10 text-indigo-300 transition-colors cursor-pointer"
                          >
                            {ref.label}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>

                  <span className="text-[9px] text-slate-500 mt-1 px-1">
                    {new Date(msg.timestamp).toLocaleTimeString([], {
                      hour: '2-digit',
                      minute: '2-digit'
                    })}
                  </span>
                </div>
              </div>
            ))}

            {/* Waiting for response indicator */}
            {isLoading && (
              <div className="flex gap-2.5 items-start">
                <CuteBotAvatar size={24} className="mt-1 shrink-0" />
                <div className="p-3 rounded-2xl bg-slate-900/90 border border-white/10 text-xs text-slate-400 flex items-center gap-2 rounded-tl-sm shadow-md">
                  <span className="text-slate-300">Thinking</span>
                  <span className="flex gap-1">
                    <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce [animation-delay:-0.3s]" />
                    <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce [animation-delay:-0.15s]" />
                    <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce" />
                  </span>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Simple Clean Input Bar like ChatGPT */}
          <div className="p-3 border-t border-white/[0.08] bg-slate-900/70 space-y-2">
            <div className="relative flex items-center bg-slate-950 border border-white/10 focus-within:border-indigo-500/60 rounded-2xl transition-colors">
              <textarea
                ref={textareaRef}
                rows={1}
                disabled={isLoading}
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask BlindSpot anything..."
                className="w-full bg-transparent px-3.5 py-2.5 pr-10 text-xs text-white placeholder-slate-500 focus:outline-none resize-none disabled:opacity-50"
              />

              <button
                disabled={!inputMessage.trim() || isLoading}
                onClick={() => handleSendMessage()}
                className="absolute right-2 w-7 h-7 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-30 disabled:cursor-not-allowed flex items-center justify-center transition-all cursor-pointer shadow-md"
                title="Send Message"
              >
                <ArrowUp className="w-4 h-4" />
              </button>
            </div>

            <p className="text-[10px] text-slate-500 text-center select-none">
              BlindSpot AI can make mistakes. Verify critical security findings.
            </p>
          </div>
        </div>
      )}
    </>
  );
};
