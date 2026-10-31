import React, { useState, useEffect, useRef } from 'react';
import { Folder, ArrowRight, ShieldAlert, Network, Flame, ShieldCheck, ChevronDown, Sparkles } from 'lucide-react';

interface LandingPageProps {
  onScanFiles: (projectName: string, files: Record<string, string>) => Promise<void>;
  isScanning: boolean;
}

const ROTATING_TEXTS = [
  "Your code stays on your machine.",
  "Discover hidden dependencies and connections.",
  "See what breaks when a dependency fails.",
  "Find the risks hiding in your codebase."
];

export const LandingPage: React.FC<LandingPageProps> = ({
  onScanFiles,
  isScanning
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [scanStatusText, setScanStatusText] = useState<string>('');

  // Slow, premium typewriter for rotating subtitle texts
  const [textIndex, setTextIndex] = useState(0);
  const [currentText, setCurrentText] = useState('');
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    const targetString = ROTATING_TEXTS[textIndex];
    let timeout: any;

    if (!isDeleting) {
      if (currentText.length < targetString.length) {
        // Slow and deliberate typing speed
        timeout = setTimeout(() => {
          setCurrentText(targetString.slice(0, currentText.length + 1));
        }, 85);
      } else {
        // Long, comfortable reading pause
        timeout = setTimeout(() => {
          setIsDeleting(true);
        }, 3600);
      }
    } else {
      if (currentText.length > 0) {
        // Smooth deleting
        timeout = setTimeout(() => {
          setCurrentText(targetString.slice(0, currentText.length - 1));
        }, 40);
      } else {
        // Pause before typing next
        timeout = setTimeout(() => {
          setIsDeleting(false);
          setTextIndex((prev) => (prev + 1) % ROTATING_TEXTS.length);
        }, 450);
      }
    }

    return () => clearTimeout(timeout);
  }, [currentText, isDeleting, textIndex]);

  // Folder Upload Handler
  const handleFolderUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

    setScanStatusText('Reading codebase files locally...');
    let detectedProjectName = 'Target-Project';
    const firstPath = fileList[0].webkitRelativePath || '';
    if (firstPath) {
      detectedProjectName = firstPath.split('/')[0] || detectedProjectName;
    }

    const filesToRead: Record<string, string> = {};
    const textExtensions = [
      '.json', '.txt', '.js', '.jsx', '.ts', '.tsx', '.py', '.env', '.yml', '.yaml',
      '.toml', '.mod', '.lock', '.php', '.html', '.css', '.md'
    ];

    let filesProcessed = 0;
    const maxFiles = 300;

    for (let i = 0; i < fileList.length && filesProcessed < maxFiles; i++) {
      const file = fileList[i];
      const relPath = file.webkitRelativePath || file.name;

      if (
        relPath.includes('node_modules/') ||
        relPath.includes('.git/') ||
        relPath.includes('dist/') ||
        relPath.includes('build/') ||
        relPath.includes('.venv/') ||
        relPath.includes('__pycache__/')
      ) {
        continue;
      }

      const lowerName = file.name.toLowerCase();
      const isTargetFile =
        textExtensions.some((ext) => lowerName.endsWith(ext)) ||
        lowerName.startsWith('.env') ||
        lowerName === 'dockerfile';

      if (isTargetFile && file.size < 600000) {
        try {
          const content = await file.text();
          filesToRead[relPath] = content;
          filesProcessed++;
        } catch {
          // Skip binary
        }
      }
    }

    setScanStatusText('Analyzing topology & live Google OSV queries...');
    await onScanFiles(detectedProjectName, filesToRead);
  };

  const scrollToCards = () => {
    const el = document.getElementById('features-section');
    el?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="relative min-h-screen w-full bg-[#060204] text-white flex flex-col font-heading selection:bg-rose-600 selection:text-white overflow-x-hidden">
      {/* 1. Infinite Video Background with Reddish Dark Theme Vignette & Watermark Mask */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none z-0">
        <video
          autoPlay
          loop
          muted
          playsInline
          className="w-full h-full object-cover scale-[1.14] translate-y-[-1%] filter brightness-[0.62] contrast-[1.22] saturate-[1.12]"
        >
          <source src="/herovideo.mp4" type="video/mp4" />
        </video>

        {/* Modern Reddish Ambient Nebula & Radial Glow */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_rgba(225,29,72,0.18)_0%,_rgba(15,3,8,0.76)_55%,_#060204_94%)]" />

        {/* Top Vignette (Deep dark red-black fade) */}
        <div className="absolute top-0 left-0 right-0 h-48 bg-gradient-to-b from-[#060204] via-[#060204]/75 to-transparent" />

        {/* Bottom Edge Mask (Completely covers any corner logo/watermark) */}
        <div className="absolute bottom-0 left-0 right-0 h-64 bg-gradient-to-t from-[#060204] via-[#060204]/85 to-transparent" />

        {/* Ultra-subtle grid lines */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#ffffff04_1px,transparent_1px),linear-gradient(to_bottom,#ffffff04_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)]" />
      </div>

      {/* 2. Hero Section (Direct texts & button, no top bar) */}
      <section className="relative z-10 min-h-screen w-full flex flex-col items-center justify-center px-4 sm:px-6 text-center pt-8 pb-16">
        <div className="max-w-5xl mx-auto flex flex-col items-center">
          {/* Big Font Heading — Inspired by Screenshot 1 (Ultra-bold, geometric, uppercase) */}
          <div className="relative group mb-5">
            <div className="absolute -inset-3 bg-gradient-to-r from-red-600/30 via-rose-600/40 to-amber-600/25 rounded-3xl blur-3xl opacity-75 group-hover:opacity-100 transition duration-1000" />
            <h1 className="relative font-heading font-black tracking-tight uppercase text-6xl sm:text-7xl md:text-8xl lg:text-9xl text-white drop-shadow-[0_4px_35px_rgba(239,68,68,0.4)]">
              BLINDSPOT
            </h1>
          </div>

          {/* Solid Tagline (Font like Screenshot 2 card headings with distinct colors for code and Blindspot) */}
          <h2 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl font-bold tracking-tight text-slate-100 mb-6 drop-shadow-sm max-w-3xl leading-snug">
            You protect your{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400 font-extrabold drop-shadow-[0_0_16px_rgba(52,211,153,0.4)]">
              code
            </span>
            , We protect your{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-rose-500 via-red-500 to-amber-500 font-black drop-shadow-[0_0_20px_rgba(244,63,94,0.65)]">
              Blindspot
            </span>
            .
          </h2>

          {/* Rotating Value Propositions (Slow, readable, premium typewriter in dedicated glowing capsule) */}
          <div className="h-12 flex items-center justify-center mb-10 px-4">
            <div className="flex items-center gap-2.5 px-6 py-2 rounded-full bg-black/60 border border-rose-500/35 backdrop-blur-md shadow-[0_0_25px_rgba(244,63,94,0.2)]">
              <Sparkles className="w-4 h-4 text-rose-400 shrink-0 animate-pulse" />
              <span className="text-sm sm:text-base font-medium text-slate-200 tracking-wide">
                {currentText}
              </span>
              <span className="inline-block w-1.5 h-4 bg-rose-400 ml-0.5 animate-pulse shadow-[0_0_8px_#f43f5e]" />
            </div>
          </div>

          {/* Upload Codebase CTA Button (Inspired by Screenshot 1 pill button with glowing reddish/neon stroke) */}
          <div className="flex flex-col items-center">
            {/* Hidden native directory input */}
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFolderUpload}
              // @ts-ignore
              webkitdirectory=""
              directory=""
              multiple
              className="hidden"
            />

            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={isScanning}
              className="group relative inline-flex items-center justify-center px-10 py-4.5 text-base sm:text-lg font-bold tracking-wide text-white transition-all duration-300 ease-out rounded-full bg-black/80 hover:bg-black/90 border border-rose-500/70 hover:border-rose-400 shadow-[0_0_30px_rgba(244,63,94,0.35)] hover:shadow-[0_0_55px_rgba(244,63,94,0.7)] hover:scale-105 active:scale-95 cursor-pointer disabled:opacity-50"
            >
              {/* Subtle inner ambient pulse */}
              <div className="absolute inset-0 rounded-full bg-gradient-to-r from-rose-600/20 to-red-600/20 opacity-0 group-hover:opacity-100 transition-opacity" />

              {isScanning ? (
                <div className="flex items-center gap-3 relative z-10">
                  <div className="w-5 h-5 border-2 border-white/30 border-t-rose-400 rounded-full animate-spin" />
                  <span>{scanStatusText || 'Analyzing Codebase...'}</span>
                </div>
              ) : (
                <div className="flex items-center gap-3 relative z-10">
                  <Folder className="w-5 h-5 text-rose-300 group-hover:scale-110 transition-transform duration-200" />
                  <span>Upload Codebase</span>
                  <ArrowRight className="w-4 h-4 text-rose-300 group-hover:translate-x-1.5 transition-transform duration-200" />
                </div>
              )}
            </button>

            {/* Privacy indicator */}
            <div className="mt-8 flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-black/50 border border-slate-800/80 backdrop-blur-sm text-xs text-slate-400">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>100% Client-Side Privacy — Your code never leaves your computer</span>
            </div>
          </div>
        </div>

        {/* Scroll indicator pointing to feature cards */}
        <button
          onClick={scrollToCards}
          className="absolute bottom-6 flex flex-col items-center gap-1.5 text-slate-400 hover:text-white transition-colors cursor-pointer group"
        >
          <span className="text-xs tracking-wider uppercase font-semibold text-slate-400 group-hover:text-rose-300">
            Explore Capabilities
          </span>
          <ChevronDown className="w-5 h-5 animate-bounce text-rose-400" />
        </button>
      </section>

      {/* 3. Big Feature Cards Section (After scroll, inspired by Screenshot 2) */}
      <section id="features-section" className="relative z-10 w-full max-w-7xl mx-auto px-6 py-24 sm:py-32">
        {/* Section Title */}
        <div className="text-center mb-16 sm:mb-20">
          <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs font-bold tracking-widest uppercase mb-4">
            <Sparkles className="w-3.5 h-3.5" />
            Dependency Intelligence Platform
          </div>
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-black tracking-tight text-white max-w-3xl mx-auto">
            Everything your dependency tree is hiding, made visible.
          </h2>
          <p className="mt-4 text-base sm:text-lg text-slate-300 max-w-2xl mx-auto">
            Bridge the gap between what you think your architecture is and what your codebase actually communicates with.
          </p>
        </div>

        {/* 4 Big Premium Cards Grid with Screenshot 2 Glowing Borders */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 lg:gap-8">
          {/* Card 1: Map every dependency */}
          <div className="group relative rounded-3xl p-[1.5px] bg-gradient-to-r from-rose-500/60 via-red-500/40 to-purple-600/60 transition-all duration-500 hover:from-rose-500 hover:via-red-500 hover:to-purple-500 hover:shadow-[0_0_40px_rgba(244,63,94,0.35)] hover:-translate-y-1.5">
            <div className="h-full w-full rounded-3xl bg-[#090306]/90 backdrop-blur-xl p-8 sm:p-10 flex flex-col justify-between">
              <div>
                <div className="w-12 h-12 rounded-2xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 mb-6 group-hover:scale-110 group-hover:bg-rose-500/20 transition-all">
                  <Network className="w-6 h-6" />
                </div>
                <h3 className="text-2xl sm:text-3xl font-bold text-white tracking-tight mb-4 group-hover:text-rose-100 transition-colors">
                  Map every dependency in your codebase.
                </h3>
                <p className="text-slate-300 text-base leading-relaxed">
                  Deep recursive manifest parsing and code AST inspection across npm, PyPI, Go, and monorepos to generate an evidence-backed topology of direct, transitive, and deployed components.
                </p>
              </div>
              <div className="mt-8 pt-6 border-t border-white/5 flex items-center justify-between text-xs font-semibold text-rose-300">
                <span>FULL TOPOLOGY ENGINE</span>
                <span>01</span>
              </div>
            </div>
          </div>

          {/* Card 2: Detect live vulnerabilities */}
          <div className="group relative rounded-3xl p-[1.5px] bg-gradient-to-r from-red-500/60 via-orange-500/40 to-pink-500/60 transition-all duration-500 hover:from-red-500 hover:via-orange-500 hover:to-pink-500 hover:shadow-[0_0_40px_rgba(239,68,68,0.35)] hover:-translate-y-1.5">
            <div className="h-full w-full rounded-3xl bg-[#090306]/90 backdrop-blur-xl p-8 sm:p-10 flex flex-col justify-between">
              <div>
                <div className="w-12 h-12 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400 mb-6 group-hover:scale-110 group-hover:bg-red-500/20 transition-all">
                  <ShieldAlert className="w-6 h-6" />
                </div>
                <h3 className="text-2xl sm:text-3xl font-bold text-white tracking-tight mb-4 group-hover:text-red-100 transition-colors">
                  Detect live vulnerabilities and package outages.
                </h3>
                <p className="text-slate-300 text-base leading-relaxed">
                  Live concurrent queries against Google's OSV advisory database to flag active CVEs, supply-chain exploits, GHSA advisories, and malicious releases with zero stale caches.
                </p>
              </div>
              <div className="mt-8 pt-6 border-t border-white/5 flex items-center justify-between text-xs font-semibold text-red-300">
                <span>GOOGLE OSV REAL-TIME SYNC</span>
                <span>02</span>
              </div>
            </div>
          </div>

          {/* Card 3: Simulate dependency failures */}
          <div className="group relative rounded-3xl p-[1.5px] bg-gradient-to-r from-purple-500/60 via-violet-500/40 to-blue-500/60 transition-all duration-500 hover:from-purple-500 hover:via-violet-500 hover:to-blue-500 hover:shadow-[0_0_40px_rgba(168,85,247,0.35)] hover:-translate-y-1.5">
            <div className="h-full w-full rounded-3xl bg-[#090306]/90 backdrop-blur-xl p-8 sm:p-10 flex flex-col justify-between">
              <div>
                <div className="w-12 h-12 rounded-2xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400 mb-6 group-hover:scale-110 group-hover:bg-purple-500/20 transition-all">
                  <Flame className="w-6 h-6" />
                </div>
                <h3 className="text-2xl sm:text-3xl font-bold text-white tracking-tight mb-4 group-hover:text-purple-100 transition-colors">
                  Simulate dependency failures and see what breaks.
                </h3>
                <p className="text-slate-300 text-base leading-relaxed">
                  Calculate blast-radius propagation across internal microservices and critical business operations to forecast revenue loss, downtime impact, and cascading failure paths before outages strike.
                </p>
              </div>
              <div className="mt-8 pt-6 border-t border-white/5 flex items-center justify-between text-xs font-semibold text-purple-300">
                <span>BLAST RADIUS & FINANCIAL IMPACT</span>
                <span>03</span>
              </div>
            </div>
          </div>

          {/* Card 4: Uncover hidden risks */}
          <div className="group relative rounded-3xl p-[1.5px] bg-gradient-to-r from-cyan-500/60 via-rose-500/40 to-amber-500/60 transition-all duration-500 hover:from-cyan-500 hover:via-rose-500 hover:to-amber-500 hover:shadow-[0_0_40px_rgba(6,182,212,0.35)] hover:-translate-y-1.5">
            <div className="h-full w-full rounded-3xl bg-[#090306]/90 backdrop-blur-xl p-8 sm:p-10 flex flex-col justify-between">
              <div>
                <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-6 group-hover:scale-110 group-hover:bg-cyan-500/20 transition-all">
                  <ShieldCheck className="w-6 h-6" />
                </div>
                <h3 className="text-2xl sm:text-3xl font-bold text-white tracking-tight mb-4 group-hover:text-cyan-100 transition-colors">
                  Uncover hidden risks across third-party dependencies.
                </h3>
                <p className="text-slate-300 text-base leading-relaxed">
                  Intercept undocumented shadow APIs, unapproved external telemetry beacons, and cloud credentials that bypass architectural governance or formal security audits.
                </p>
              </div>
              <div className="mt-8 pt-6 border-t border-white/5 flex items-center justify-between text-xs font-semibold text-cyan-300">
                <span>SHADOW DEPENDENCY DISCOVERY</span>
                <span>04</span>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom CTA to upload */}
        <div className="mt-20 text-center flex flex-col items-center">
          <button
            onClick={() => {
              window.scrollTo({ top: 0, behavior: 'smooth' });
              setTimeout(() => fileInputRef.current?.click(), 400);
            }}
            className="inline-flex items-center gap-3 px-8 py-4 rounded-full bg-rose-600 hover:bg-rose-500 text-white font-bold text-base shadow-[0_0_30px_rgba(244,63,94,0.4)] hover:shadow-[0_0_45px_rgba(244,63,94,0.7)] transition-all cursor-pointer"
          >
            <Folder className="w-5 h-5" />
            <span>Select Local Project to Analyze</span>
          </button>
        </div>
      </section>
    </div>
  );
};
