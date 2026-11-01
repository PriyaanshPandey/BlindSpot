import React, { useState, useEffect, useRef } from 'react';
import { Folder, ArrowRight, ChevronDown } from 'lucide-react';

interface LandingPageProps {
  onScanFiles: (projectName: string, files: Record<string, string>) => Promise<void>;
  onScanZip?: (file: File) => Promise<void>;
  onStartScan?: (projectName: string) => void;
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
  onScanZip,
  onStartScan,
  isScanning
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const zipInputRef = useRef<HTMLInputElement>(null);
  const [scanStatusText, setScanStatusText] = useState<string>('');

  // 1. Smooth Scroll Parallax Reaction for Background Video
  const [scrollY, setScrollY] = useState(0);

  useEffect(() => {
    let ticking = false;
    const handleScroll = () => {
      if (!ticking) {
        window.requestAnimationFrame(() => {
          setScrollY(window.scrollY);
          ticking = false;
        });
        ticking = true;
      }
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Compute smooth normalized scroll progress (0 to 1)
  const maxScroll = typeof window !== 'undefined' ? Math.max(window.innerHeight * 0.85, 500) : 600;
  const scrollProgress = Math.min(Math.max(scrollY / maxScroll, 0), 1);

  // Dynamic video transformations on scroll
  const videoScale = 1.08 + scrollProgress * 0.12;
  const videoTranslateY = scrollProgress * 25;
  const videoBrightness = Math.max(0.38, 0.68 - scrollProgress * 0.30);
  const videoBlur = scrollProgress * 7;
  const darkOverlayOpacity = 0.40 + scrollProgress * 0.48;

  // 2. Slow, graceful typewriter for subtitle text (starts with full text, no blank flicker)
  const [textIndex, setTextIndex] = useState(0);
  const [currentText, setCurrentText] = useState(ROTATING_TEXTS[0]);
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    const targetString = ROTATING_TEXTS[textIndex];
    let timeout: any;

    if (!isDeleting) {
      if (currentText.length < targetString.length) {
        timeout = setTimeout(() => {
          setCurrentText(targetString.slice(0, currentText.length + 1));
        }, 70);
      } else {
        timeout = setTimeout(() => {
          setIsDeleting(true);
        }, 3400);
      }
    } else {
      if (currentText.length > 0) {
        timeout = setTimeout(() => {
          setCurrentText(targetString.slice(0, currentText.length - 1));
        }, 30);
      } else {
        timeout = setTimeout(() => {
          setIsDeleting(false);
          setTextIndex((prev) => (prev + 1) % ROTATING_TEXTS.length);
        }, 350);
      }
    }

    return () => clearTimeout(timeout);
  }, [currentText, isDeleting, textIndex]);

  // 3. Synchronized typing animation for 'code' and 'Blindspot'
  const [codeText, setCodeText] = useState('code');
  const [blindspotText, setBlindspotText] = useState('Blindspot');
  const [taglinePhase, setTaglinePhase] = useState<'hold' | 'delete_blindspot' | 'delete_code' | 'pause' | 'type_code' | 'type_blindspot'>('hold');

  useEffect(() => {
    let timeout: any;
    const TARGET_CODE = 'code';
    const TARGET_BLINDSPOT = 'Blindspot';

    if (taglinePhase === 'hold') {
      timeout = setTimeout(() => {
        setTaglinePhase('delete_blindspot');
      }, 4000);
    } else if (taglinePhase === 'delete_blindspot') {
      if (blindspotText.length > 0) {
        timeout = setTimeout(() => {
          setBlindspotText((prev) => prev.slice(0, -1));
        }, 45);
      } else {
        setTaglinePhase('delete_code');
      }
    } else if (taglinePhase === 'delete_code') {
      if (codeText.length > 0) {
        timeout = setTimeout(() => {
          setCodeText((prev) => prev.slice(0, -1));
        }, 50);
      } else {
        timeout = setTimeout(() => {
          setTaglinePhase('type_code');
        }, 400);
      }
    } else if (taglinePhase === 'type_code') {
      if (codeText.length < TARGET_CODE.length) {
        timeout = setTimeout(() => {
          setCodeText(TARGET_CODE.slice(0, codeText.length + 1));
        }, 90);
      } else {
        timeout = setTimeout(() => {
          setTaglinePhase('type_blindspot');
        }, 150);
      }
    } else if (taglinePhase === 'type_blindspot') {
      if (blindspotText.length < TARGET_BLINDSPOT.length) {
        timeout = setTimeout(() => {
          setBlindspotText(TARGET_BLINDSPOT.slice(0, blindspotText.length + 1));
        }, 80);
      } else {
        setTaglinePhase('hold');
      }
    }

    return () => clearTimeout(timeout);
  }, [codeText, blindspotText, taglinePhase]);

  // Folder Upload Handler
  const handleFolderUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

    let detectedProjectName = 'Target-Project';
    const firstPath = fileList[0].webkitRelativePath || '';
    if (firstPath) {
      detectedProjectName = firstPath.split('/')[0] || detectedProjectName;
    }

    // Trigger loading screen immediately
    onStartScan?.(detectedProjectName);
    setScanStatusText('Scanning codebase...');

    const filesToRead: Record<string, string> = {};
    const textExtensions = [
      '.json', '.txt', '.js', '.jsx', '.ts', '.tsx', '.py', '.env', '.yml', '.yaml',
      '.toml', '.mod', '.lock', '.php', '.html', '.css', '.md'
    ];

    let filesProcessed = 0;
    const maxFiles = 1500;

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

      // 25MB for lockfiles, 2MB for source code
      const isLockfile = lowerName.includes('lock') || lowerName.endsWith('.json');
      const sizeLimit = isLockfile ? 25000000 : 2000000;

      if (isTargetFile && file.size < sizeLimit) {
        try {
          const content = await file.text();
          filesToRead[relPath] = content;
          filesProcessed++;
        } catch {
          // skip unreadable
        }
      }
    }

    setScanStatusText('Scanning codebase...');
    await onScanFiles(detectedProjectName, filesToRead);
  };

  const handleZipUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const cleanName = file.name.replace(/\.zip$/i, '');
    onStartScan?.(cleanName);
    setScanStatusText('Scanning codebase archive...');
    if (onScanZip) {
      await onScanZip(file);
    }
  };

  const scrollToFeatures = () => {
    const el = document.getElementById('feature-cards-section');
    el?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="relative min-h-screen w-full bg-[#050204] text-white flex flex-col font-sans selection:bg-purple-600 selection:text-white overflow-x-hidden">
      {/* 1. Scroll-Reactive Background Video */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none z-0">
        <video
          autoPlay
          loop
          muted
          playsInline
          style={{
            transform: `scale(${videoScale}) translateY(${videoTranslateY}px)`,
            filter: `brightness(${videoBrightness}) contrast(1.18) blur(${videoBlur}px)`,
            transition: 'transform 0.15s ease-out, filter 0.2s ease-out'
          }}
          className="w-full h-full object-cover"
        >
          <source src="/herovideo.mp4" type="video/mp4" />
        </video>

        {/* Dynamic Dark Atmosphere Overlay that responds to scroll */}
        <div
          style={{ opacity: darkOverlayOpacity }}
          className="absolute inset-0 bg-[#050204] transition-opacity duration-200"
        />

        {/* Ambient Radial Vignette */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_rgba(120,20,50,0.15)_0%,_rgba(5,2,4,0.65)_50%,_#050204_92%)]" />

        {/* Top & Bottom deep blackout masks to hide edge watermarks */}
        <div className="absolute top-0 left-0 right-0 h-44 bg-gradient-to-b from-[#050204] via-[#050204]/70 to-transparent" />
        <div className="absolute bottom-0 left-0 right-0 h-64 bg-gradient-to-t from-[#050204] via-[#050204]/90 to-transparent" />
      </div>

      {/* 2. Hero Section */}
      <section className="relative z-10 min-h-screen w-full flex flex-col items-center justify-center px-4 sm:px-6 text-center pt-10 pb-20">
        <div className="max-w-4xl mx-auto flex flex-col items-center">
          {/* Subtle architectural kicker badge */}
          <div className="mb-6 inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-white/[0.04] border border-white/10 backdrop-blur-md text-[11px] font-medium tracking-widest uppercase text-slate-300 shadow-sm">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-ping" />
            <span>Dependency Intelligence Platform</span>
          </div>

          {/* Main Brand Title: Clean, modern, high-fashion geometric uppercase */}
          <h1 className="font-sans font-extrabold tracking-[-0.035em] uppercase text-6xl sm:text-7xl md:text-8xl lg:text-[100px] text-white leading-none drop-shadow-[0_10px_35px_rgba(0,0,0,0.85)] mb-5">
            BLINDSPOT
          </h1>

          {/* Balanced Tagline: Pure white text with animated typing on 'code' and 'Blindspot' — Single line */}
          <h2 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl xl:text-[40px] font-semibold text-white tracking-[-0.025em] leading-tight max-w-5xl mx-auto mb-5 sm:whitespace-nowrap">
            You protect your{' '}
            <span className="inline-flex items-center text-emerald-400 font-bold drop-shadow-[0_0_14px_rgba(52,211,153,0.4)]">
              {codeText}
              {(taglinePhase === 'type_code' || taglinePhase === 'delete_code') && (
                <span className="inline-block w-[2px] h-5 sm:h-7 bg-emerald-400 ml-0.5 animate-pulse" />
              )}
            </span>
            , We protect your{' '}
            <span className="inline-flex items-center text-rose-400 font-bold drop-shadow-[0_0_18px_rgba(251,113,133,0.45)]">
              {blindspotText}
              {(taglinePhase === 'type_blindspot' || taglinePhase === 'delete_blindspot') && (
                <span className="inline-block w-[2px] h-5 sm:h-7 bg-rose-400 ml-0.5 animate-pulse" />
              )}
            </span>
            .
          </h2>

          {/* Clean, unboxed rotating subtitle line (no tacky pills or red borders) */}
          <div className="h-8 flex items-center justify-center mb-10">
            <p className="text-sm sm:text-base md:text-lg text-slate-300 font-normal tracking-wide">
              {currentText}
              <span className="inline-block w-[1.5px] h-4 bg-white/70 ml-1.5 align-middle animate-pulse" />
            </p>
          </div>

          {/* Upload Buttons: Folder or ZIP Archive */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3.5">
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
            <input
              type="file"
              ref={zipInputRef}
              onChange={handleZipUpload}
              accept=".zip"
              className="hidden"
            />

            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={isScanning}
              className="group relative inline-flex items-center justify-center px-7 py-3.5 text-base sm:text-lg font-semibold tracking-wide text-white transition-all duration-300 ease-out rounded-full bg-gradient-to-r from-violet-600 via-purple-600 to-indigo-600 hover:from-violet-500 hover:via-purple-500 hover:to-indigo-500 shadow-[0_0_35px_rgba(147,51,234,0.5)] hover:shadow-[0_0_60px_rgba(168,85,247,0.85)] hover:scale-105 active:scale-95 border border-purple-300/40 cursor-pointer disabled:opacity-50"
            >
              {isScanning ? (
                <div className="flex items-center gap-3">
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>{scanStatusText || 'Analyzing Codebase...'}</span>
                </div>
              ) : (
                <div className="flex items-center gap-2.5">
                  <Folder className="w-5 h-5 text-purple-200 group-hover:scale-110 transition-transform duration-200" />
                  <span>Upload Folder</span>
                  <ArrowRight className="w-4 h-4 text-purple-200 group-hover:translate-x-1 transition-transform duration-200" />
                </div>
              )}
            </button>

            <button
              onClick={() => zipInputRef.current?.click()}
              disabled={isScanning}
              className="group relative inline-flex items-center justify-center px-6 py-3.5 text-base sm:text-lg font-semibold tracking-wide text-zinc-200 hover:text-white transition-all duration-300 ease-out rounded-full bg-zinc-950/90 hover:bg-zinc-900 border border-zinc-700/80 shadow-[0_0_25px_rgba(0,0,0,0.6)] hover:scale-105 active:scale-95 cursor-pointer disabled:opacity-50"
            >
              <div className="flex items-center gap-2">
                <span>Upload .ZIP Archive</span>
              </div>
            </button>
          </div>
        </div>

        {/* Subtle scroll cue */}
        <button
          onClick={scrollToFeatures}
          className="absolute bottom-6 flex flex-col items-center gap-1 text-slate-400 hover:text-white transition-colors cursor-pointer group"
        >
          <span className="text-[11px] tracking-wider uppercase font-medium text-slate-400 group-hover:text-purple-300">
            Explore Capabilities
          </span>
          <ChevronDown className="w-4 h-4 animate-bounce text-purple-300" />
        </button>
      </section>

      {/* 3. Feature Cards Section: 2 Box Side by Side, Then 2 Box, Title Texts Only (Screenshot 2 Style) */}
      <section id="feature-cards-section" className="relative z-10 w-full max-w-6xl mx-auto px-6 pt-8 pb-36">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-7 lg:gap-8">
          {/* Card 1 */}
          <div className="group relative rounded-[24px] p-[1.5px] bg-gradient-to-r from-blue-500/70 via-purple-500/50 to-pink-500/70 transition-all duration-500 hover:from-blue-400 hover:to-pink-400 hover:shadow-[0_0_45px_rgba(168,85,247,0.4)] hover:-translate-y-1">
            <div className="h-full w-full rounded-[23px] bg-[#09040a]/85 backdrop-blur-2xl p-8 sm:p-11 flex items-center min-h-[170px]">
              <h3 className="text-2xl sm:text-[27px] md:text-[30px] font-semibold text-white tracking-[-0.02em] leading-snug group-hover:text-purple-100 transition-colors">
                Map every dependency in your codebase.
              </h3>
            </div>
          </div>

          {/* Card 2 */}
          <div className="group relative rounded-[24px] p-[1.5px] bg-gradient-to-r from-purple-500/70 via-rose-500/50 to-amber-500/70 transition-all duration-500 hover:from-purple-400 hover:to-amber-400 hover:shadow-[0_0_45px_rgba(244,63,94,0.4)] hover:-translate-y-1">
            <div className="h-full w-full rounded-[23px] bg-[#09040a]/85 backdrop-blur-2xl p-8 sm:p-11 flex items-center min-h-[170px]">
              <h3 className="text-2xl sm:text-[27px] md:text-[30px] font-semibold text-white tracking-[-0.02em] leading-snug group-hover:text-rose-100 transition-colors">
                Detect live vulnerabilities and package outages.
              </h3>
            </div>
          </div>

          {/* Card 3 */}
          <div className="group relative rounded-[24px] p-[1.5px] bg-gradient-to-r from-cyan-500/70 via-blue-500/50 to-violet-500/70 transition-all duration-500 hover:from-cyan-400 hover:to-violet-400 hover:shadow-[0_0_45px_rgba(59,130,246,0.4)] hover:-translate-y-1">
            <div className="h-full w-full rounded-[23px] bg-[#09040a]/85 backdrop-blur-2xl p-8 sm:p-11 flex items-center min-h-[170px]">
              <h3 className="text-2xl sm:text-[27px] md:text-[30px] font-semibold text-white tracking-[-0.02em] leading-snug group-hover:text-blue-100 transition-colors">
                Simulate dependency failures and see what breaks.
              </h3>
            </div>
          </div>

          {/* Card 4 */}
          <div className="group relative rounded-[24px] p-[1.5px] bg-gradient-to-r from-rose-500/70 via-pink-500/50 to-purple-500/70 transition-all duration-500 hover:from-rose-400 hover:to-purple-400 hover:shadow-[0_0_45px_rgba(236,72,153,0.4)] hover:-translate-y-1">
            <div className="h-full w-full rounded-[23px] bg-[#09040a]/85 backdrop-blur-2xl p-8 sm:p-11 flex items-center min-h-[170px]">
              <h3 className="text-2xl sm:text-[27px] md:text-[30px] font-semibold text-white tracking-[-0.02em] leading-snug group-hover:text-pink-100 transition-colors">
                Uncover hidden risks across third-party dependencies.
              </h3>
            </div>
          </div>
        </div>
      </section>

      {/* 4. Footer */}
      <footer className="relative z-10 w-full border-t border-white/[0.06] py-10 px-6 text-center">
        <p className="text-xs sm:text-sm text-slate-500 font-medium tracking-wide">
          Made by <span className="text-slate-300 font-semibold hover:text-white transition-colors">Complexity Crushers</span>
        </p>
      </footer>
    </div>
  );
};
