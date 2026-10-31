import React, { useState, useEffect, useRef } from 'react';
import { Folder, ArrowRight } from 'lucide-react';

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

  // Slow, smooth, premium typewriter for subtitle text
  const [textIndex, setTextIndex] = useState(0);
  const [currentText, setCurrentText] = useState('');
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    const targetString = ROTATING_TEXTS[textIndex];
    let timeout: any;

    if (!isDeleting) {
      if (currentText.length < targetString.length) {
        timeout = setTimeout(() => {
          setCurrentText(targetString.slice(0, currentText.length + 1));
        }, 75);
      } else {
        timeout = setTimeout(() => {
          setIsDeleting(true);
        }, 3400);
      }
    } else {
      if (currentText.length > 0) {
        timeout = setTimeout(() => {
          setCurrentText(targetString.slice(0, currentText.length - 1));
        }, 35);
      } else {
        timeout = setTimeout(() => {
          setIsDeleting(false);
          setTextIndex((prev) => (prev + 1) % ROTATING_TEXTS.length);
        }, 400);
      }
    }

    return () => clearTimeout(timeout);
  }, [currentText, isDeleting, textIndex]);

  // Folder Upload Handler
  const handleFolderUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

    setScanStatusText('Reading codebase...');
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
          // skip unreadable
        }
      }
    }

    setScanStatusText('Analyzing topology & live Google OSV advisories...');
    await onScanFiles(detectedProjectName, filesToRead);
  };

  return (
    <div className="relative min-h-screen w-full bg-[#050204] text-white flex flex-col font-heading selection:bg-purple-600 selection:text-white overflow-x-hidden">
      {/* 1. Infinite Video Background with Deep Contrast & Watermark Mask */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none z-0">
        <video
          autoPlay
          loop
          muted
          playsInline
          className="w-full h-full object-cover scale-[1.12] translate-y-[-1%] filter brightness-[0.70] contrast-[1.20]"
        >
          <source src="/herovideo.mp4" type="video/mp4" />
        </video>

        {/* Ambient deep dark vignette */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_rgba(120,20,50,0.14)_0%,_rgba(6,2,5,0.72)_55%,_#050204_95%)]" />

        {/* Top & Bottom deep blackout masks to hide edge watermarks */}
        <div className="absolute top-0 left-0 right-0 h-44 bg-gradient-to-b from-[#050204] via-[#050204]/70 to-transparent" />
        <div className="absolute bottom-0 left-0 right-0 h-60 bg-gradient-to-t from-[#050204] via-[#050204]/85 to-transparent" />
      </div>

      {/* 2. Hero Section */}
      <section className="relative z-10 min-h-screen w-full flex flex-col items-center justify-center px-4 sm:px-6 text-center pt-12 pb-24">
        <div className="max-w-5xl mx-auto flex flex-col items-center">
          {/* Main Title: Massive, bold, crisp white uppercase */}
          <h1 className="font-heading font-black tracking-tight uppercase text-6xl sm:text-7xl md:text-8xl lg:text-9xl text-white drop-shadow-[0_4px_30px_rgba(255,255,255,0.25)] mb-4">
            BLINDSPOT
          </h1>

          {/* Tagline: Large, authoritative font with clean color accents */}
          <h2 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl font-extrabold tracking-tight text-white mb-6 leading-tight drop-shadow-md max-w-4xl">
            You protect your{' '}
            <span className="text-emerald-400 font-black drop-shadow-[0_0_20px_rgba(52,211,153,0.4)]">
              code
            </span>
            , We protect your{' '}
            <span className="text-rose-500 font-black drop-shadow-[0_0_25px_rgba(244,63,94,0.5)]">
              Blindspot
            </span>
            .
          </h2>

          {/* Clean, unboxed rotating text below without tacky borders or pills */}
          <div className="h-10 flex items-center justify-center mb-12">
            <p className="text-lg sm:text-xl md:text-2xl font-medium text-slate-300 tracking-wide">
              {currentText}
              <span className="inline-block w-0.5 h-5 sm:h-6 bg-white/80 ml-2 align-middle animate-pulse" />
            </p>
          </div>

          {/* 3. The Earlier Favorite "Upload Codebase" Button */}
          <div className="flex flex-col items-center">
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
              className="group relative inline-flex items-center justify-center px-10 py-4.5 text-base sm:text-lg font-bold tracking-wide text-white transition-all duration-300 ease-out rounded-full bg-gradient-to-r from-violet-600 via-purple-600 to-indigo-600 hover:from-violet-500 hover:via-purple-500 hover:to-indigo-500 shadow-[0_0_35px_rgba(147,51,234,0.5)] hover:shadow-[0_0_60px_rgba(168,85,247,0.85)] hover:scale-105 active:scale-95 border border-purple-300/40 cursor-pointer disabled:opacity-50"
            >
              {isScanning ? (
                <div className="flex items-center gap-3">
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>{scanStatusText || 'Analyzing Codebase...'}</span>
                </div>
              ) : (
                <div className="flex items-center gap-3">
                  <Folder className="w-5 h-5 text-purple-200 group-hover:scale-110 transition-transform duration-200" />
                  <span>Upload Codebase</span>
                  <ArrowRight className="w-4 h-4 text-purple-200 group-hover:translate-x-1.5 transition-transform duration-200" />
                </div>
              )}
            </button>
          </div>
        </div>
      </section>

      {/* 4. Feature Cards Section: 2 by 2 Grid, Only Title Texts, Screenshot 2 Style Glowing Borders */}
      <section className="relative z-10 w-full max-w-6xl mx-auto px-6 pb-32">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 lg:gap-10">
          {/* Card 1 */}
          <div className="group relative rounded-3xl p-[1.5px] bg-gradient-to-r from-blue-500/70 via-purple-500/50 to-pink-500/70 transition-all duration-500 hover:from-blue-400 hover:to-pink-400 hover:shadow-[0_0_45px_rgba(168,85,247,0.4)] hover:-translate-y-1.5">
            <div className="h-full w-full rounded-3xl bg-[#090408]/90 backdrop-blur-xl p-10 sm:p-14 flex items-center justify-center text-center min-h-[220px]">
              <h3 className="text-2xl sm:text-3xl md:text-4xl font-extrabold text-white tracking-tight leading-snug group-hover:text-purple-100 transition-colors">
                Map every dependency in your codebase.
              </h3>
            </div>
          </div>

          {/* Card 2 */}
          <div className="group relative rounded-3xl p-[1.5px] bg-gradient-to-r from-purple-500/70 via-rose-500/50 to-amber-500/70 transition-all duration-500 hover:from-purple-400 hover:to-amber-400 hover:shadow-[0_0_45px_rgba(244,63,94,0.4)] hover:-translate-y-1.5">
            <div className="h-full w-full rounded-3xl bg-[#090408]/90 backdrop-blur-xl p-10 sm:p-14 flex items-center justify-center text-center min-h-[220px]">
              <h3 className="text-2xl sm:text-3xl md:text-4xl font-extrabold text-white tracking-tight leading-snug group-hover:text-rose-100 transition-colors">
                Detect live vulnerabilities and package outages.
              </h3>
            </div>
          </div>

          {/* Card 3 */}
          <div className="group relative rounded-3xl p-[1.5px] bg-gradient-to-r from-cyan-500/70 via-blue-500/50 to-violet-500/70 transition-all duration-500 hover:from-cyan-400 hover:to-violet-400 hover:shadow-[0_0_45px_rgba(59,130,246,0.4)] hover:-translate-y-1.5">
            <div className="h-full w-full rounded-3xl bg-[#090408]/90 backdrop-blur-xl p-10 sm:p-14 flex items-center justify-center text-center min-h-[220px]">
              <h3 className="text-2xl sm:text-3xl md:text-4xl font-extrabold text-white tracking-tight leading-snug group-hover:text-blue-100 transition-colors">
                Simulate dependency failures and see what breaks.
              </h3>
            </div>
          </div>

          {/* Card 4 */}
          <div className="group relative rounded-3xl p-[1.5px] bg-gradient-to-r from-rose-500/70 via-pink-500/50 to-purple-500/70 transition-all duration-500 hover:from-rose-400 hover:to-purple-400 hover:shadow-[0_0_45px_rgba(236,72,153,0.4)] hover:-translate-y-1.5">
            <div className="h-full w-full rounded-3xl bg-[#090408]/90 backdrop-blur-xl p-10 sm:p-14 flex items-center justify-center text-center min-h-[220px]">
              <h3 className="text-2xl sm:text-3xl md:text-4xl font-extrabold text-white tracking-tight leading-snug group-hover:text-pink-100 transition-colors">
                Uncover hidden risks across third-party dependencies.
              </h3>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};
