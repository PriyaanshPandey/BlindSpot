import React, { useState, useEffect, useRef } from 'react';
import { UploadCloud, Folder, Sparkles, ArrowRight, ShieldCheck, CheckCircle2 } from 'lucide-react';

interface LandingPageProps {
  onScanFiles: (projectName: string, files: Record<string, string>) => Promise<void>;
  onExplorePreset: (path: string) => Promise<void>;
  isScanning: boolean;
}

const ROTATING_TEXTS = [
  "Your code stays on your machine.",
  "Discover hidden dependencies and connections.",
  "See what breaks when a dependency fails.",
  "Find the risks hiding in your codebase."
];

const TAGLINE = "you protect your code we protect your blindspot.";

export const LandingPage: React.FC<LandingPageProps> = ({
  onScanFiles,
  onExplorePreset,
  isScanning
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [scanStatusText, setScanStatusText] = useState<string>('');

  // 1. Tagline Typewriter State (Continuously types in and out)
  const [taglineText, setTaglineText] = useState('');
  const [isTaglineDeleting, setIsTaglineDeleting] = useState(false);

  useEffect(() => {
    let timeout: any;

    if (!isTaglineDeleting) {
      if (taglineText.length < TAGLINE.length) {
        timeout = setTimeout(() => {
          setTaglineText(TAGLINE.slice(0, taglineText.length + 1));
        }, 55);
      } else {
        // Pause at full text before deleting
        timeout = setTimeout(() => {
          setIsTaglineDeleting(true);
        }, 2400);
      }
    } else {
      if (taglineText.length > 0) {
        timeout = setTimeout(() => {
          setTaglineText(TAGLINE.slice(0, taglineText.length - 1));
        }, 30);
      } else {
        // Pause before typing again
        timeout = setTimeout(() => {
          setIsTaglineDeleting(false);
        }, 500);
      }
    }

    return () => clearTimeout(timeout);
  }, [taglineText, isTaglineDeleting]);

  // 2. Rotating Subtitle Typewriter State (Types in, pauses, types out, switches to next)
  const [textIndex, setTextIndex] = useState(0);
  const [currentText, setCurrentText] = useState('');
  const [isRotatingDeleting, setIsRotatingDeleting] = useState(false);

  useEffect(() => {
    const targetString = ROTATING_TEXTS[textIndex];
    let timeout: any;

    if (!isRotatingDeleting) {
      if (currentText.length < targetString.length) {
        timeout = setTimeout(() => {
          setCurrentText(targetString.slice(0, currentText.length + 1));
        }, 45);
      } else {
        timeout = setTimeout(() => {
          setIsRotatingDeleting(true);
        }, 2200);
      }
    } else {
      if (currentText.length > 0) {
        timeout = setTimeout(() => {
          setCurrentText(targetString.slice(0, currentText.length - 1));
        }, 25);
      } else {
        timeout = setTimeout(() => {
          setIsRotatingDeleting(false);
          setTextIndex((prev) => (prev + 1) % ROTATING_TEXTS.length);
        }, 350);
      }
    }

    return () => clearTimeout(timeout);
  }, [currentText, isRotatingDeleting, textIndex]);

  // Folder Upload Handler
  const handleFolderUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

    setScanStatusText('Reading codebase files...');
    let detectedProjectName = 'Uploaded-Project';
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
          // Skip binary/unreadable
        }
      }
    }

    setScanStatusText('Discovering architecture and querying Google OSV...');
    await onScanFiles(detectedProjectName, filesToRead);
  };

  return (
    <div className="relative min-h-screen w-full bg-[#05050B] text-white flex flex-col items-center justify-center overflow-hidden select-none font-sans">
      {/* 1. Infinite Video Background with Vignette & Crop (Completely hides Gemini logo & watermarks) */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none z-0">
        <video
          autoPlay
          loop
          muted
          playsInline
          className="w-full h-full object-cover scale-[1.12] translate-y-[-1%] filter brightness-[0.72] contrast-[1.15]"
        >
          <source src="/herovideo.mp4" type="video/mp4" />
        </video>

        {/* Multi-layered dark ambient vignette inspired by the dark neon reference */}
        {/* Radial center highlight with deep purple ambient glow */}
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_rgba(147,51,234,0.15)_0%,_rgba(5,5,11,0.65)_55%,_#05050B_92%)]" />

        {/* Top mask */}
        <div className="absolute top-0 left-0 right-0 h-44 bg-gradient-to-b from-[#05050B] via-[#05050B]/70 to-transparent" />

        {/* Bottom edge deep blackout mask (covers bottom corner watermarks completely) */}
        <div className="absolute bottom-0 left-0 right-0 h-56 bg-gradient-to-t from-[#05050B] via-[#05050B]/85 to-transparent" />

        {/* Subtle grid pattern accent overlay */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#ffffff05_1px,transparent_1px),linear-gradient(to_bottom,#ffffff05_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)]" />
      </div>

      {/* 2. Main Centered Hero Content */}
      <main className="relative z-10 flex flex-col items-center text-center px-4 max-w-4xl mx-auto my-auto">
        {/* Big Font Brand Title */}
        <div className="relative group mb-3">
          {/* Subtle neon glow under text */}
          <div className="absolute -inset-2 bg-gradient-to-r from-purple-600/30 via-violet-500/40 to-fuchsia-600/30 rounded-3xl blur-2xl opacity-75 group-hover:opacity-100 transition duration-1000 group-hover:duration-200" />
          <h1 className="relative text-6xl sm:text-7xl md:text-8xl lg:text-9xl font-extrabold tracking-tight bg-gradient-to-b from-white via-slate-100 to-purple-300 bg-clip-text text-transparent drop-shadow-[0_0_40px_rgba(168,85,247,0.35)]">
            BlindSpot
          </h1>
        </div>

        {/* Tagline: Continuously typed in and out */}
        <div className="h-10 sm:h-12 flex items-center justify-center mb-6">
          <p className="text-lg sm:text-2xl md:text-3xl font-medium tracking-wide bg-gradient-to-r from-purple-200 via-violet-300 to-fuchsia-200 bg-clip-text text-transparent drop-shadow-sm">
            {taglineText}
            <span className="inline-block w-0.5 h-5 sm:h-7 bg-violet-400 ml-1.5 align-middle animate-pulse shadow-[0_0_8px_#a855f7]" />
          </p>
        </div>

        {/* Dynamic Rotating Subtitle: Typed in and out at the same place */}
        <div className="h-8 sm:h-10 flex items-center justify-center mb-10 px-4">
          <div className="flex items-center gap-2 px-4 py-1.5 rounded-full bg-slate-900/60 border border-violet-500/30 backdrop-blur-md shadow-inner shadow-purple-900/20">
            <Sparkles className="w-4 h-4 text-violet-400 shrink-0 animate-spin-slow" />
            <span className="text-xs sm:text-sm md:text-base font-normal text-slate-300 tracking-wide">
              {currentText}
            </span>
            <span className="inline-block w-1.5 h-3.5 bg-violet-300 ml-0.5 animate-pulse" />
          </div>
        </div>

        {/* 3. Action Section: Upload Codebase Button */}
        <div className="flex flex-col items-center gap-4">
          {/* Hidden Directory File Input */}
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
            className="group relative inline-flex items-center justify-center px-9 py-4 text-base sm:text-lg font-semibold tracking-wide text-white transition-all duration-300 ease-out rounded-full bg-gradient-to-r from-violet-600 via-purple-600 to-indigo-600 hover:from-violet-500 hover:via-purple-500 hover:to-indigo-500 shadow-[0_0_35px_rgba(147,51,234,0.45)] hover:shadow-[0_0_55px_rgba(168,85,247,0.75)] hover:scale-105 active:scale-95 border border-purple-300/40 cursor-pointer disabled:opacity-50"
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
                <ArrowRight className="w-4 h-4 text-purple-200 group-hover:translate-x-1 transition-transform duration-200" />
              </div>
            )}
          </button>

          {/* Quick Demo Option for Instant Access */}
          <div className="flex items-center gap-2 mt-2">
            <span className="text-xs text-slate-400">or explore immediate demo:</span>
            <button
              onClick={() => onExplorePreset('./demo/nexus-commerce')}
              className="text-xs font-medium text-violet-300 hover:text-white underline underline-offset-4 hover:decoration-violet-400 transition-colors"
            >
              Nexus Commerce Sample
            </button>
            <span className="text-slate-600">•</span>
            <button
              onClick={() => onExplorePreset('C:/Users/Priyansh Pandey/OneDrive/Desktop/CAREER PILOT')}
              className="text-xs font-medium text-purple-300 hover:text-white underline underline-offset-4 hover:decoration-purple-400 transition-colors"
            >
              CAREER PILOT
            </button>
          </div>
        </div>

        {/* 4. Privacy Capsule Footer */}
        <div className="mt-14 flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-black/40 border border-slate-800/80 backdrop-blur-sm text-[11px] text-slate-400">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          <span>Local Privacy Guarantee — Zero source code transmitted outside your device</span>
        </div>
      </main>
    </div>
  );
};
