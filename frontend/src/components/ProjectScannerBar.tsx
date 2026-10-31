import React, { useRef } from 'react';
import { FolderUp, Play, Sparkles, FolderOpen, RefreshCw, CheckCircle2 } from 'lucide-react';
import { ScanSummary } from '../types';

interface ProjectScannerBarProps {
  targetPath: string;
  setTargetPath: (path: string) => void;
  onScanPath: (path: string) => void;
  onScanFiles: (projectName: string, files: Record<string, string>) => void;
  isScanning: boolean;
  activeScan: ScanSummary | null;
}

export const ProjectScannerBar: React.FC<ProjectScannerBarProps> = ({
  targetPath,
  setTargetPath,
  onScanPath,
  onScanFiles,
  isScanning,
  activeScan
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const presets = [
    { label: 'Nexus Commerce (Demo)', path: './demo/nexus-commerce' },
    { label: 'Desktop SampleShop (Test App)', path: 'C:/Users/Priyansh Pandey/OneDrive/Desktop/SampleShop' }
  ];

  // Handle browser folder upload (webkitdirectory)
  const handleFolderUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    let folderName = 'Uploaded Project';
    const fileMap: Record<string, string> = {};

    // Get root folder name
    const firstPath = files[0].webkitRelativePath || files[0].name;
    if (firstPath.includes('/')) {
      folderName = firstPath.split('/')[0];
    }

    const scannableExtensions = ['.json', '.js', '.jsx', '.ts', '.tsx', '.html', '.htm', '.py', '.txt'];

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const ext = '.' + file.name.split('.').pop()?.toLowerCase();
      
      // Read manifest and code files (limit size to 100KB per file)
      if (scannableExtensions.includes(ext) && file.size < 100000) {
        try {
          const content = await file.text();
          fileMap[file.name] = content;
        } catch (err) {
          console.warn('Could not read file:', file.name);
        }
      }
    }

    setTargetPath(`Browser Upload: ${folderName}`);
    onScanFiles(folderName, fileMap);
  };

  return (
    <div className="bg-[#0D1322] border-b border-slate-800 p-4 shadow-xl">
      <div className="max-w-7xl mx-auto flex flex-col lg:flex-row gap-4 items-center justify-between">
        {/* Left: Input options */}
        <div className="flex flex-wrap items-center gap-3 w-full lg:w-auto">
          {/* Native Folder Upload Button */}
          <input
            type="file"
            // @ts-ignore
            webkitdirectory="true"
            directory="true"
            multiple
            ref={fileInputRef}
            onChange={handleFolderUpload}
            className="hidden"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center gap-2 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white font-semibold text-xs px-4 py-2.5 rounded-xl shadow-lg shadow-blue-500/20 active:scale-95 transition-all shrink-0"
          >
            <FolderUp className="w-4 h-4" />
            <span>Select Any Folder from PC</span>
          </button>

          <span className="text-slate-500 text-xs hidden sm:inline">or</span>

          {/* Path Text Input */}
          <div className="flex-1 min-w-[280px] max-w-md flex items-center bg-slate-900 border border-slate-700 rounded-xl px-3 py-1.5 shadow-inner">
            <FolderOpen className="w-4 h-4 text-blue-400 mr-2 shrink-0" />
            <input
              type="text"
              value={targetPath}
              onChange={(e) => setTargetPath(e.target.value)}
              placeholder="Paste any folder path (e.g. C:/Projects/my-app)..."
              className="bg-transparent text-white font-mono text-xs w-full focus:outline-none"
            />
          </div>

          {/* Scan Button */}
          <button
            onClick={() => onScanPath(targetPath)}
            disabled={isScanning}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 text-white font-semibold text-xs px-5 py-2.5 rounded-xl shadow-lg shadow-blue-600/30 transition-all active:scale-95 shrink-0"
          >
            {isScanning ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Analyzing Project...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Scan Target</span>
              </>
            )}
          </button>
        </div>

        {/* Right: Quick Presets */}
        <div className="flex items-center gap-2 text-xs w-full lg:w-auto justify-end">
          <span className="text-slate-400 text-[11px] font-medium hidden md:inline">Quick Test Presets:</span>
          {presets.map((preset) => (
            <button
              key={preset.path}
              onClick={() => {
                setTargetPath(preset.path);
                onScanPath(preset.path);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                targetPath === preset.path
                  ? 'bg-blue-500/20 text-blue-300 border-blue-500/40 shadow-sm'
                  : 'bg-slate-900/80 text-slate-300 border-slate-700/60 hover:bg-slate-800'
              }`}
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {/* Active Project Summary Ribbon */}
      {activeScan && (
        <div className="max-w-7xl mx-auto mt-3 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between text-xs gap-3">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span className="text-slate-300 font-medium">Currently Analyzing:</span>
            <span className="text-white font-bold bg-slate-800 px-2.5 py-0.5 rounded-md border border-slate-700">
              {activeScan.project_name}
            </span>
          </div>

          <div className="flex items-center gap-4 text-[11px]">
            <div className="flex items-center gap-1.5">
              <span className="text-slate-400">Declared Packages:</span>
              <span className="font-bold text-white bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                {activeScan.summary.declared_dependencies}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-slate-400">Observed Endpoints:</span>
              <span className="font-bold text-blue-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                {activeScan.summary.observed_dependencies}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-slate-400">Discrepancies:</span>
              <span className="font-bold text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                {activeScan.summary.discrepancies_found}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-slate-400">Vulnerabilities:</span>
              <span className="font-bold text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/20">
                {activeScan.summary.vulnerabilities_found}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
