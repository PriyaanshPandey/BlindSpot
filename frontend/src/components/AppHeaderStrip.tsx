import React, { useRef } from 'react';
import { Folder, FolderPlus, UploadCloud, Layers } from 'lucide-react';

interface AppHeaderStripProps {
  projectName: string;
  targetPath: string;
  onScanFiles: (projectName: string, files: Record<string, string>) => Promise<void>;
  filterLayer: string;
  setFilterLayer: (layer: string) => void;
  activeTab: string;
  isScanning: boolean;
}

export const AppHeaderStrip: React.FC<AppHeaderStripProps> = ({
  projectName,
  targetPath,
  onScanFiles,
  filterLayer,
  setFilterLayer,
  activeTab,
  isScanning
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFolderUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

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
          // skip binary
        }
      }
    }

    await onScanFiles(detectedProjectName, filesToRead);
  };

  return (
    <div className="h-14 px-6 flex items-center justify-between border-b border-white/[0.08] bg-black/40 backdrop-blur-xl z-20 shrink-0">
      {/* Hidden File Input for uploading any other project */}
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

      {/* ONLY TWO STUFF: Name/Path of selected folder + Upload Icon beside it */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2.5 px-3.5 py-1.5 rounded-xl bg-white/[0.04] border border-white/10 text-xs shadow-inner">
          <Folder className="w-4 h-4 text-rose-400 shrink-0" />
          <span className="font-semibold text-white tracking-wide truncate max-w-xs md:max-w-md">
            {projectName || targetPath}
          </span>
        </div>

        {/* Upload Other Project Icon Button */}
        <button
          onClick={() => fileInputRef.current?.click()}
          disabled={isScanning}
          className="group relative flex items-center gap-2 px-3 py-1.5 rounded-xl bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/40 text-rose-200 hover:text-white transition-all text-xs font-semibold shadow-sm cursor-pointer disabled:opacity-50"
          title="Upload another project folder"
        >
          <FolderPlus className="w-4 h-4 text-rose-400 group-hover:scale-110 transition-transform" />
          <span className="hidden sm:inline">Upload Another Folder</span>
        </button>
      </div>

      {/* Floating Graph Layers (Visible only on Graph tab) */}
      {activeTab === 'graph' && (
        <div className="flex items-center gap-1 bg-black/60 p-1 rounded-xl border border-white/10 text-xs">
          {[
            { id: 'all', label: 'All Layers' },
            { id: 'declared_only', label: 'Declared' },
            { id: 'observed_only', label: 'Observed' },
            { id: 'discrepancies_only', label: 'Discrepancies' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setFilterLayer(tab.id)}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all ${
                filterLayer === tab.id
                  ? 'bg-rose-500 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
};

