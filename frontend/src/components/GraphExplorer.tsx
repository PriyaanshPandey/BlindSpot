import React, { useEffect, useRef, useState } from 'react';
import cytoscape, { Core, EventObject } from 'cytoscape';
// @ts-ignore
import dagre from 'cytoscape-dagre';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RotateCcw,
  Layers,
  ChevronDown,
  ChevronUp,
  Server,
  Cpu,
  Hexagon,
  Package,
  Database,
  Cloud,
  Star,
  ShieldAlert,
  Boxes,
  X
} from 'lucide-react';
import { GraphData, GraphNode } from '../types';

// Register dagre layout once
cytoscape.use(dagre);

interface GraphExplorerProps {
  graphData: GraphData | null;
  onSelectNode: (node: GraphNode | null) => void;
  selectedNodeId: string | null;
  blastRadiusIds: string[];
  filterLayer: string;
}

/** Compute tier from node data */
function getTier(node: GraphNode): number {
  const t = (node as any).tier as number | undefined;
  if (t !== undefined) return t;
  const type = node.type as string;
  if (type === 'business_journey') return 0;
  if (type === 'application') return 1;
  if (type === 'internal_service') return 2;
  const sub = (node as any).subtype as string | undefined;
  if (sub === 'domain_cluster') return 3;
  if (type === 'software_package' && sub === 'direct') return 4;
  if (type === 'software_package' && sub === 'transitive') return 5;
  if (type === 'infrastructure_resource' || type === 'infrastructure') return 4;
  if (type === 'vendor' || type === 'external_api') return 4;
  if (type === 'vendor_upstream') return 6;
  return 4;
}

/** Professional dark theme colors per tier */
const TIER_COLORS: Record<number, { bg: string; border: string; text: string }> = {
  0: { bg: '#854D0E', border: '#FACC15', text: '#FEF08A' },   // amber  – Journey
  1: { bg: '#1E3A8A', border: '#60A5FA', text: '#DBEAFE' },   // blue   – App
  2: { bg: '#4C1D95', border: '#A78BFA', text: '#EDE9FE' },   // violet – Service
  3: { bg: '#083344', border: '#06B6D4', text: '#E0F2FE' },   // cyan   – Subsystem Cluster
  4: { bg: '#1E293B', border: '#64748B', text: '#CBD5E1' },   // slate  – Direct pkg / Infra
  5: { bg: '#0F172A', border: '#334155', text: '#94A3B8' },   // dark   – Transitive
  6: { bg: '#1E1B4B', border: '#818CF8', text: '#E0E7FF' },   // indigo – Upstream
};

export const GraphExplorer: React.FC<GraphExplorerProps> = ({
  graphData,
  onSelectNode,
  selectedNodeId,
  blastRadiusIds,
  filterLayer,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [isLegendOpen, setIsLegendOpen] = useState(false);
  const [layoutMode, setLayoutMode] = useState<'hierarchical' | 'organic'>('hierarchical');

  useEffect(() => {
    if (!containerRef.current || !graphData) return;

    let activeNodes = graphData.nodes;
    let activeEdges = graphData.edges;

    if (filterLayer === 'declared_only') {
      activeNodes = activeNodes.filter((n) => n.provenance === 'declared');
      const nodeIds = new Set(activeNodes.map((n) => n.id));
      activeEdges = activeEdges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target));
    } else if (filterLayer === 'observed_only') {
      activeNodes = activeNodes.filter((n) => n.provenance === 'observed');
      const nodeIds = new Set(activeNodes.map((n) => n.id));
      activeEdges = activeEdges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target));
    } else if (filterLayer === 'discrepancies_only') {
      activeNodes = activeNodes.filter(
        (n) => n.provenance === 'observed' || n.status === 'compromised'
      );
      const nodeIds = new Set(activeNodes.map((n) => n.id));
      activeEdges = activeEdges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target));
    }

    const elements = [
      ...activeNodes.map((node) => {
        const tier = getTier(node);
        const sub = (node as any).subtype || '';
        const isCluster = sub === 'domain_cluster';
        const isBundle = sub === 'cluster_bundle';
        const isVuln = node.status === 'compromised';

        let bg = TIER_COLORS[tier]?.bg ?? '#1E293B';
        let border = TIER_COLORS[tier]?.border ?? '#64748B';
        let textColor = TIER_COLORS[tier]?.text ?? '#CBD5E1';

        // Generous, clearly visible node dimensions
        let w = 56;
        let h = 42;

        if (isCluster) {
          bg = '#083344';
          border = '#06B6D4';
          textColor = '#E0F2FE';
          w = 72;
          h = 48;
        } else if (isBundle) {
          bg = '#131A26';
          border = '#64748B';
          textColor = '#94A3B8';
          w = 60;
          h = 36;
        } else if (node.type === 'business_journey') {
          bg = '#854D0E';
          border = '#FACC15';
          textColor = '#FEF08A';
          w = 64;
          h = 64;
        } else if (node.type === 'application') {
          bg = '#1E3A8A';
          border = '#60A5FA';
          textColor = '#DBEAFE';
          w = 68;
          h = 50;
        } else if (node.type === 'internal_service') {
          bg = '#4C1D95';
          border = '#A78BFA';
          textColor = '#EDE9FE';
          w = 62;
          h = 48;
        } else if (node.type === 'infrastructure_resource') {
          bg = '#064E3B';
          border = '#34D399';
          textColor = '#D1FAE5';
          w = 58;
          h = 46;
        } else if (node.type === 'vendor' || node.type === 'external_api') {
          bg = '#7F1D1D';
          border = '#F87171';
          textColor = '#FEE2E2';
          w = 58;
          h = 42;
        } else if (sub === 'transitive') {
          bg = '#0F172A';
          border = '#475569';
          textColor = '#94A3B8';
          w = 46;
          h = 34;
        }

        if (isVuln) {
          bg = '#7F1D1D';
          border = '#EF4444';
          textColor = '#FEE2E2';
        }

        return {
          data: {
            id: node.id,
            label: node.label,
            type: node.type,
            subtype: sub,
            tier,
            provenance: node.provenance,
            status: node.status,
            criticality: node.criticality,
            raw: node,
            bg,
            border,
            textColor,
            nodeWidth: w,
            nodeHeight: h,
          },
        };
      }),
      ...activeEdges.map((edge) => ({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          relation: edge.relation,
          provenance: edge.provenance,
        },
      })),
    ];

    // Dagre layout configuration for top-to-bottom structured DAG
    const dagreLayout: any = {
      name: 'dagre',
      rankDir: 'TB',
      align: 'UL',
      nodeSep: 65,
      rankSep: 105,
      edgeSep: 25,
      ranker: 'network-simplex',
      animate: false,
      padding: 60,
    };

    // Organic force layout
    const coseLayout: any = {
      name: 'cose',
      animate: false,
      padding: 60,
      nodeRepulsion: () => 600000,
      idealEdgeLength: () => 120,
      edgeElasticity: () => 150,
      nestingFactor: 1.2,
      gravity: 0.25,
      numIter: 1000,
    };

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        // Base node with clear, readable pill label
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': 'data(textColor)',
            'font-family': '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
            'font-size': '11px',
            'font-weight': 'bold',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'text-margin-y': 7,
            'text-background-color': '#060209',
            'text-background-opacity': 0.94,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'text-border-color': '#231530',
            'text-border-width': 1,
            'text-border-opacity': 0.9,
            'text-max-width': '135px',
            'text-wrap': 'wrap',
            'background-color': 'data(bg)',
            'border-width': 1.5,
            'border-color': 'data(border)',
            'width': 'data(nodeWidth)',
            'height': 'data(nodeHeight)',
            'shape': 'round-rectangle',
            'transition-property': 'border-color, border-width',
            'transition-duration': 150,
          },
        },

        // Per-type shapes
        { selector: 'node[type = "business_journey"]', style: { 'shape': 'star' } },
        { selector: 'node[type = "application"]', style: { 'shape': 'round-rectangle' } },
        { selector: 'node[type = "internal_service"]', style: { 'shape': 'ellipse' } },
        { selector: 'node[subtype = "domain_cluster"]', style: { 'shape': 'hexagon', 'border-width': 2 } },
        { selector: 'node[subtype = "cluster_bundle"]', style: { 'shape': 'round-rectangle', 'border-style': 'dashed', 'border-width': 1.5 } },
        { selector: 'node[type = "software_package"][subtype = "direct"]', style: { 'shape': 'round-rectangle' } },
        { selector: 'node[subtype = "transitive"]', style: { 'shape': 'diamond' } },
        { selector: 'node[type = "infrastructure_resource"]', style: { 'shape': 'barrel' } },
        { selector: 'node[type = "vendor"], node[type = "external_api"]', style: { 'shape': 'cut-rectangle' } },
        { selector: 'node[type = "vendor_upstream"]', style: { 'shape': 'tag' } },

        // Selected node
        {
          selector: 'node.selected-node',
          style: {
            'border-color': '#FFFFFF',
            'border-width': 3.5,
          },
        },

        // Blast radius highlight
        {
          selector: 'node.blast-radius-node',
          style: {
            'border-color': '#FBBF24',
            'border-width': 3.5,
          },
        },

        // Compromised CVE (pulsing red border)
        {
          selector: 'node[status = "compromised"]',
          style: {
            'border-color': '#EF4444',
            'border-width': 2.5,
          },
        },

        // Observed / Shadow
        {
          selector: 'node[provenance = "observed"]',
          style: {
            'border-style': 'dashed',
          },
        },

        // Default edge
        {
          selector: 'edge',
          style: {
            'width': 1.2,
            'line-color': '#334155',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.7,
            'curve-style': 'bezier',
            'line-style': 'solid',
            'opacity': 0.7,
          },
        },

        // powers_subsystem edge (cyan subsystem flow)
        {
          selector: 'edge[relation = "powers_subsystem"]',
          style: {
            'line-color': '#0891B2',
            'target-arrow-color': '#06B6D4',
            'width': 2.2,
            'line-style': 'solid',
          },
        },

        // contains_packages edge (dashed)
        {
          selector: 'edge[relation = "contains_packages"]',
          style: {
            'line-color': '#475569',
            'target-arrow-color': '#64748B',
            'width': 1.2,
            'line-style': 'dashed',
          },
        },

        // depends_on – direct
        {
          selector: 'edge[relation = "depends_on"]',
          style: {
            'line-color': '#4B5563',
            'target-arrow-color': '#6B7280',
            'width': 1.2,
          },
        },

        // depends_on_transitive – dashed dimmer
        {
          selector: 'edge[relation = "depends_on_transitive"]',
          style: {
            'line-style': 'dashed',
            'line-color': '#374151',
            'target-arrow-color': '#4B5563',
            'width': 1,
            'opacity': 0.6,
          },
        },

        // calls_service – service flow
        {
          selector: 'edge[relation = "calls_service"]',
          style: {
            'line-color': '#7C3AED',
            'target-arrow-color': '#8B5CF6',
            'width': 2,
          },
        },

        // calls_api – external vendor
        {
          selector: 'edge[relation = "calls_api"]',
          style: {
            'line-color': '#991B1B',
            'target-arrow-color': '#EF4444',
            'width': 1.5,
            'line-style': 'dashed',
          },
        },

        // queries_database / uses_cache
        {
          selector: 'edge[relation = "queries_database"], edge[relation = "uses_cache"]',
          style: {
            'line-color': '#065F46',
            'target-arrow-color': '#34D399',
            'width': 1.5,
          },
        },

        // relies_on_upstream
        {
          selector: 'edge[relation = "relies_on_upstream"]',
          style: {
            'line-color': '#312E81',
            'target-arrow-color': '#818CF8',
            'width': 1,
            'line-style': 'dotted',
            'opacity': 0.5,
          },
        },
      ],
      layout: layoutMode === 'hierarchical' ? dagreLayout : coseLayout,
    });

    cy.on('tap', 'node', (evt: EventObject) => {
      const nodeData = evt.target.data('raw') as GraphNode;
      onSelectNode(nodeData);
    });

    cy.on('tap', (evt: EventObject) => {
      if (evt.target === cy) {
        onSelectNode(null);
      }
    });

    // Fit cleanly and enforce readable minimum zoom
    cy.one('layoutstop', () => {
      cy.fit(undefined, 60);
      if (cy.zoom() < 0.65) {
        cy.zoom(0.7);
        cy.center();
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [graphData, filterLayer, layoutMode]);

  // Handle selected node and blast radius glow
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      cy.nodes().removeClass('blast-radius-node selected-node');

      if (selectedNodeId) {
        const node = cy.getElementById(selectedNodeId);
        if (node.length > 0) {
          node.addClass('selected-node');
        }
      }

      if (blastRadiusIds.length > 0) {
        blastRadiusIds.forEach((id) => {
          const node = cy.getElementById(id);
          if (node.length > 0) {
            node.addClass('blast-radius-node');
          }
        });
      }
    });
  }, [selectedNodeId, blastRadiusIds]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => {
    if (!cyRef.current) return;
    cyRef.current.fit(undefined, 60);
    if (cyRef.current.zoom() < 0.65) {
      cyRef.current.zoom(0.7);
      cyRef.current.center();
    }
  };
  const handleReset = () => {
    if (!cyRef.current) return;
    cyRef.current.reset();
    handleFit();
  };

  return (
    <div className="w-full h-full relative bg-[#060205] overflow-hidden select-none">
      {/* Cytoscape Canvas */}
      <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

      {/* Professional Architecture Map Legend */}
      <div className="absolute top-4 left-4 z-20">
        {!isLegendOpen ? (
          <button
            onClick={() => setIsLegendOpen(true)}
            className="flex items-center gap-2 px-3.5 py-2 rounded-full bg-zinc-950/90 hover:bg-zinc-900 border border-zinc-800 backdrop-blur-xl shadow-xl text-xs font-medium text-zinc-300 hover:text-white transition-all cursor-pointer"
          >
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>Map Legend</span>
            <ChevronDown className="w-3 h-3 text-zinc-500" />
          </button>
        ) : (
          <div className="w-72 rounded-2xl bg-zinc-950/95 border border-zinc-800 backdrop-blur-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            {/* Legend Header */}
            <div className="px-4 py-3 border-b border-zinc-800/80 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-semibold text-white tracking-wide">Architecture Notation</span>
              </div>
              <button
                onClick={() => setIsLegendOpen(false)}
                className="p-1 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-900 transition-colors cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Legend Body */}
            <div className="p-4 space-y-4 text-xs text-zinc-300">
              {/* Components */}
              <div className="space-y-2">
                <span className="text-[10px] font-semibold tracking-wider text-zinc-500 uppercase block">Components</span>
                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div className="flex items-center gap-2">
                    <Server className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                    <span>Application</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Cpu className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                    <span>Service</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Hexagon className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <span>Subsystem</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Package className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    <span>Direct Pkg</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Database className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    <span>DB / Cache</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Cloud className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    <span>Cloud API</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Star className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                    <span>Journey</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />
                    <span>CVE Risk</span>
                  </div>
                </div>
              </div>

              {/* Connections */}
              <div className="border-t border-zinc-800/80 pt-3 space-y-2">
                <span className="text-[10px] font-semibold tracking-wider text-zinc-500 uppercase block">Connections</span>
                <div className="space-y-1.5 text-[11px]">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="w-4 h-0.5 bg-cyan-500 rounded" />
                      <span>Subsystem Power</span>
                    </div>
                    <span className="text-zinc-500 text-[10px]">Solid</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="w-4 h-0.5 bg-slate-400 rounded" />
                      <span>Dependency</span>
                    </div>
                    <span className="text-zinc-500 text-[10px]">Solid</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="w-4 h-0 border-t-2 border-dashed border-red-400" />
                      <span>External API Call</span>
                    </div>
                    <span className="text-zinc-500 text-[10px]">Dashed</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="w-4 h-0 border-t-2 border-dotted border-indigo-400" />
                      <span>Upstream Infra</span>
                    </div>
                    <span className="text-zinc-500 text-[10px]">Dotted</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Floating Layout & Viewport Controls */}
      <div className="absolute bottom-6 right-6 z-20 flex flex-col gap-2">
        {/* Layout Switcher */}
        <div className="flex items-center bg-zinc-950/80 backdrop-blur-xl border border-zinc-800 rounded-xl p-1 shadow-xl">
          {(['hierarchical', 'organic'] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setLayoutMode(mode)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                layoutMode === mode
                  ? 'bg-cyan-600 text-white shadow-md'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              {mode === 'hierarchical' ? 'Architecture DAG' : 'Force Graph'}
            </button>
          ))}
        </div>

        {/* Viewport Zoom Controls */}
        <div className="flex items-center justify-end gap-1 bg-zinc-950/80 backdrop-blur-xl border border-zinc-800 rounded-xl p-1.5 shadow-xl">
          {[
            { icon: <ZoomIn className="w-4 h-4" />, fn: handleZoomIn, title: 'Zoom In' },
            { icon: <ZoomOut className="w-4 h-4" />, fn: handleZoomOut, title: 'Zoom Out' },
            { icon: <Maximize2 className="w-4 h-4" />, fn: handleFit, title: 'Fit Viewport' },
            { icon: <RotateCcw className="w-4 h-4" />, fn: handleReset, title: 'Reset Viewport' },
          ].map(({ icon, fn, title }) => (
            <button
              key={title}
              onClick={fn}
              title={title}
              className="p-1.5 rounded-lg text-zinc-300 hover:text-white hover:bg-zinc-900 transition-colors cursor-pointer"
            >
              {icon}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
