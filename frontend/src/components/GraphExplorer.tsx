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

/** Map tier number -> y rank string for dagre rankSep-based layout */
const TIER_RANK: Record<number, string> = {
  0: 'source',
  1: 'min',
  2: 'same',
  3: 'same',
  4: 'same',
  5: 'same',
  6: 'max',
  7: 'sink',
};

/** Compute tier from node data */
function getTier(node: GraphNode): number {
  const t = (node as any).tier as number | undefined;
  if (t !== undefined) return t;
  const type = node.type as string;
  if (type === 'business_journey') return 0;
  if (type === 'application') return 1;
  if (type === 'internal_service') return 2;
  const sub = (node as any).subtype as string | undefined;
  if (type === 'software_package' && sub === 'direct') return 3;
  if (type === 'software_package' && sub === 'transitive') return 4;
  if (type === 'infrastructure_resource' || type === 'infrastructure') return 5;
  if (type === 'vendor' || type === 'external_api') return 6;
  if (type === 'vendor_upstream') return 7;
  return 3;
}

/** Node colors per tier */
const TIER_COLORS: Record<number, { bg: string; border: string; text: string }> = {
  0: { bg: '#92400E', border: '#FBBF24', text: '#FEF3C7' },   // amber  – Journey
  1: { bg: '#1E3A8A', border: '#60A5FA', text: '#DBEAFE' },   // blue   – App
  2: { bg: '#4C1D95', border: '#A78BFA', text: '#EDE9FE' },   // violet – Service
  3: { bg: '#1E293B', border: '#64748B', text: '#CBD5E1' },   // slate  – Direct pkg
  4: { bg: '#0F172A', border: '#334155', text: '#94A3B8' },   // dark   – Transitive
  5: { bg: '#064E3B', border: '#34D399', text: '#D1FAE5' },   // green  – Infra
  6: { bg: '#7F1D1D', border: '#F87171', text: '#FEE2E2' },   // red    – Vendor
  7: { bg: '#1A1A2E', border: '#818CF8', text: '#E0E7FF' },   // indigo – Upstream
};

/** Node shapes per tier */
const TIER_SHAPES: Record<number, string> = {
  0: 'star',
  1: 'round-rectangle',
  2: 'ellipse',
  3: 'round-rectangle',
  4: 'diamond',
  5: 'barrel',
  6: 'cut-rectangle',
  7: 'tag',
};

/** Node sizes per tier (width, height) */
const TIER_SIZES: Record<number, [number, number]> = {
  0: [52, 52],
  1: [56, 44],
  2: [50, 40],
  3: [40, 32],
  4: [30, 24],
  5: [46, 40],
  6: [46, 36],
  7: [36, 28],
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
  const [isLegendOpen, setIsLegendOpen] = useState(true);
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
        const colors = TIER_COLORS[tier] ?? TIER_COLORS[3];
        const [w, h] = TIER_SIZES[tier] ?? [38, 30];
        const shape = TIER_SHAPES[tier] ?? 'round-rectangle';
        const isVuln = node.status === 'compromised';
        return {
          data: {
            id: node.id,
            label: node.label,
            type: node.type,
            subtype: (node as any).subtype || '',
            tier,
            provenance: node.provenance,
            status: node.status,
            criticality: node.criticality,
            raw: node,
            // inline style data for cytoscape
            bg: isVuln ? '#7F1D1D' : colors.bg,
            border: isVuln ? '#EF4444' : colors.border,
            textColor: colors.text,
            nodeWidth: w,
            nodeHeight: h,
            shape,
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

    // Dagre layout config (proper top-down tiered DAG)
    const dagreLayout: any = {
      name: 'dagre',
      rankDir: 'TB',         // top-to-bottom
      align: 'UL',
      nodeSep: 60,           // horizontal spacing between nodes in same rank
      rankSep: 120,          // vertical spacing between ranks
      edgeSep: 20,
      ranker: 'longest-path',
      animate: false,
      padding: 80,
    };

    // Organic cose layout for force-directed view
    const coseLayout: any = {
      name: 'cose',
      animate: false,
      padding: 60,
      nodeRepulsion: () => 600000,
      idealEdgeLength: () => 120,
      edgeElasticity: () => 200,
      nestingFactor: 1.2,
      gravity: 0.25,
      numIter: 1000,
      initialTemp: 200,
      coolingFactor: 0.95,
      minTemp: 1.0,
    };

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        // ── Base node (uses inline data-driven values)
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': 'data(textColor)',
            'font-family': '"Inter", "SF Pro Display", system-ui, sans-serif',
            'font-size': '10px',
            'font-weight': 'bold',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'text-margin-y': 6,
            'text-background-color': '#04020A',
            'text-background-opacity': 0.88,
            'text-background-padding': '2px',
            'text-background-shape': 'roundrectangle',
            'text-max-width': '120px',
            'text-wrap': 'ellipsis',
            'text-overflow-wrap': 'whitespace',
            'background-color': 'data(bg)',
            'border-width': 1.5,
            'border-color': 'data(border)',
            'width': 'data(nodeWidth)',
            'height': 'data(nodeHeight)',
            // shape is applied per-node below via selectors
            'transition-property': 'border-color, border-width',
            'transition-duration': 150,
          },
        },

        // ── Highlighted blast-radius nodes
        {
          selector: 'node.blast-radius-node',
          style: {
            'border-color': '#FBBF24',
            'border-width': 3,
          },
        },

        // ── Selected node
        {
          selector: 'node.selected-node',
          style: {
            'border-color': '#FFFFFF',
            'border-width': 3,
          },
        },

        // ── Compromised / vuln nodes – pulsing red override
        {
          selector: 'node[status = "compromised"]',
          style: {
            'border-color': '#EF4444',
            'border-width': 2.5,
          },
        },

        // ── Per-tier shapes
        { selector: 'node[tier = 0]', style: { 'shape': 'star' } },
        { selector: 'node[tier = 1]', style: { 'shape': 'round-rectangle' } },
        { selector: 'node[tier = 2]', style: { 'shape': 'ellipse' } },
        { selector: 'node[tier = 3]', style: { 'shape': 'round-rectangle' } },
        { selector: 'node[tier = 4]', style: { 'shape': 'diamond' } },
        { selector: 'node[tier = 5]', style: { 'shape': 'barrel' } },
        { selector: 'node[tier = 6]', style: { 'shape': 'cut-rectangle' } },
        { selector: 'node[tier = 7]', style: { 'shape': 'tag' } },

        // ── Observed (shadow) nodes
        {
          selector: 'node[provenance = "observed"]',
          style: {
            'border-style': 'dashed',
          },
        },

        // ─────── EDGE STYLES ───────

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

    // Fit after layout finishes
    cy.one('layoutstop', () => {
      cy.fit(undefined, 60);
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
  const handleFit = () => cyRef.current?.fit(undefined, 60);
  const handleReset = () => cyRef.current?.reset();

  const LEGEND_ITEMS = [
    { color: '#1E3A8A', border: '#60A5FA', label: 'Application (Root)' },
    { color: '#4C1D95', border: '#A78BFA', label: 'Internal Service' },
    { color: '#1E293B', border: '#64748B', label: 'Direct Package' },
    { color: '#0F172A', border: '#334155', label: 'Transitive Dep' },
    { color: '#064E3B', border: '#34D399', label: 'Infrastructure (DB/Cache)' },
    { color: '#7F1D1D', border: '#F87171', label: 'Cloud Vendor / API' },
    { color: '#1A1A2E', border: '#818CF8', label: 'Vendor Upstream' },
    { color: '#7F1D1D', border: '#EF4444', label: '⚠ Compromised CVE' },
  ];

  const EDGE_LEGEND = [
    { style: 'solid', color: '#6B7280', label: 'Declared dependency' },
    { style: 'dashed', color: '#4B5563', label: 'Transitive / Observed' },
    { style: 'dotted', color: '#818CF8', label: 'Vendor upstream' },
  ];

  return (
    <div className="w-full h-full relative bg-[#060205] overflow-hidden select-none">
      {/* Cytoscape Canvas */}
      <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

      {/* Architecture Notation Legend */}
      <div className="absolute top-4 left-4 z-20 w-56">
        <div className="rounded-xl bg-black/80 backdrop-blur-xl border border-white/10 shadow-2xl overflow-hidden">
          <button
            onClick={() => setIsLegendOpen(!isLegendOpen)}
            className="w-full px-3 py-2 flex items-center justify-between text-[11px] font-semibold text-slate-200 hover:text-white border-b border-white/[0.06] transition-colors"
          >
            <div className="flex items-center gap-1.5">
              <Layers className="w-3 h-3 text-rose-400" />
              <span>Architecture Legend</span>
            </div>
            {isLegendOpen ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>

          {isLegendOpen && (
            <div className="p-3 space-y-1.5 text-[10px] text-slate-300">
              {LEGEND_ITEMS.map((item) => (
                <div key={item.label} className="flex items-center gap-2">
                  <span
                    className="w-3 h-3 rounded-sm shrink-0"
                    style={{ backgroundColor: item.color, border: `1px solid ${item.border}` }}
                  />
                  <span>{item.label}</span>
                </div>
              ))}
              <div className="border-t border-white/[0.06] pt-1.5 mt-1.5 space-y-1 text-[9px] text-slate-400">
                {EDGE_LEGEND.map((e) => (
                  <div key={e.label} className="flex items-center gap-2">
                    <span className="w-5 h-0 shrink-0" style={{
                      borderTop: `2px ${e.style} ${e.color}`,
                      display: 'inline-block',
                    }} />
                    <span>{e.label}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Layout + Zoom Controls */}
      <div className="absolute bottom-6 right-6 z-20 flex flex-col gap-2">
        {/* Layout switcher */}
        <div className="flex items-center bg-black/80 backdrop-blur-xl border border-white/10 rounded-xl p-1 shadow-xl">
          {(['hierarchical', 'organic'] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setLayoutMode(mode)}
              className={`px-2.5 py-1 rounded-lg text-[10px] font-semibold transition-all ${
                layoutMode === mode
                  ? 'bg-rose-600 text-white shadow-md'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {mode === 'hierarchical' ? 'Tiered DAG' : 'Force Graph'}
            </button>
          ))}
        </div>

        {/* Viewport controls */}
        <div className="flex items-center justify-end gap-1 bg-black/80 backdrop-blur-xl border border-white/10 rounded-xl p-1.5 shadow-xl">
          {[
            { icon: <ZoomIn className="w-4 h-4" />, fn: handleZoomIn, title: 'Zoom In' },
            { icon: <ZoomOut className="w-4 h-4" />, fn: handleZoomOut, title: 'Zoom Out' },
            { icon: <Maximize2 className="w-4 h-4" />, fn: handleFit, title: 'Fit to Screen' },
            { icon: <RotateCcw className="w-4 h-4" />, fn: handleReset, title: 'Reset Viewport' },
          ].map(({ icon, fn, title }) => (
            <button
              key={title}
              onClick={fn}
              title={title}
              className="p-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/[0.08] transition-colors"
            >
              {icon}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
