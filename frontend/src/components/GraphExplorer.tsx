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

/** Node colors per tier fallback */
const TIER_COLORS: Record<number, { bg: string; border: string; text: string }> = {
  0: { bg: '#92400E', border: '#FBBF24', text: '#FEF3C7' },   // amber  – Journey
  1: { bg: '#1E3A8A', border: '#60A5FA', text: '#DBEAFE' },   // blue   – App
  2: { bg: '#4C1D95', border: '#A78BFA', text: '#EDE9FE' },   // violet – Service
  3: { bg: '#083344', border: '#06B6D4', text: '#E0F2FE' },   // cyan   – Subsystem Cluster
  4: { bg: '#1E293B', border: '#64748B', text: '#CBD5E1' },   // slate  – Direct pkg / Infra
  5: { bg: '#0F172A', border: '#334155', text: '#94A3B8' },   // dark   – Transitive
  6: { bg: '#1A1A2E', border: '#818CF8', text: '#E0E7FF' },   // indigo – Upstream
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
        const sub = (node as any).subtype || '';
        const isCluster = sub === 'domain_cluster';
        const isBundle = sub === 'cluster_bundle';
        const isVuln = node.status === 'compromised';

        let bg = TIER_COLORS[tier]?.bg ?? '#1E293B';
        let border = TIER_COLORS[tier]?.border ?? '#64748B';
        let textColor = TIER_COLORS[tier]?.text ?? '#CBD5E1';
        let w = 44;
        let h = 34;

        if (isCluster) {
          bg = '#083344';
          border = '#06B6D4';
          textColor = '#E0F2FE';
          w = 64;
          h = 42;
        } else if (isBundle) {
          bg = '#131A26';
          border = '#475569';
          textColor = '#94A3B8';
          w = 54;
          h = 32;
        } else if (node.type === 'business_journey') {
          bg = '#92400E';
          border = '#FBBF24';
          textColor = '#FEF3C7';
          w = 54;
          h = 54;
        } else if (node.type === 'application') {
          bg = '#1E3A8A';
          border = '#60A5FA';
          textColor = '#DBEAFE';
          w = 58;
          h = 44;
        } else if (node.type === 'internal_service') {
          bg = '#4C1D95';
          border = '#A78BFA';
          textColor = '#EDE9FE';
          w = 52;
          h = 42;
        } else if (node.type === 'infrastructure_resource') {
          bg = '#064E3B';
          border = '#34D399';
          textColor = '#D1FAE5';
          w = 48;
          h = 40;
        } else if (node.type === 'vendor' || node.type === 'external_api') {
          bg = '#7F1D1D';
          border = '#F87171';
          textColor = '#FEE2E2';
          w = 46;
          h = 36;
        } else if (sub === 'transitive') {
          bg = '#0F172A';
          border = '#334155';
          textColor = '#94A3B8';
          w = 34;
          h = 26;
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

    // Dagre layout config (top-to-bottom structured DAG)
    const dagreLayout: any = {
      name: 'dagre',
      rankDir: 'TB',
      align: 'UL',
      nodeSep: 55,
      rankSep: 95,
      edgeSep: 20,
      ranker: 'network-simplex',
      animate: false,
      padding: 70,
    };

    // Organic force layout
    const coseLayout: any = {
      name: 'cose',
      animate: false,
      padding: 60,
      nodeRepulsion: () => 500000,
      idealEdgeLength: () => 110,
      edgeElasticity: () => 150,
      nestingFactor: 1.2,
      gravity: 0.25,
      numIter: 1000,
    };

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        // Base node
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': 'data(textColor)',
            'font-family': '"Inter", system-ui, sans-serif',
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
            'border-width': 3,
          },
        },

        // Blast radius highlight
        {
          selector: 'node.blast-radius-node',
          style: {
            'border-color': '#FBBF24',
            'border-width': 3,
          },
        },

        // Compromised CVE
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

        // powers_subsystem edge (subsystem flow)
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

    // Fit cleanly after layout
    cy.one('layoutstop', () => {
      cy.fit(undefined, 50);
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
  const handleFit = () => cyRef.current?.fit(undefined, 50);
  const handleReset = () => cyRef.current?.reset();

  const LEGEND_ITEMS = [
    { color: '#1E3A8A', border: '#60A5FA', label: 'Application (Root)' },
    { color: '#4C1D95', border: '#A78BFA', label: 'Internal Service' },
    { color: '#083344', border: '#06B6D4', label: 'Architecture Subsystem' },
    { color: '#1E293B', border: '#64748B', label: 'Direct Package' },
    { color: '#131A26', border: '#475569', label: '+ X More Cluster Bundle' },
    { color: '#0F172A', border: '#334155', label: 'Transitive Sub-dep' },
    { color: '#064E3B', border: '#34D399', label: 'Infrastructure (DB/Cache)' },
    { color: '#7F1D1D', border: '#F87171', label: 'Cloud Vendor / API' },
    { color: '#7F1D1D', border: '#EF4444', label: '⚠ Compromised CVE' },
  ];

  const EDGE_LEGEND = [
    { style: 'solid', color: '#0891B2', label: 'Powers subsystem' },
    { style: 'solid', color: '#6B7280', label: 'Declared dependency' },
    { style: 'dashed', color: '#475569', label: 'Bundled / Transitive' },
  ];

  return (
    <div className="w-full h-full relative bg-[#060205] overflow-hidden select-none">
      {/* Cytoscape Canvas */}
      <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

      {/* Architecture Notation Legend */}
      <div className="absolute top-4 left-4 z-20 w-60">
        <div className="rounded-xl bg-black/80 backdrop-blur-xl border border-white/10 shadow-2xl overflow-hidden">
          <button
            onClick={() => setIsLegendOpen(!isLegendOpen)}
            className="w-full px-3 py-2 flex items-center justify-between text-[11px] font-semibold text-slate-200 hover:text-white border-b border-white/[0.06] transition-colors"
          >
            <div className="flex items-center gap-1.5">
              <Layers className="w-3 h-3 text-cyan-400" />
              <span>Architecture Map Notation</span>
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
                    <span
                      className="w-5 h-0 shrink-0"
                      style={{
                        borderTop: `2px ${e.style} ${e.color}`,
                        display: 'inline-block',
                      }}
                    />
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
                  ? 'bg-cyan-600 text-white shadow-md'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {mode === 'hierarchical' ? 'Architecture DAG' : 'Force Graph'}
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
