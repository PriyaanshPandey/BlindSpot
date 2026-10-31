import React, { useEffect, useRef, useState } from 'react';
import cytoscape, { Core, EventObject } from 'cytoscape';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RotateCcw,
  Layers,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  ShieldAlert,
  Server,
  Package,
  Database,
  Cloud,
  Star,
  Activity
} from 'lucide-react';
import { GraphData, GraphNode } from '../types';

interface GraphExplorerProps {
  graphData: GraphData | null;
  onSelectNode: (node: GraphNode | null) => void;
  selectedNodeId: string | null;
  blastRadiusIds: string[];
  filterLayer: string;
}

export const GraphExplorer: React.FC<GraphExplorerProps> = ({
  graphData,
  onSelectNode,
  selectedNodeId,
  blastRadiusIds,
  filterLayer
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

    // Tier-based hierarchical positioning
    const elements = [
      ...activeNodes.map((node) => {
        const subtype = (node as any).subtype || 'direct';
        const t = node.type as string;
        const tier = (node as any).tier ?? (t === 'business_journey' ? 0 : t === 'application' ? 1 : t === 'internal_service' ? 2 : (t === 'infrastructure' || t === 'infrastructure_resource') ? 3 : t === 'software_package' ? 4 : 5);
        return {
          data: {
            id: node.id,
            label: node.label,
            type: node.type,
            subtype: subtype,
            tier: tier,
            provenance: node.provenance,
            status: node.status,
            criticality: node.criticality,
            raw: node
          }
        };
      }),
      ...activeEdges.map((edge) => ({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          relation: edge.relation,
          provenance: edge.provenance
        }
      }))
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        // Base Node Style
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': '#F1F5F9',
            'font-family': 'Inter, system-ui, sans-serif',
            'font-size': '11px',
            'font-weight': 'bold',
            'text-valign': 'bottom',
            'text-margin-y': 7,
            'text-background-color': '#09050C',
            'text-background-opacity': 0.85,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'text-border-color': '#2A1D30',
            'text-border-width': 1,
            'text-border-opacity': 0.8,
            'text-max-width': '140px',
            'text-wrap': 'ellipsis',
            'background-color': '#130C19',
            'border-width': 2,
            'border-color': '#475569',
            'width': 46,
            'height': 46,
            'transition-property': 'background-color, border-color, width, height',
            'transition-duration': 0.25
          }
        },

        // Tier 0: Business Journey
        {
          selector: 'node[type = "business_journey"]',
          style: {
            'shape': 'star',
            'background-color': '#D97706',
            'border-color': '#FBBF24',
            'border-width': 2.5,
            'width': 56,
            'height': 56,
            'text-background-color': '#271704',
            'text-border-color': '#F59E0B'
          }
        },

        // Tier 1: Client Application
        {
          selector: 'node[type = "application"]',
          style: {
            'shape': 'round-rectangle',
            'background-color': '#1D4ED8',
            'border-color': '#60A5FA',
            'border-width': 3,
            'width': 58,
            'height': 58,
            'text-background-color': '#0C1E4A',
            'text-border-color': '#3B82F6'
          }
        },

        // Tier 2: Internal Services / Microservices
        {
          selector: 'node[type = "internal_service"]',
          style: {
            'shape': 'hexagon',
            'background-color': '#6D28D9',
            'border-color': '#A78BFA',
            'border-width': 2.5,
            'width': 52,
            'height': 52,
            'text-background-color': '#240B48',
            'text-border-color': '#8B5CF6'
          }
        },

        // Tier 3: Infrastructure (Databases, Caches)
        {
          selector: 'node[type = "infrastructure"]',
          style: {
            'shape': 'barrel',
            'background-color': '#047857',
            'border-color': '#34D399',
            'border-width': 2.5,
            'width': 50,
            'height': 50,
            'text-background-color': '#032C20',
            'text-border-color': '#10B981'
          }
        },

        // Tier 4: Direct Software Packages
        {
          selector: 'node[type = "software_package"][subtype = "direct"]',
          style: {
            'shape': 'round-rectangle',
            'background-color': '#1E293B',
            'border-color': '#64748B',
            'border-width': 2,
            'width': 44,
            'height': 44
          }
        },

        // Tier 5: Transitive Sub-Packages
        {
          selector: 'node[type = "software_package"][subtype = "transitive"]',
          style: {
            'shape': 'ellipse',
            'background-color': '#0F172A',
            'border-color': '#94A3B8',
            'border-style': 'dotted',
            'border-width': 2,
            'width': 36,
            'height': 36,
            'font-size': '10px'
          }
        },

        // Tier 6: Cloud Vendors & External APIs
        {
          selector: 'node[type = "vendor"]',
          style: {
            'shape': 'octagon',
            'background-color': '#BE123C',
            'border-color': '#FB7185',
            'border-width': 2.5,
            'width': 48,
            'height': 48,
            'text-background-color': '#3E0413',
            'text-border-color': '#F43F5E'
          }
        },
        {
          selector: 'node[type = "external_api"]',
          style: {
            'shape': 'diamond',
            'background-color': '#B45309',
            'border-color': '#FCD34D',
            'border-width': 2.5,
            'width': 46,
            'height': 46
          }
        },

        // Tier 7: Vendor Upstream Infrastructure
        {
          selector: 'node[type = "vendor_upstream"]',
          style: {
            'shape': 'hexagon',
            'background-color': '#3730A3',
            'border-color': '#818CF8',
            'border-style': 'dashed',
            'border-width': 2,
            'width': 40,
            'height': 40,
            'font-size': '10px'
          }
        },

        // Status Modifiers
        {
          selector: 'node[status = "compromised"]',
          style: {
            'background-color': '#DC2626',
            'border-color': '#F87171',
            'border-width': 4,
            'text-background-color': '#450A0A',
            'text-border-color': '#EF4444'
          }
        },
        {
          selector: 'node[provenance = "observed"]',
          style: {
            'border-style': 'dashed',
            'border-color': '#F59E0B',
            'border-width': 3
          }
        },

        // Edges
        {
          selector: 'edge',
          style: {
            'width': 1.8,
            'line-color': '#334155',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.85
          }
        },
        {
          selector: 'edge[relation = "depends_on_transitive"]',
          style: {
            'width': 1.5,
            'line-style': 'dashed',
            'line-color': '#64748B',
            'target-arrow-color': '#64748B',
            'arrow-scale': 0.7
          }
        },
        {
          selector: 'edge[relation = "queries_database"]',
          style: {
            'line-color': '#10B981',
            'target-arrow-color': '#10B981',
            'width': 2.2
          }
        },
        {
          selector: 'edge[relation = "calls_api"]',
          style: {
            'line-color': '#F43F5E',
            'target-arrow-color': '#F43F5E',
            'width': 2
          }
        },
        {
          selector: 'edge[relation = "powers_journey"]',
          style: {
            'line-style': 'dotted',
            'line-color': '#F59E0B',
            'target-arrow-color': '#F59E0B',
            'width': 2.5
          }
        },

        // Selection
        {
          selector: ':selected',
          style: {
            'border-color': '#FFFFFF',
            'border-width': 4
          }
        }
      ],
      layout:
        layoutMode === 'hierarchical'
          ? {
              name: 'breadthfirst',
              directed: true,
              roots: activeNodes.filter((n) => n.type === 'business_journey').map((n) => n.id),
              padding: 60,
              spacingFactor: 2.2,
              avoidOverlap: true
            }
          : {
              name: 'cose',
              animate: false,
              padding: 60,
              nodeRepulsion: () => 450000,
              idealEdgeLength: () => 100
            }
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

  return (
    <div className="w-full h-full relative bg-[#060205] overflow-hidden select-none">
      {/* 1. Cytoscape Canvas */}
      <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

      {/* 2. Architecture Map Notation Legend (Floating Collapsible Glass Panel) */}
      <div className="absolute top-4 left-4 z-20 max-w-xs w-full">
        <div className="rounded-2xl bg-black/75 backdrop-blur-xl border border-white/10 shadow-2xl overflow-hidden transition-all duration-300">
          <button
            onClick={() => setIsLegendOpen(!isLegendOpen)}
            className="w-full px-3.5 py-2.5 flex items-center justify-between text-xs font-semibold text-slate-200 hover:text-white border-b border-white/[0.06] transition-colors"
          >
            <div className="flex items-center gap-2">
              <Layers className="w-3.5 h-3.5 text-rose-400" />
              <span>Architecture Notation & Symbols</span>
            </div>
            {isLegendOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>

          {isLegendOpen && (
            <div className="p-3.5 space-y-2 text-[11px] text-slate-300 max-h-72 overflow-y-auto">
              <div className="grid grid-cols-2 gap-2 pb-2 border-b border-white/[0.06]">
                <div className="flex items-center gap-2">
                  <span className="w-3.5 h-3.5 rounded bg-blue-600 border border-blue-400 shrink-0" />
                  <span>Application</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-3.5 h-3.5 rounded-full bg-purple-600 border border-purple-400 shrink-0" />
                  <span>Internal Service</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-3.5 h-3.5 rounded-sm bg-slate-800 border border-slate-500 shrink-0" />
                  <span>Direct Package</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full bg-slate-900 border border-slate-400 border-dotted shrink-0" />
                  <span>Transitive Sub-dep</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-3.5 h-3.5 rounded bg-emerald-700 border border-emerald-400 shrink-0" />
                  <span>DB / Cache</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-3.5 h-3.5 rounded bg-rose-700 border border-rose-400 shrink-0" />
                  <span>Cloud Vendor</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-3.5 h-3.5 rounded bg-amber-600 border border-amber-400 shrink-0" />
                  <span>Business Journey</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-3.5 h-3.5 rounded bg-red-600 border border-red-400 animate-pulse shrink-0" />
                  <span>Compromised CVE</span>
                </div>
              </div>

              {/* Edge Relationships */}
              <div className="space-y-1 pt-1 text-[10px] text-slate-400">
                <div className="flex items-center justify-between">
                  <span>── Solid Edge:</span>
                  <span className="text-slate-300">Declared Connection</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>╌╌ Dashed Edge:</span>
                  <span className="text-amber-300">Observed Shadow API / Transitive</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>···· Dotted Edge:</span>
                  <span className="text-emerald-300">Powers Business Journey</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 3. Floating Zoom & Layout Controls */}
      <div className="absolute bottom-6 right-6 z-20 flex flex-col gap-2">
        {/* Layout Switcher */}
        <div className="flex items-center bg-black/75 backdrop-blur-xl border border-white/10 rounded-2xl p-1 shadow-xl">
          <button
            onClick={() => setLayoutMode('hierarchical')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all ${
              layoutMode === 'hierarchical'
                ? 'bg-rose-500 text-white shadow-md shadow-rose-500/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Tiered Hierarchy
          </button>
          <button
            onClick={() => setLayoutMode('organic')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all ${
              layoutMode === 'organic'
                ? 'bg-rose-500 text-white shadow-md shadow-rose-500/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Force Organic
          </button>
        </div>

        {/* Viewport Zoom Controls */}
        <div className="flex items-center justify-end gap-1.5 bg-black/75 backdrop-blur-xl border border-white/10 rounded-2xl p-1.5 shadow-xl">
          <button
            onClick={handleZoomIn}
            className="p-2 rounded-xl text-slate-300 hover:text-white hover:bg-white/[0.08] transition-colors"
            title="Zoom In"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={handleZoomOut}
            className="p-2 rounded-xl text-slate-300 hover:text-white hover:bg-white/[0.08] transition-colors"
            title="Zoom Out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={handleFit}
            className="p-2 rounded-xl text-slate-300 hover:text-white hover:bg-white/[0.08] transition-colors"
            title="Fit to Screen"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
          <button
            onClick={handleReset}
            className="p-2 rounded-xl text-slate-300 hover:text-white hover:bg-white/[0.08] transition-colors"
            title="Reset Viewport"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
