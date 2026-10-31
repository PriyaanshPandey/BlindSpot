import React, { useEffect, useRef } from 'react';
import cytoscape, { Core, EventObject } from 'cytoscape';
import { ZoomIn, ZoomOut, Maximize2, RotateCcw, Info } from 'lucide-react';
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

  useEffect(() => {
    if (!containerRef.current || !graphData) return;

    let activeNodes = graphData.nodes;
    let activeEdges = graphData.edges;

    if (filterLayer === 'declared_only') {
      activeNodes = activeNodes.filter(n => n.provenance === 'declared');
      const nodeIds = new Set(activeNodes.map(n => n.id));
      activeEdges = activeEdges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));
    } else if (filterLayer === 'observed_only') {
      activeNodes = activeNodes.filter(n => n.provenance === 'observed');
      const nodeIds = new Set(activeNodes.map(n => n.id));
      activeEdges = activeEdges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));
    } else if (filterLayer === 'discrepancies_only') {
      activeNodes = activeNodes.filter(n => n.provenance === 'observed' || n.status === 'compromised');
      const nodeIds = new Set(activeNodes.map(n => n.id));
      activeEdges = activeEdges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));
    }

    const elements = [
      ...activeNodes.map(node => ({
        data: {
          id: node.id,
          label: node.label,
          type: node.type,
          provenance: node.provenance,
          status: node.status,
          criticality: node.criticality,
          raw: node
        }
      })),
      ...activeEdges.map(edge => ({
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
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': '#E2E8F0',
            'font-size': '11px',
            'font-weight': 'bold',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'background-color': '#1E293B',
            'border-width': 2,
            'border-color': '#475569',
            'width': 44,
            'height': 44,
            'transition-property': 'background-color, border-color, width, height',
            'transition-duration': 0.3
          }
        },
        // Node Type Specific Shapes
        {
          selector: 'node[type = "application"]',
          style: {
            'shape': 'round-rectangle',
            'background-color': '#2563EB',
            'border-color': '#60A5FA',
            'width': 54,
            'height': 54
          }
        },
        {
          selector: 'node[type = "internal_service"]',
          style: {
            'shape': 'round-rectangle',
            'background-color': '#4F46E5',
            'border-color': '#818CF8'
          }
        },
        {
          selector: 'node[type = "vendor"]',
          style: {
            'shape': 'hexagon',
            'background-color': '#7C3AED',
            'border-color': '#A78BFA'
          }
        },
        {
          selector: 'node[type = "external_api"]',
          style: {
            'shape': 'diamond',
            'background-color': '#D97706',
            'border-color': '#FBBF24'
          }
        },
        {
          selector: 'node[type = "software_package"]',
          style: {
            'shape': 'ellipse',
            'background-color': '#334155',
            'border-color': '#64748B'
          }
        },
        {
          selector: 'node[type = "business_journey"]',
          style: {
            'shape': 'star',
            'background-color': '#059669',
            'border-color': '#34D399',
            'width': 50,
            'height': 50
          }
        },
        // Provenance & Status Styling
        {
          selector: 'node[provenance = "observed"]',
          style: {
            'border-style': 'dashed',
            'border-color': '#F59E0B',
            'border-width': 3
          }
        },
        {
          selector: 'node[status = "compromised"]',
          style: {
            'background-color': '#DC2626',
            'border-color': '#EF4444',
            'border-width': 3
          }
        },
        // Edges
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': '#334155',
            'target-arrow-color': '#334155',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8
          }
        },
        {
          selector: 'edge[provenance = "observed"]',
          style: {
            'line-style': 'dashed',
            'line-color': '#F59E0B',
            'target-arrow-color': '#F59E0B'
          }
        },
        {
          selector: 'edge[provenance = "vendor_passport"]',
          style: {
            'line-style': 'dashed',
            'line-color': '#A855F7',
            'target-arrow-color': '#A855F7'
          }
        },
        {
          selector: 'edge[relation = "powers_journey"]',
          style: {
            'line-style': 'dotted',
            'line-color': '#10B981',
            'target-arrow-color': '#10B981',
            'width': 3
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
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 50,
        spacingFactor: 1.4
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
  }, [graphData, filterLayer]);

  // Update blast radius highlights dynamically
  useEffect(() => {
    if (!cyRef.current) return;
    const cy = cyRef.current;

    cy.batch(() => {
      cy.nodes().forEach(node => {
        const id = node.id();
        if (blastRadiusIds.includes(id)) {
          node.style({
            'background-color': '#DC2626',
            'border-color': '#F87171',
            'border-width': 4
          });
        }
      });
    });
  }, [blastRadiusIds]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current?.fit(undefined, 40);
  const handleReset = () => {
    if (!cyRef.current) return;
    cyRef.current.layout({
      name: 'breadthfirst',
      directed: true,
      padding: 50,
      spacingFactor: 1.4
    }).run();
  };

  return (
    <div className="relative w-full h-full bg-[#080C14]">
      {/* Cytoscape DOM container */}
      <div ref={containerRef} className="cytoscape-container" />

      {/* Floating Canvas Controls */}
      <div className="absolute top-4 right-4 z-20 flex flex-col gap-1.5 bg-slate-900/90 border border-slate-700/80 p-1.5 rounded-xl shadow-xl backdrop-blur-md">
        <button
          onClick={handleZoomIn}
          className="p-2 rounded-lg hover:bg-slate-800 text-slate-300 hover:text-white transition-all"
          title="Zoom In"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          onClick={handleZoomOut}
          className="p-2 rounded-lg hover:bg-slate-800 text-slate-300 hover:text-white transition-all"
          title="Zoom Out"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button
          onClick={handleFit}
          className="p-2 rounded-lg hover:bg-slate-800 text-slate-300 hover:text-white transition-all"
          title="Fit View"
        >
          <Maximize2 className="w-4 h-4" />
        </button>
        <button
          onClick={handleReset}
          className="p-2 rounded-lg hover:bg-slate-800 text-slate-300 hover:text-white transition-all"
          title="Reset Layout"
        >
          <RotateCcw className="w-4 h-4" />
        </button>
      </div>

      {/* Floating Instructions Pill */}
      <div className="absolute top-4 left-4 z-10 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-xl text-xs text-slate-300 flex items-center gap-2 shadow-lg backdrop-blur-md">
        <Info className="w-4 h-4 text-blue-400 shrink-0" />
        <span>Click any node to inspect evidence or simulate component failure</span>
      </div>

      {/* Legend overlay */}
      <div className="absolute bottom-4 left-4 z-10 bg-slate-900/90 backdrop-blur-md p-3 rounded-xl border border-slate-800 text-[11px] text-slate-300 flex flex-wrap gap-x-4 gap-y-2 max-w-lg shadow-lg">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded bg-blue-600"></span>
          <span>Application</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded bg-indigo-600"></span>
          <span>Service</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded bg-purple-600"></span>
          <span>Vendor</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded bg-amber-500 border border-amber-400 border-dashed"></span>
          <span>Observed Endpoint</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded bg-emerald-600"></span>
          <span>Journey</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded bg-rose-600 animate-pulse"></span>
          <span>Compromised / Blast Radius</span>
        </div>
      </div>
    </div>
  );
};
