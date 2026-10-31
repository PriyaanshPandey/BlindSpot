import React, { useEffect, useRef } from 'react';
import cytoscape, { Core, EventObject } from 'cytoscape';
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

    // Filter nodes/edges based on filterLayer
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
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'background-color': '#1E293B',
            'border-width': 2,
            'border-color': '#475569',
            'width': 44,
            'height': 44,
            'transition-property': 'background-color, border-color, width, height, line-color',
            'transition-duration': 0.3
          }
        },
        // Node Type Styling
        {
          selector: 'node[type = "application"]',
          style: {
            'shape': 'round-rectangle',
            'background-color': '#1D4ED8',
            'border-color': '#3B82F6'
          }
        },
        {
          selector: 'node[type = "internal_service"]',
          style: {
            'shape': 'round-rectangle',
            'background-color': '#4338CA',
            'border-color': '#6366F1'
          }
        },
        {
          selector: 'node[type = "vendor"]',
          style: {
            'shape': 'hexagon',
            'background-color': '#6D28D9',
            'border-color': '#8B5CF6'
          }
        },
        {
          selector: 'node[type = "external_api"]',
          style: {
            'shape': 'diamond',
            'background-color': '#B45309',
            'border-color': '#F59E0B'
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
          selector: 'node[type = "infrastructure_resource"]',
          style: {
            'shape': 'round-diamond',
            'background-color': '#0E7490',
            'border-color': '#06B6D4'
          }
        },
        {
          selector: 'node[type = "business_journey"]',
          style: {
            'shape': 'star',
            'background-color': '#047857',
            'border-color': '#10B981'
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
            'background-color': '#991B1B',
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
            'target-arrow-color': '#10B981'
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

  return (
    <div className="relative w-full h-full bg-[#080C14]">
      <div ref={containerRef} className="cytoscape-container" />

      {/* Legend overlay */}
      <div className="absolute bottom-4 left-4 z-10 bg-slate-900/90 backdrop-blur-md p-3 rounded-xl border border-slate-800 text-[11px] text-slate-300 flex flex-wrap gap-x-4 gap-y-2 max-w-lg shadow-lg">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded bg-blue-600"></span>
          <span>Application</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded bg-indigo-600"></span>
          <span>Internal Service</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded bg-purple-600"></span>
          <span>Vendor</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded bg-amber-500 border border-amber-400 border-dashed"></span>
          <span>Observed (Discrepancy)</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded bg-emerald-600"></span>
          <span>Business Journey</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded bg-rose-600 animate-pulse"></span>
          <span>Blast Radius / Vulnerable</span>
        </div>
      </div>
    </div>
  );
};
