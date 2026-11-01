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
  Server,
  Cpu,
  Package,
  Database,
  Cloud,
  Star,
  ShieldAlert,
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

/** Get node visual config by type */
function getNodeStyle(node: GraphNode, isVirtual = false): {
  bg: string; border: string; text: string; w: number; h: number; shape: string;
} {
  const type = node.type as string;
  const sub = (node as any).subtype as string | undefined;
  const isVuln = node.status === 'compromised';

  if (isVirtual) {
    return { bg: '#0F172A', border: '#1E293B', text: '#334155', w: 10, h: 10, shape: 'ellipse' };
  }
  if (isVuln) {
    return { bg: '#7F1D1D', border: '#EF4444', text: '#FEE2E2', w: 145, h: 46, shape: 'round-rectangle' };
  }
  if (type === 'business_journey') {
    return { bg: '#78350F', border: '#FBBF24', text: '#FEF3C7', w: 110, h: 110, shape: 'star' };
  }
  if (type === 'application') {
    return { bg: '#1E3A8A', border: '#60A5FA', text: '#DBEAFE', w: 170, h: 58, shape: 'round-rectangle' };
  }
  if (type === 'internal_service') {
    return { bg: '#4C1D95', border: '#A78BFA', text: '#EDE9FE', w: 155, h: 52, shape: 'ellipse' };
  }
  if (type === 'infrastructure_resource') {
    return { bg: '#064E3B', border: '#34D399', text: '#D1FAE5', w: 148, h: 52, shape: 'barrel' };
  }
  if (type === 'vendor') {
    return { bg: '#7F1D1D', border: '#F87171', text: '#FEE2E2', w: 150, h: 52, shape: 'cut-rectangle' };
  }
  if (type === 'external_api') {
    return { bg: '#451A03', border: '#FB923C', text: '#FED7AA', w: 145, h: 48, shape: 'cut-rectangle' };
  }
  if (type === 'vendor_upstream') {
    return { bg: '#1E1B4B', border: '#818CF8', text: '#E0E7FF', w: 135, h: 44, shape: 'tag' };
  }
  if (type === 'software_package' && sub === 'deep_transitive') {
    return { bg: '#070C18', border: '#334155', text: '#64748B', w: 115, h: 34, shape: 'diamond' };
  }
  if (type === 'software_package' && sub === 'transitive') {
    return { bg: '#0F172A', border: '#475569', text: '#94A3B8', w: 125, h: 38, shape: 'diamond' };
  }
  if (type === 'software_package') {
    return { bg: '#082F49', border: '#38BDF8', text: '#E0F2FE', w: 135, h: 44, shape: 'round-rectangle' };
  }
  return { bg: '#1E293B', border: '#64748B', text: '#CBD5E1', w: 130, h: 44, shape: 'round-rectangle' };
}

/**
 * Build a MANUAL HIERARCHICAL LAYOUT that positions nodes in clear tiers.
 * Returns position map { nodeId: { x, y } }
 */
function computeManualLayout(
  nodes: GraphNode[],
  edges: Array<{ source: string; target: string }>
): Record<string, { x: number; y: number }> {
  const pos: Record<string, { x: number; y: number }> = {};

  const byType = (type: string) => nodes.filter((n) => n.type === type);
  const bySubtype = (type: string, sub: string) =>
    nodes.filter((n) => n.type === type && (n as any).subtype === sub);
  const notSubtype = (type: string, sub: string) =>
    nodes.filter((n) => n.type === type && (n as any).subtype !== sub);

  const appNodes = byType('application');
  const svcNodes = byType('internal_service');
  const infraNodes = byType('infrastructure_resource');
  const vendorNodes = [...byType('vendor'), ...byType('external_api')];
  const upstreamNodes = byType('vendor_upstream');
  const journeyNodes = byType('business_journey');
  const directPkgs = nodes.filter(
    (n) => n.type === 'software_package' && (n as any).subtype === 'direct'
  );
  const transPkgs = nodes.filter(
    (n) => n.type === 'software_package' && (n as any).subtype === 'transitive'
  );
  const deepPkgs = nodes.filter(
    (n) => n.type === 'software_package' && (n as any).subtype === 'deep_transitive'
  );

  const CANVAS_W = 2400;

  // ── Tier Y positions ──────────────────────────────────────────────────
  const Y = {
    journey: -600,
    app: -450,
    service: -280,
    infra: -80,       // same row as vendors
    vendor: -80,
    directPkg: 160,
    transPkg: 380,
    deepPkg: 600,
    upstream: 820,
  };

  // Helper: spread N items evenly across CANVAS_W around center
  function spreadX(items: GraphNode[], y: number, spacing: number) {
    const count = items.length;
    if (count === 0) return;
    const totalW = (count - 1) * spacing;
    const startX = -totalW / 2;
    items.forEach((n, i) => {
      pos[n.id] = { x: startX + i * spacing, y };
    });
  }

  // App: center top
  spreadX(appNodes, Y.app, 220);

  // Services: below app
  spreadX(svcNodes, Y.service, 240);

  // Journey: top right
  journeyNodes.forEach((n, i) => {
    pos[n.id] = { x: CANVAS_W / 2 - 200 + i * 160, y: Y.journey };
  });

  // Infra: LEFT half, Vendors: RIGHT half
  const infraSpacing = 200;
  const infraStart = -((infraNodes.length - 1) * infraSpacing) / 2 - CANVAS_W / 4;
  infraNodes.forEach((n, i) => {
    pos[n.id] = { x: infraStart + i * infraSpacing, y: Y.infra };
  });

  const vendorSpacing = 200;
  const vendorStart = CANVAS_W / 4 - ((vendorNodes.length - 1) * vendorSpacing) / 2;
  vendorNodes.forEach((n, i) => {
    pos[n.id] = { x: vendorStart + i * vendorSpacing, y: Y.vendor };
  });

  // Direct packages: multi-column grid centered
  const dCount = directPkgs.length;
  const dCols = Math.min(dCount, Math.max(4, Math.ceil(Math.sqrt(dCount * 1.8))));
  const dColW = 175;
  const dRowH = 110;
  const dStartX = -((dCols - 1) * dColW) / 2;
  directPkgs.forEach((n, idx) => {
    const col = idx % dCols;
    const row = Math.floor(idx / dCols);
    pos[n.id] = { x: dStartX + col * dColW, y: Y.directPkg + row * dRowH };
  });

  // Transitive packages: denser multi-column grid below direct
  const tCount = transPkgs.length;
  const tCols = Math.min(tCount, Math.max(5, Math.ceil(Math.sqrt(tCount * 2))));
  const tColW = 155;
  const tRowH = 95;
  const tStartX = -((tCols - 1) * tColW) / 2;
  transPkgs.forEach((n, idx) => {
    const col = idx % tCols;
    const row = Math.floor(idx / tCols);
    pos[n.id] = { x: tStartX + col * tColW, y: Y.transPkg + row * tRowH };
  });

  // Deep transitive packages (Layer 3): grid below Layer 2
  const dpCount = deepPkgs.length;
  const dpCols = Math.min(dpCount, Math.max(5, Math.ceil(Math.sqrt(dpCount * 2))));
  const dpColW = 145;
  const dpRowH = 85;
  const dpStartX = -((dpCols - 1) * dpColW) / 2;
  deepPkgs.forEach((n, idx) => {
    const col = idx % dpCols;
    const row = Math.floor(idx / dpCols);
    pos[n.id] = { x: dpStartX + col * dpColW, y: Y.deepPkg + row * dpRowH };
  });

  // Upstream: anchor near their vendor
  // Build a quick lookup: vendor → upstream nodes via edges
  const vendorForUpstream: Record<string, { x: number; y: number }> = {};
  edges.forEach((e) => {
    if (e.source.startsWith('vendor:') && e.target.startsWith('upstream:')) {
      if (pos[e.source]) vendorForUpstream[e.target] = pos[e.source];
    }
  });

  // Group upstream by vendor anchor
  const upstreamByVendor: Record<string, GraphNode[]> = {};
  upstreamNodes.forEach((n) => {
    const anchor = vendorForUpstream[n.id];
    const key = anchor ? `${anchor.x}` : 'default';
    (upstreamByVendor[key] = upstreamByVendor[key] || []).push(n);
  });

  Object.entries(upstreamByVendor).forEach(([key, ups]) => {
    const anchorX = key === 'default' ? 0 : parseFloat(key);
    const spacing = 160;
    const startX = anchorX - ((ups.length - 1) * spacing) / 2;
    ups.forEach((n, i) => {
      pos[n.id] = { x: startX + i * spacing, y: Y.upstream };
    });
  });

  return pos;
}

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
  const [categoryFilter, setCategoryFilter] = useState<'all' | 'direct' | 'transitive' | 'deep' | 'vendors' | 'vulnerable'>('all');

  useEffect(() => {
    if (!containerRef.current || !graphData) return;

    let activeNodes = graphData.nodes;
    let activeEdges = graphData.edges;

    if (filterLayer === 'declared_only') {
      activeNodes = activeNodes.filter(
        (n) => n.provenance === 'declared' || (n.type as string) === 'infrastructure_resource'
      );
      const nodeIds = new Set(activeNodes.map((n) => n.id));
      activeEdges = activeEdges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target));
    } else if (filterLayer === 'observed_only') {
      activeNodes = activeNodes.filter(
        (n) => n.provenance === 'observed' || n.type === 'external_api'
      );
      const nodeIds = new Set(activeNodes.map((n) => n.id));
      activeEdges = activeEdges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target));
    } else if (filterLayer === 'discrepancies_only') {
      activeNodes = activeNodes.filter(
        (n) => n.provenance === 'observed' || n.status === 'compromised'
      );
      const nodeIds = new Set(activeNodes.map((n) => n.id));
      activeEdges = activeEdges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target));
    }

    // Interactive category filter from top pill bar
    if (categoryFilter === 'direct') {
      const matchIds = new Set(
        activeNodes.filter((n) => n.type === 'software_package' && (n as any).subtype === 'direct').map((n) => n.id)
      );
      const connectedEdges = activeEdges.filter((e) => matchIds.has(e.source) || matchIds.has(e.target));
      const connectedNodeIds = new Set<string>();
      matchIds.forEach((id) => connectedNodeIds.add(id));
      connectedEdges.forEach((e) => { connectedNodeIds.add(e.source); connectedNodeIds.add(e.target); });
      activeNodes = activeNodes.filter((n) => connectedNodeIds.has(n.id));
      activeEdges = connectedEdges;
    } else if (categoryFilter === 'transitive') {
      const matchIds = new Set(
        activeNodes.filter((n) => n.type === 'software_package' && (n as any).subtype === 'transitive').map((n) => n.id)
      );
      const connectedEdges = activeEdges.filter((e) => matchIds.has(e.source) || matchIds.has(e.target));
      const connectedNodeIds = new Set<string>();
      matchIds.forEach((id) => connectedNodeIds.add(id));
      connectedEdges.forEach((e) => { connectedNodeIds.add(e.source); connectedNodeIds.add(e.target); });
      activeNodes = activeNodes.filter((n) => connectedNodeIds.has(n.id));
      activeEdges = connectedEdges;
    } else if (categoryFilter === 'deep') {
      const matchIds = new Set(
        activeNodes.filter((n) => n.type === 'software_package' && (n as any).subtype === 'deep_transitive').map((n) => n.id)
      );
      const connectedEdges = activeEdges.filter((e) => matchIds.has(e.source) || matchIds.has(e.target));
      const connectedNodeIds = new Set<string>();
      matchIds.forEach((id) => connectedNodeIds.add(id));
      connectedEdges.forEach((e) => { connectedNodeIds.add(e.source); connectedNodeIds.add(e.target); });
      activeNodes = activeNodes.filter((n) => connectedNodeIds.has(n.id));
      activeEdges = connectedEdges;
    } else if (categoryFilter === 'vendors') {
      const matchIds = new Set(
        activeNodes
          .filter(
            (n) =>
              n.type === 'vendor' ||
              n.type === 'external_api' ||
              n.id.startsWith('vendor:') ||
              n.id.startsWith('upstream:')
          )
          .map((n) => n.id)
      );
      const connectedEdges = activeEdges.filter((e) => matchIds.has(e.source) || matchIds.has(e.target));
      const connectedNodeIds = new Set<string>();
      matchIds.forEach((id) => connectedNodeIds.add(id));
      connectedEdges.forEach((e) => { connectedNodeIds.add(e.source); connectedNodeIds.add(e.target); });
      activeNodes = activeNodes.filter((n) => connectedNodeIds.has(n.id));
      activeEdges = connectedEdges;
    } else if (categoryFilter === 'vulnerable') {
      const matchIds = new Set(
        activeNodes.filter((n) => n.status === 'compromised').map((n) => n.id)
      );
      const connectedEdges = activeEdges.filter((e) => matchIds.has(e.source) || matchIds.has(e.target));
      const connectedNodeIds = new Set<string>();
      matchIds.forEach((id) => connectedNodeIds.add(id));
      connectedEdges.forEach((e) => { connectedNodeIds.add(e.source); connectedNodeIds.add(e.target); });
      activeNodes = activeNodes.filter((n) => connectedNodeIds.has(n.id));
      activeEdges = connectedEdges;
    }

    // Smart node capping: keep all non-package nodes; cap packages
    const nonPkgNodes = activeNodes.filter((n) => n.type !== 'software_package');
    const directPkgs = activeNodes
      .filter((n) => n.type === 'software_package' && (n as any).subtype === 'direct')
      .sort((a, b) => {
        if (a.status === 'compromised' && b.status !== 'compromised') return -1;
        if (b.status === 'compromised' && a.status !== 'compromised') return 1;
        return a.label.localeCompare(b.label);
      });
    const transPkgs = activeNodes
      .filter((n) => n.type === 'software_package' && (n as any).subtype === 'transitive')
      .sort((a, b) => {
        if (a.status === 'compromised' && b.status !== 'compromised') return -1;
        if (b.status === 'compromised' && a.status !== 'compromised') return 1;
        return a.label.localeCompare(b.label);
      });
    const deepPkgs = activeNodes
      .filter((n) => n.type === 'software_package' && (n as any).subtype === 'deep_transitive')
      .sort((a, b) => {
        if (a.status === 'compromised' && b.status !== 'compromised') return -1;
        if (b.status === 'compromised' && a.status !== 'compromised') return 1;
        return a.label.localeCompare(b.label);
      });

    const MAX_DIRECT = 50;
    const MAX_TRANSITIVE = 35;
    const MAX_DEEP = 30;
    const cappedDirect = directPkgs.slice(0, MAX_DIRECT);
    const cappedTrans = transPkgs.slice(0, MAX_TRANSITIVE);
    const cappedDeep = deepPkgs.slice(0, MAX_DEEP);

    const displayNodes = [...nonPkgNodes, ...cappedDirect, ...cappedTrans, ...cappedDeep];
    const displayNodeIds = new Set(displayNodes.map((n) => n.id));
    const displayEdges = activeEdges.filter(
      (e) => displayNodeIds.has(e.source) && displayNodeIds.has(e.target)
    );

    // Compute positions for hierarchical layout
    const positions = layoutMode === 'hierarchical'
      ? computeManualLayout(displayNodes, displayEdges.map((e) => ({ source: e.source, target: e.target })))
      : {};

    const elements = [
      ...displayNodes.map((node) => {
        const style = getNodeStyle(node);
        const nodePos = positions[node.id] || { x: Math.random() * 800 - 400, y: Math.random() * 600 - 300 };
        return {
          data: {
            id: node.id,
            label: node.label,
            type: node.type,
            subtype: (node as any).subtype || '',
            provenance: node.provenance,
            status: node.status,
            criticality: node.criticality,
            raw: node,
            bg: style.bg,
            border: style.border,
            textColor: style.text,
            nodeWidth: style.w,
            nodeHeight: style.h,
            nodeShape: style.shape,
          },
          position: nodePos,
        };
      }),
      ...displayEdges.map((edge) => ({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          relation: edge.relation,
          provenance: edge.provenance,
        },
      })),
    ];

    // Layout configs
    const presetLayout: any = {
      name: 'preset',
      fit: true,
      padding: 80,
      animate: false,
    };

    const coseLayout: any = {
      name: 'cose',
      animate: false,
      padding: 80,
      nodeRepulsion: () => 900000,
      idealEdgeLength: () => 180,
      edgeElasticity: () => 250,
      nestingFactor: 1.5,
      gravity: 0.15,
      numIter: 2500,
      fit: true,
    };

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        // Base node style
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': 'data(textColor)',
            'font-family': '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
            'font-size': '12px',
            'font-weight': 600,
            'text-valign': 'bottom',
            'text-halign': 'center',
            'text-margin-y': 9,
            'text-background-color': '#060209',
            'text-background-opacity': 0.92,
            'text-background-padding': '4px',
            'text-background-shape': 'roundrectangle',
            'text-border-color': '#1E1B2E',
            'text-border-width': 1,
            'text-border-opacity': 0.8,
            'text-max-width': '155px',
            'text-wrap': 'wrap',
            'background-color': 'data(bg)',
            'border-width': 2,
            'border-color': 'data(border)',
            'width': 'data(nodeWidth)',
            'height': 'data(nodeHeight)',
            'shape': 'round-rectangle',
            'transition-property': 'border-color, border-width, background-color',
            'transition-duration': 200,
          },
        },

        // Per-type shapes (overrides base round-rectangle)
        { selector: 'node[type = "business_journey"]', style: { 'shape': 'star' } },
        { selector: 'node[type = "internal_service"]', style: { 'shape': 'ellipse' } },
        { selector: 'node[type = "infrastructure_resource"]', style: { 'shape': 'barrel' } },
        { selector: 'node[type = "vendor"], node[type = "external_api"]', style: { 'shape': 'cut-rectangle' } },
        { selector: 'node[type = "vendor_upstream"]', style: { 'shape': 'tag' } },
        { selector: 'node[type = "software_package"][subtype = "transitive"]', style: { 'shape': 'diamond' } },
        { selector: 'node[type = "software_package"][subtype = "deep_transitive"]', style: { 'shape': 'diamond' } },

        // Hovered
        {
          selector: 'node:hover',
          style: {
            'border-width': 3,
            'z-index': 500,
          },
        },

        // Selected node ring
        {
          selector: 'node.selected-node',
          style: {
            'border-color': '#FFFFFF',
            'border-width': 4.5,
            'z-index': 1000,
          },
        },

        // Blast radius (vivid red)
        {
          selector: 'node.blast-radius-node',
          style: {
            'border-color': '#EF4444',
            'border-width': 5,
            'background-color': '#7F1D1D',
            'z-index': 999,
          },
        },
        {
          selector: 'edge.blast-radius-edge',
          style: {
            'line-color': '#EF4444',
            'target-arrow-color': '#EF4444',
            'width': 3,
            'opacity': 1,
            'z-index': 998,
          },
        },

        // Compromised CVE
        {
          selector: 'node[status = "compromised"]',
          style: {
            'border-color': '#EF4444',
            'border-width': 3,
          },
        },

        // Observed / Shadow (dashed border)
        {
          selector: 'node[provenance = "observed"]',
          style: {
            'border-style': 'dashed',
          },
        },

        // Base edge
        {
          selector: 'edge',
          style: {
            'width': 1.8,
            'line-color': '#334155',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 1.0,
            'curve-style': 'bezier',
            'line-style': 'solid',
            'opacity': 0.8,
          },
        },

        // calls_service – violet
        {
          selector: 'edge[relation = "calls_service"]',
          style: {
            'line-color': '#7C3AED',
            'target-arrow-color': '#8B5CF6',
            'width': 2.5,
          },
        },

        // depends_on – sky blue (direct package)
        {
          selector: 'edge[relation = "depends_on"]',
          style: {
            'line-color': '#0284C7',
            'target-arrow-color': '#38BDF8',
            'width': 1.8,
          },
        },

        // depends_on_transitive – dashed slate
        {
          selector: 'edge[relation = "depends_on_transitive"]',
          style: {
            'line-style': 'dashed',
            'line-color': '#334155',
            'target-arrow-color': '#475569',
            'width': 1.4,
            'opacity': 0.55,
          },
        },

        // depends_on_deep_transitive – dotted subtle slate (3rd layer)
        {
          selector: 'edge[relation = "depends_on_deep_transitive"]',
          style: {
            'line-style': 'dotted',
            'line-color': '#1E293B',
            'target-arrow-color': '#334155',
            'width': 1.2,
            'opacity': 0.5,
          },
        },

        // calls_api – red dashed (external vendor)
        {
          selector: 'edge[relation = "calls_api"]',
          style: {
            'line-color': '#DC2626',
            'target-arrow-color': '#EF4444',
            'width': 1.8,
            'line-style': 'dashed',
          },
        },

        // queries_database / uses_cache – emerald
        {
          selector: 'edge[relation = "queries_database"], edge[relation = "uses_cache"]',
          style: {
            'line-color': '#059669',
            'target-arrow-color': '#34D399',
            'width': 2,
          },
        },

        // powers_journey – amber dotted
        {
          selector: 'edge[relation = "powers_journey"]',
          style: {
            'line-color': '#D97706',
            'target-arrow-color': '#FBBF24',
            'width': 1.8,
            'line-style': 'dotted',
            'opacity': 0.7,
          },
        },

        // relies_on_upstream – indigo dotted
        {
          selector: 'edge[relation = "relies_on_upstream"]',
          style: {
            'line-color': '#4F46E5',
            'target-arrow-color': '#818CF8',
            'width': 1.4,
            'line-style': 'dotted',
            'opacity': 0.6,
          },
        },
      ],
      layout: layoutMode === 'hierarchical' ? presetLayout : coseLayout,
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

    cy.one('layoutstop', () => {
      cy.fit(undefined, 80);
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [graphData, filterLayer, layoutMode, categoryFilter]);

  // Selected node & blast radius highlight
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      cy.nodes().removeClass('blast-radius-node selected-node');
      cy.edges().removeClass('blast-radius-edge');

      if (selectedNodeId) {
        const node = cy.getElementById(selectedNodeId);
        if (node.length > 0) node.addClass('selected-node');
      }

      if (blastRadiusIds.length > 0) {
        const blastSet = new Set(blastRadiusIds);
        blastRadiusIds.forEach((id) => {
          const node = cy.getElementById(id);
          if (node.length > 0) node.addClass('blast-radius-node');
        });
        cy.edges().forEach((edge) => {
          if (blastSet.has(edge.data('source')) || blastSet.has(edge.data('target'))) {
            edge.addClass('blast-radius-edge');
          }
        });
      }
    });
  }, [selectedNodeId, blastRadiusIds]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current?.fit(undefined, 80);
  const handleReset = () => { cyRef.current?.reset(); handleFit(); };

  // Graph stats for info bar
  const stats = graphData ? {
    total: graphData.nodes.length,
    direct: graphData.nodes.filter((n) => n.type === 'software_package' && (n as any).subtype === 'direct').length,
    transitive: graphData.nodes.filter((n) => n.type === 'software_package' && (n as any).subtype === 'transitive').length,
    deep: graphData.nodes.filter((n) => n.type === 'software_package' && (n as any).subtype === 'deep_transitive').length,
    vendors: graphData.nodes.filter((n) => n.type === 'vendor' || n.type === 'external_api').length,
    vulnerable: graphData.nodes.filter((n) => n.status === 'compromised').length,
  } : null;

  return (
    <div className="w-full h-full relative bg-[#060205] overflow-hidden select-none">
      {/* Cytoscape Canvas */}
      <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

      {/* Top Stats Bar & Interactive Category Filters */}
      {stats && (
        <div className="absolute top-3 left-1/2 -translate-x-1/2 z-20 flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-zinc-950/90 border border-zinc-800 backdrop-blur-xl shadow-xl">
          <button
            onClick={() => setCategoryFilter('all')}
            className={`text-[11px] font-medium px-2 py-0.5 rounded-full transition-all cursor-pointer ${
              categoryFilter === 'all'
                ? 'bg-zinc-800 text-white shadow-sm ring-1 ring-white/20'
                : 'text-zinc-400 hover:text-white'
            }`}
            title="Reset filter to show all graph nodes"
          >
            {stats.total} nodes
          </button>
          <span className="w-px h-3 bg-zinc-800" />
          <button
            onClick={() => setCategoryFilter(categoryFilter === 'direct' ? 'all' : 'direct')}
            className={`text-[11px] font-medium px-2 py-0.5 rounded-full transition-all cursor-pointer ${
              categoryFilter === 'direct'
                ? 'bg-sky-500/20 text-sky-300 ring-1 ring-sky-500/60 shadow-sm'
                : 'text-sky-400 hover:text-sky-200 hover:bg-sky-500/10'
            }`}
            title="Filter graph to direct dependencies"
          >
            {stats.direct} direct pkgs
          </button>
          <span className="w-px h-3 bg-zinc-800" />
          <button
            onClick={() => setCategoryFilter(categoryFilter === 'transitive' ? 'all' : 'transitive')}
            className={`text-[11px] font-medium px-2 py-0.5 rounded-full transition-all cursor-pointer ${
              categoryFilter === 'transitive'
                ? 'bg-slate-700/60 text-slate-100 ring-1 ring-slate-500/60 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/20'
            }`}
            title="Filter graph to transitive dependencies"
          >
            {stats.transitive} transitive
          </button>
          {stats.deep > 0 && (
            <>
              <span className="w-px h-3 bg-zinc-800" />
              <button
                onClick={() => setCategoryFilter(categoryFilter === 'deep' ? 'all' : 'deep')}
                className={`text-[11px] font-medium px-2 py-0.5 rounded-full transition-all cursor-pointer ${
                  categoryFilter === 'deep'
                    ? 'bg-indigo-500/20 text-indigo-300 ring-1 ring-indigo-500/60 shadow-sm'
                    : 'text-indigo-400 hover:text-indigo-200 hover:bg-indigo-500/10'
                }`}
                title="Filter graph to 3rd-layer deep dependencies"
              >
                {stats.deep} 3rd-layer deep
              </button>
            </>
          )}
          <span className="w-px h-3 bg-zinc-800" />
          <button
            onClick={() => setCategoryFilter(categoryFilter === 'vendors' ? 'all' : 'vendors')}
            className={`text-[11px] font-medium px-2 py-0.5 rounded-full transition-all cursor-pointer ${
              categoryFilter === 'vendors'
                ? 'bg-rose-500/20 text-rose-300 ring-1 ring-rose-500/60 shadow-sm'
                : 'text-rose-400 hover:text-rose-200 hover:bg-rose-500/10'
            }`}
            title="Filter graph to external vendors and APIs"
          >
            {stats.vendors} vendors/APIs
          </button>
          {stats.vulnerable > 0 && (
            <>
              <span className="w-px h-3 bg-zinc-800" />
              <button
                onClick={() => setCategoryFilter(categoryFilter === 'vulnerable' ? 'all' : 'vulnerable')}
                className={`text-[11px] font-semibold px-2 py-0.5 rounded-full transition-all cursor-pointer ${
                  categoryFilter === 'vulnerable'
                    ? 'bg-red-500/30 text-red-200 ring-1 ring-red-500/70 shadow-sm animate-pulse'
                    : 'text-red-400 hover:text-red-200 hover:bg-red-500/10 animate-pulse'
                }`}
                title="Filter graph to vulnerable compromised components"
              >
                {stats.vulnerable} ⚠ CVE/Outage
              </button>
            </>
          )}
        </div>
      )}

      {/* Map Legend */}
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
          <div className="w-72 rounded-2xl bg-zinc-950/97 border border-zinc-800 backdrop-blur-2xl shadow-2xl overflow-hidden">
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
            <div className="p-4 space-y-4 text-xs">
              {/* Node types */}
              <div>
                <span className="text-[10px] font-semibold tracking-wider text-zinc-500 uppercase block mb-2">Node Types</span>
                <div className="grid grid-cols-2 gap-y-2.5 gap-x-3 text-[11px]">
                  {[
                    { icon: <Star className="w-3.5 h-3.5 text-amber-400 shrink-0" />, label: 'Business Journey', color: 'text-amber-300' },
                    { icon: <Server className="w-3.5 h-3.5 text-blue-400 shrink-0" />, label: 'Application', color: 'text-blue-300' },
                    { icon: <Cpu className="w-3.5 h-3.5 text-purple-400 shrink-0" />, label: 'Internal Service', color: 'text-purple-300' },
                    { icon: <Database className="w-3.5 h-3.5 text-emerald-400 shrink-0" />, label: 'DB / Cache', color: 'text-emerald-300' },
                    { icon: <Package className="w-3.5 h-3.5 text-sky-400 shrink-0" />, label: 'Direct Package', color: 'text-sky-300' },
                    { icon: <Layers className="w-3.5 h-3.5 text-slate-400 shrink-0" />, label: 'Transitive Dep', color: 'text-slate-400' },
                    { icon: <Cloud className="w-3.5 h-3.5 text-rose-400 shrink-0" />, label: 'Cloud Vendor / API', color: 'text-rose-300' },
                    { icon: <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />, label: 'CVE Risk (red border)', color: 'text-red-400' },
                  ].map(({ icon, label, color }) => (
                    <div key={label} className="flex items-center gap-2">
                      {icon}
                      <span className={`${color}`}>{label}</span>
                    </div>
                  ))}
                </div>
              </div>
              {/* Edge types */}
              <div className="border-t border-zinc-800/80 pt-3">
                <span className="text-[10px] font-semibold tracking-wider text-zinc-500 uppercase block mb-2">Connections</span>
                <div className="space-y-2 text-[11px]">
                  {[
                    { color: 'bg-violet-500', label: 'Service Call', style: 'Solid' },
                    { color: 'bg-sky-500', label: 'Package Dependency', style: 'Solid' },
                    { color: 'bg-emerald-500', label: 'Database / Cache', style: 'Solid' },
                    { color: 'bg-amber-500', label: 'Powers Journey', style: 'Dotted' },
                    { color: 'bg-red-500', label: 'External API', style: 'Dashed' },
                    { color: 'bg-slate-500', label: 'Transitive Sub-dep', style: 'Dashed' },
                    { color: 'bg-indigo-400', label: 'Upstream Infra', style: 'Dotted' },
                    { color: 'bg-red-400', label: 'Blast Radius', style: 'Highlighted' },
                  ].map(({ color, label, style }) => (
                    <div key={label} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className={`w-5 h-0.5 ${color} rounded block`} />
                        <span className="text-zinc-300">{label}</span>
                      </div>
                      <span className="text-zinc-600 text-[10px]">{style}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="border-t border-zinc-800/60 pt-2 text-[10px] text-zinc-600 leading-relaxed">
                Shows up to 50 direct + 40 transitive packages. Vulnerable packages are shown first.
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Floating Controls */}
      <div className="absolute bottom-6 right-6 z-20 flex flex-col gap-2">
        {/* Zoom controls */}
        <div className="flex items-center justify-end gap-1 bg-zinc-950/90 backdrop-blur-xl border border-zinc-800 rounded-xl p-1.5 shadow-xl">
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
