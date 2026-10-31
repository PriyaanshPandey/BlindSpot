"""
Graph Engine [Role B]:
Constructs the unified dependency graph using NetworkX and detects discrepancies.
"""
import networkx as nx
from typing import Dict, Any, List

class GraphEngine:
    def __init__(self):
        self.nx_graph = nx.DiGraph()

    def add_node(self, node_id: str, **attributes):
        self.nx_graph.add_node(node_id, **attributes)

    def add_edge(self, source: str, target: str, **attributes):
        self.nx_graph.add_edge(source, target, **attributes)

    def get_blast_radius(self, target_node_id: str) -> List[str]:
        """Calculates upstream impacted nodes when target_node_id fails."""
        if target_node_id not in self.nx_graph:
            return []
        # Predecessors in directed dependency graph depend on this node
        try:
            impacted = list(nx.ancestors(self.nx_graph, target_node_id))
            impacted.append(target_node_id)
            return impacted
        except Exception:
            return [target_node_id]

