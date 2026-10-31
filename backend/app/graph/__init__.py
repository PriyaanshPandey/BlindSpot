"""
Unified Dependency Graph Engine [Role B]:
Constructs, manages, analyzes, and traverses the evidence-backed dependency graph using NetworkX.
Implements the canonical schema defined in contracts/graph-schema.json.
"""
import networkx as nx
from typing import Dict, Any, List, Optional, Set, Tuple, Union
from datetime import datetime
import uuid

from app.models import (
    NodeType,
    NodeProvenance,
    NodeStatus,
    Criticality,
    EdgeRelation,
    EdgeProvenance,
    NodeModel,
    EdgeModel,
    GraphData,
    GraphMetadata
)

class GraphEngine:
    def __init__(self, scan_id: Optional[str] = None):
        self.scan_id = scan_id or str(uuid.uuid4())
        # Directed graph: Edge (A, B) means A depends on / calls / routes to B
        # Therefore, if B fails, A is directly impacted.
        self.nx_graph = nx.DiGraph()
        self.created_at = datetime.utcnow().isoformat()
        self.target_name = "Target Application"

    def add_node(
        self,
        node_id: str,
        label: str,
        node_type: Union[NodeType, str],
        subtype: Optional[str] = None,
        version: Optional[str] = None,
        provenance: Union[NodeProvenance, str] = NodeProvenance.DECLARED,
        status: Union[NodeStatus, str] = NodeStatus.HEALTHY,
        criticality: Union[Criticality, str] = Criticality.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Adds or updates a node in the NetworkX graph with full canonical properties."""
        type_val = node_type.value if isinstance(node_type, NodeType) else str(node_type)
        prov_val = provenance.value if isinstance(provenance, NodeProvenance) else str(provenance)
        status_val = status.value if isinstance(status, NodeStatus) else str(status)
        crit_val = criticality.value if isinstance(criticality, Criticality) else str(criticality)

        node_attrs = {
            "id": node_id,
            "label": label,
            "type": type_val,
            "subtype": subtype,
            "version": version,
            "provenance": prov_val,
            "status": status_val,
            "criticality": crit_val,
            "metadata": metadata or {}
        }
        self.nx_graph.add_node(node_id, **node_attrs)
        return node_attrs

    def add_edge(
        self,
        source: str,
        target: str,
        relation: Union[EdgeRelation, str] = EdgeRelation.DEPENDS_ON,
        provenance: Union[EdgeProvenance, str] = EdgeProvenance.DECLARED,
        confidence_score: float = 1.0,
        evidence_ids: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        edge_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Adds or updates a directed edge from source to target."""
        rel_val = relation.value if isinstance(relation, EdgeRelation) else str(relation)
        prov_val = provenance.value if isinstance(provenance, EdgeProvenance) else str(provenance)
        e_id = edge_id or f"edge:{source}->{target}:{rel_val}"

        edge_attrs = {
            "id": e_id,
            "source": source,
            "target": target,
            "relation": rel_val,
            "provenance": prov_val,
            "confidence_score": float(confidence_score),
            "evidence_ids": evidence_ids or [],
            "metadata": metadata or {}
        }
        self.nx_graph.add_edge(source, target, **edge_attrs)
        return edge_attrs

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        if node_id in self.nx_graph:
            return dict(self.nx_graph.nodes[node_id])
        return None

    def get_edge(self, source: str, target: str) -> Optional[Dict[str, Any]]:
        if self.nx_graph.has_edge(source, target):
            return dict(self.nx_graph.edges[source, target])
        return None

    # --- Traversal & Blast Radius Algorithms ---

    def get_direct_downstream(self, node_id: str) -> List[str]:
        """Dependencies that this node directly relies on (successors in A -> B)."""
        if node_id not in self.nx_graph:
            return []
        return list(self.nx_graph.successors(node_id))

    def get_direct_upstream(self, node_id: str) -> List[str]:
        """Components that directly rely on this node (predecessors in A -> B)."""
        if node_id not in self.nx_graph:
            return []
        return list(self.nx_graph.predecessors(node_id))

    def get_blast_radius(self, target_node_id: str) -> List[str]:
        """
        Calculates all upstream components that are impacted if target_node_id experiences an outage.
        In our dependency graph where Edge(A, B) represents 'A depends on B',
        ancestors of B (predecessors recursively) are the systems that depend on B.
        Returns target_node_id plus all upstream impacted nodes.
        """
        if target_node_id not in self.nx_graph:
            return [target_node_id]

        try:
            # nx.ancestors returns all nodes having a path to target_node_id
            impacted = set(nx.ancestors(self.nx_graph, target_node_id))
            impacted.add(target_node_id)
            return list(impacted)
        except Exception:
            return [target_node_id]

    def find_dependency_chains(self, source_id: str, target_id: str) -> List[List[str]]:
        """Finds all dependency paths from source to target."""
        if source_id not in self.nx_graph or target_id not in self.nx_graph:
            return []
        try:
            return list(nx.all_simple_paths(self.nx_graph, source=source_id, target=target_id, cutoff=10))
        except Exception:
            return []

    def get_isolated_nodes(self) -> List[str]:
        """Identifies isolated nodes with no incoming or outgoing connections."""
        return list(nx.isolates(self.nx_graph))

    def get_subgraph_for_journey(self, journey_id: str) -> List[str]:
        """Returns all nodes contributing to or powering a business journey."""
        if journey_id not in self.nx_graph:
            return []
        # Journey nodes have incoming edges (relation="powers_journey")
        return list(nx.ancestors(self.nx_graph, journey_id))

    # --- Serialization and Filtering ---

    def to_dict(self, filter_layer: str = "all") -> Dict[str, Any]:
        """
        Exports the graph to the contracts/graph-schema.json format.
        Supports filter_layer:
          - 'all': complete graph
          - 'declared_only': only declared nodes and edges
          - 'observed_only': only observed nodes and edges + their immediate connections
          - 'discrepancies_only': nodes with warnings/discrepancies and their paths
        """
        filtered_nodes = []
        filtered_edges = []
        allowed_node_ids: Set[str] = set()

        all_nodes = [dict(self.nx_graph.nodes[n]) for n in self.nx_graph.nodes]
        all_edges = [dict(self.nx_graph.edges[u, v]) for u, v in self.nx_graph.edges]

        if filter_layer == "declared_only":
            for n in all_nodes:
                if n.get("provenance") in ["declared", "inferred"]:
                    filtered_nodes.append(n)
                    allowed_node_ids.add(n["id"])
            for e in all_edges:
                if e.get("provenance") == "declared" and e["source"] in allowed_node_ids and e["target"] in allowed_node_ids:
                    filtered_edges.append(e)

        elif filter_layer == "observed_only":
            for n in all_nodes:
                if n.get("provenance") in ["observed", "inferred", "disclosed", "vendor_passport"]:
                    filtered_nodes.append(n)
                    allowed_node_ids.add(n["id"])
            for e in all_edges:
                if e.get("provenance") in ["observed", "vendor_passport"] or (e["source"] in allowed_node_ids and e["target"] in allowed_node_ids):
                    filtered_edges.append(e)

        elif filter_layer == "discrepancies_only":
            discrepancy_nodes = {
                n["id"] for n in all_nodes
                if n.get("status") in ["warning", "compromised"] or n.get("provenance") == "observed"
            }
            # Include discrepancy nodes and their direct neighbors
            for d_id in list(discrepancy_nodes):
                if d_id in self.nx_graph:
                    discrepancy_nodes.update(self.nx_graph.predecessors(d_id))
                    discrepancy_nodes.update(self.nx_graph.successors(d_id))

            for n in all_nodes:
                if n["id"] in discrepancy_nodes:
                    filtered_nodes.append(n)
                    allowed_node_ids.add(n["id"])
            for e in all_edges:
                if e["source"] in allowed_node_ids and e["target"] in allowed_node_ids:
                    filtered_edges.append(e)

        else: # "all"
            filtered_nodes = all_nodes
            filtered_edges = all_edges

        # Calculate counts
        discrepancy_count = sum(
            1 for n in all_nodes if n.get("status") == "warning" or n.get("provenance") == "observed"
        )
        vulnerability_count = sum(
            1 for n in all_nodes if n.get("status") == "compromised"
        )

        return {
            "scan_id": self.scan_id,
            "created_at": self.created_at,
            "metadata": {
                "target_name": self.target_name,
                "total_nodes": len(filtered_nodes),
                "total_edges": len(filtered_edges),
                "discrepancy_count": discrepancy_count,
                "vulnerability_count": vulnerability_count
            },
            "nodes": filtered_nodes,
            "edges": filtered_edges
        }

    # --- Builder from Evidence ---

    @classmethod
    def from_evidence(
        cls,
        scan_id: str,
        project_name: str,
        dependencies: Dict[str, str],
        observed_hosts: List[str],
        vulnerabilities: List[Dict[str, Any]],
        runtime_traces: Optional[List[Dict[str, Any]]] = None,
        vendor_passports: Optional[List[Dict[str, Any]]] = None,
        deployed_components: Optional[List[Dict[str, Any]]] = None
    ) -> "GraphEngine":
        """
        Constructs an evidence-backed unified dependency graph from normalized scan results.
        """
        engine = cls(scan_id=scan_id)
        engine.target_name = project_name
        clean_name = project_name.replace(" ", "-").lower()

        # 1. Application Root Node
        app_id = f"app:{clean_name}"
        engine.add_node(
            node_id=app_id,
            label=f"{project_name}",
            node_type=NodeType.APPLICATION,
            provenance=NodeProvenance.DECLARED,
            status=NodeStatus.HEALTHY,
            criticality=Criticality.CRITICAL,
            metadata={"source": "project_root"}
        )

        # 2. Internal Core Service
        core_service_id = f"service:{clean_name}-core"
        engine.add_node(
            node_id=core_service_id,
            label=f"{project_name} Core Engine",
            node_type=NodeType.INTERNAL_SERVICE,
            provenance=NodeProvenance.DECLARED,
            status=NodeStatus.HEALTHY,
            criticality=Criticality.CRITICAL
        )
        engine.add_edge(
            source=app_id,
            target=core_service_id,
            relation=EdgeRelation.CALLS_API,
            provenance=EdgeProvenance.DECLARED,
            confidence_score=1.0,
            evidence_ids=[f"ev:root_link"]
        )

        # 3. Software Package Nodes (Declared Dependencies)
        for pkg_name, ver in dependencies.items():
            clean_ver = str(ver).replace("^", "").replace("~", "").replace(">", "").replace("=", "").strip()
            is_vuln = any(v.get("package") == pkg_name for v in vulnerabilities)
            vuln_obj = next((v for v in vulnerabilities if v.get("package") == pkg_name), None)

            pkg_id = f"pkg:{pkg_name}"
            status = NodeStatus.COMPROMISED if is_vuln else NodeStatus.HEALTHY
            crit = Criticality.CRITICAL if is_vuln else Criticality.MEDIUM

            engine.add_node(
                node_id=pkg_id,
                label=f"{pkg_name}@{clean_ver}",
                node_type=NodeType.SOFTWARE_PACKAGE,
                version=clean_ver,
                provenance=NodeProvenance.DECLARED,
                status=status,
                criticality=crit,
                metadata={
                    "package_name": pkg_name,
                    "declared_version": ver,
                    "vulnerability": vuln_obj
                }
            )
            engine.add_edge(
                source=core_service_id,
                target=pkg_id,
                relation=EdgeRelation.DEPENDS_ON,
                provenance=EdgeProvenance.DECLARED,
                confidence_score=1.0,
                evidence_ids=[f"ev:pkg:{pkg_name}"]
            )

        # 4. Known Vendor vs Observed External APIs
        KNOWN_VENDORS = {
            "stripe.com": {"id": "vendor:stripe", "name": "Stripe Payments", "type": NodeType.VENDOR},
            "auth0.com": {"id": "vendor:auth0", "name": "Auth0 Identity", "type": NodeType.VENDOR},
            "twilio.com": {"id": "vendor:twilio", "name": "Twilio Communications", "type": NodeType.VENDOR},
            "sendgrid.com": {"id": "vendor:sendgrid", "name": "SendGrid Email", "type": NodeType.VENDOR},
            "cloudflare.com": {"id": "vendor:cloudflare", "name": "Cloudflare CDN", "type": NodeType.VENDOR},
            "amazonaws.com": {"id": "vendor:aws", "name": "Amazon Web Services", "type": NodeType.INFRASTRUCTURE_RESOURCE}
        }

        # Index trace evidence
        trace_endpoints: Dict[str, List[Dict[str, Any]]] = {}
        if runtime_traces:
            for t in runtime_traces:
                dest = t.get("destination_host", "")
                if dest:
                    trace_endpoints.setdefault(dest, []).append(t)

        for host in observed_hosts:
            matching_vendor_key = next((k for k in KNOWN_VENDORS if k in host.lower()), None)

            if matching_vendor_key:
                v_meta = KNOWN_VENDORS[matching_vendor_key]
                v_id = v_meta["id"]
                engine.add_node(
                    node_id=v_id,
                    label=v_meta["name"],
                    node_type=v_meta["type"],
                    provenance=NodeProvenance.DECLARED,
                    status=NodeStatus.HEALTHY,
                    criticality=Criticality.CRITICAL,
                    metadata={"host": host, "domain": matching_vendor_key}
                )
                engine.add_edge(
                    source=core_service_id,
                    target=v_id,
                    relation=EdgeRelation.CALLS_API,
                    provenance=EdgeProvenance.OBSERVED,
                    confidence_score=0.99,
                    evidence_ids=[f"ev:host:{host}"]
                )
            else:
                # Undocumented / Observed external connection
                ext_id = f"ext:{host}"
                engine.add_node(
                    node_id=ext_id,
                    label=host,
                    node_type=NodeType.EXTERNAL_API,
                    provenance=NodeProvenance.OBSERVED,
                    status=NodeStatus.WARNING,
                    criticality=Criticality.HIGH,
                    metadata={"host": host, "is_undocumented": True}
                )
                engine.add_edge(
                    source=app_id,
                    target=ext_id,
                    relation=EdgeRelation.CALLS_API,
                    provenance=EdgeProvenance.OBSERVED,
                    confidence_score=0.95,
                    evidence_ids=[f"ev:trace:{host}"]
                )

        # 5. Vendor Passports (Disclosed Transitive Dependencies)
        if vendor_passports:
            for vp in vendor_passports:
                v_id = vp.get("vendor_id")
                if v_id and v_id in engine.nx_graph:
                    for sub in vp.get("subprocessors", []):
                        sub_name = sub.get("provider", "Unknown Subprocessor")
                        sub_id = f"infra:{sub_name.lower().replace(' ', '-')}"
                        engine.add_node(
                            node_id=sub_id,
                            label=sub_name,
                            node_type=NodeType.INFRASTRUCTURE_RESOURCE,
                            provenance=NodeProvenance.DISCLOSED,
                            status=NodeStatus.HEALTHY,
                            criticality=Criticality.CRITICAL
                        )
                        engine.add_edge(
                            source=v_id,
                            target=sub_id,
                            relation=EdgeRelation.DEPENDS_ON,
                            provenance=EdgeProvenance.VENDOR_PASSPORT,
                            confidence_score=0.98,
                            evidence_ids=[f"ev:passport:{v_id}"]
                        )

        # 6. Business Journeys (Inferred)
        journeys = [
            ("journey:checkout", "Journey: Customer Checkout & Payment", core_service_id, "vendor:stripe"),
            ("journey:auth", "Journey: User Sign-In & Authentication", core_service_id, "vendor:auth0")
        ]

        for j_id, j_name, s_id, target_dep in journeys:
            engine.add_node(
                node_id=j_id,
                label=j_name,
                node_type=NodeType.BUSINESS_JOURNEY,
                provenance=NodeProvenance.INFERRED,
                status=NodeStatus.HEALTHY,
                criticality=Criticality.CRITICAL
            )
            # Service powers journey
            if s_id in engine.nx_graph:
                engine.add_edge(
                    source=s_id,
                    target=j_id,
                    relation=EdgeRelation.POWERS_JOURNEY,
                    provenance=EdgeProvenance.DECLARED,
                    confidence_score=1.0
                )
            # Critical vendor powers journey
            if target_dep in engine.nx_graph:
                engine.add_edge(
                    source=target_dep,
                    target=j_id,
                    relation=EdgeRelation.POWERS_JOURNEY,
                    provenance=EdgeProvenance.DECLARED,
                    confidence_score=1.0
                )

        return engine
