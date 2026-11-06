"""Evidence Provenance Graph for TextForensics.

This module provides a directed acyclic graph (DAG) for tracking the lineage
and dependencies of forensic evidence across operations. Each piece of
evidence (detector result, calibration, threshold selection, etc.) is a node
in the graph, with edges representing derivation/dependency relationships.

This enables:
- Full traceability from final verdict back to raw inputs
- Impact analysis when upstream artifacts change
- Reproducibility verification
- Audit trail for compliance
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = [
    "ProvenanceNode",
    "ProvenanceEdge",
    "ProvenanceGraph",
    "ProvenanceGraphError",
    "create_evidence_node",
]


class ProvenanceGraphError(Exception):
    """Base exception for provenance graph errors."""

    pass


@dataclass(frozen=True, slots=True)
class ProvenanceNode:
    """A node in the provenance graph representing a piece of evidence.

    Attributes:
        node_id: Unique identifier for this node.
        node_type: Type of evidence (e.g., "detector_result", "calibration",
                   "threshold", "scan_input", "report", "verification").
        content_hash: SHA-256 hash of the node's content.
        timestamp: ISO 8601 UTC timestamp of creation.
        metadata: Additional type-specific metadata.
        operation: The operation that produced this node (e.g., "scan", "calibrate").
        actor: Optional actor identity.
    """

    node_id: str
    node_type: str
    content_hash: str
    timestamp: str
    metadata: dict[str, Any]
    operation: str
    actor: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "content_hash": self.content_hash,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
            "operation": self.operation,
            "actor": self.actor,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProvenanceNode:
        return cls(
            node_id=str(data["node_id"]),
            node_type=str(data["node_type"]),
            content_hash=str(data["content_hash"]),
            timestamp=str(data["timestamp"]),
            metadata=dict(data.get("metadata", {})),
            operation=str(data["operation"]),
            actor=data.get("actor"),
        )


@dataclass(frozen=True, slots=True)
class ProvenanceEdge:
    """A directed edge in the provenance graph representing a dependency.

    Attributes:
        source_id: ID of the source node (upstream dependency).
        target_id: ID of the target node (downstream derived).
        edge_type: Type of dependency (e.g., "derived_from", "calibrates",
                   "validates", "inputs_to").
        metadata: Additional edge-specific metadata.
    """

    source_id: str
    target_id: str
    edge_type: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProvenanceEdge:
        return cls(
            source_id=str(data["source_id"]),
            target_id=str(data["target_id"]),
            edge_type=str(data["edge_type"]),
            metadata=dict(data.get("metadata", {})),
        )


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _compute_content_hash(content: Any) -> str:
    """Compute SHA-256 hash of content."""
    if isinstance(content, (dict, list)):
        canonical = json.dumps(content, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    else:
        canonical = str(content)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _generate_node_id(node_type: str, content_hash: str) -> str:
    """Generate a deterministic node ID from type and content hash."""
    return f"{node_type}:{content_hash[:16]}"


class ProvenanceGraph:
    """Directed acyclic graph for evidence provenance tracking.

    The graph maintains nodes representing pieces of evidence and directed
    edges representing derivation/dependency relationships. It enforces
    acyclicity and provides traversal methods for traceability analysis.
    """

    def __init__(self):
        self._nodes: dict[str, ProvenanceNode] = {}
        self._edges: list[ProvenanceEdge] = []
        self._adjacency: dict[str, set[str]] = defaultdict(set)  # source -> targets
        self._reverse_adjacency: dict[str, set[str]] = defaultdict(set)  # target -> sources

    def add_node(
        self,
        node_type: str,
        content: Any,
        operation: str,
        *,
        metadata: dict[str, Any] | None = None,
        actor: str | None = None,
        node_id: str | None = None,
    ) -> ProvenanceNode:
        """Add a node to the graph.

        Args:
            node_type: Type of evidence.
            content: The content to hash.
            operation: Operation that produced this node.
            metadata: Additional metadata.
            actor: Optional actor identity.
            node_id: Optional explicit node ID (generated if not provided).

        Returns:
            The created ProvenanceNode.
        """
        content_hash = _compute_content_hash(content)
        if node_id is None:
            node_id = _generate_node_id(node_type, content_hash)

        if node_id in self._nodes:
            # Check if content matches existing node
            existing = self._nodes[node_id]
            if existing.content_hash != content_hash:
                raise ProvenanceGraphError(
                    f"Node ID collision: {node_id} exists with different content"
                )
            return existing

        timestamp = _now_iso()
        node = ProvenanceNode(
            node_id=node_id,
            node_type=node_type,
            content_hash=content_hash,
            timestamp=timestamp,
            metadata=metadata or {},
            operation=operation,
            actor=actor,
        )

        self._nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceEdge:
        """Add a directed edge between nodes.

        Args:
            source_id: Source node ID (upstream).
            target_id: Target node ID (downstream).
            edge_type: Type of dependency.
            metadata: Additional edge metadata.

        Returns:
            The created ProvenanceEdge.
        """
        if source_id not in self._nodes:
            raise ProvenanceGraphError(f"Source node not found: {source_id}")
        if target_id not in self._nodes:
            raise ProvenanceGraphError(f"Target node not found: {target_id}")

        # Check for cycles
        if self._would_create_cycle(source_id, target_id):
            raise ProvenanceGraphError(
                f"Adding edge {source_id} -> {target_id} would create a cycle"
            )

        edge = ProvenanceEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            metadata=metadata or {},
        )

        self._edges.append(edge)
        self._adjacency[source_id].add(target_id)
        self._reverse_adjacency[target_id].add(source_id)

        return edge

    def _would_create_cycle(self, source_id: str, target_id: str) -> bool:
        """Check if adding an edge would create a cycle using DFS."""
        # If target can reach source, adding source->target creates a cycle
        visited = set()
        stack = [target_id]
        while stack:
            current = stack.pop()
            if current == source_id:
                return True
            if current in visited:
                continue
            visited.add(current)
            stack.extend(self._adjacency.get(current, set()))
        return False

    def get_node(self, node_id: str) -> ProvenanceNode | None:
        """Get a node by ID."""
        return self._nodes.get(node_id)

    def get_parents(self, node_id: str) -> list[ProvenanceNode]:
        """Get all parent (upstream) nodes of a node."""
        parent_ids = self._reverse_adjacency.get(node_id, set())
        return [self._nodes[pid] for pid in parent_ids if pid in self._nodes]

    def get_children(self, node_id: str) -> list[ProvenanceNode]:
        """Get all child (downstream) nodes of a node."""
        child_ids = self._adjacency.get(node_id, set())
        return [self._nodes[cid] for cid in child_ids if cid in self._nodes]

    def get_ancestors(self, node_id: str) -> list[ProvenanceNode]:
        """Get all ancestors (transitive upstream) of a node."""
        ancestors = []
        visited = set()
        queue = deque(self._reverse_adjacency.get(node_id, set()))

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            if current in self._nodes:
                ancestors.append(self._nodes[current])
                queue.extend(self._reverse_adjacency.get(current, set()))

        return ancestors

    def get_descendants(self, node_id: str) -> list[ProvenanceNode]:
        """Get all descendants (transitive downstream) of a node."""
        descendants = []
        visited = set()
        queue = deque(self._adjacency.get(node_id, set()))

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            if current in self._nodes:
                descendants.append(self._nodes[current])
                queue.extend(self._adjacency.get(current, set()))

        return descendants

    def get_lineage(self, node_id: str) -> dict[str, Any]:
        """Get complete lineage (ancestors and descendants) of a node."""
        if node_id not in self._nodes:
            raise ProvenanceGraphError(f"Node not found: {node_id}")

        node = self._nodes[node_id]
        ancestors = self.get_ancestors(node_id)
        descendants = self.get_descendants(node_id)

        return {
            "node": node.to_dict(),
            "ancestors": [a.to_dict() for a in ancestors],
            "descendants": [d.to_dict() for d in descendants],
            "ancestor_count": len(ancestors),
            "descendant_count": len(descendants),
        }

    def get_subgraph(self, node_ids: set[str]) -> ProvenanceGraph:
        """Extract a subgraph containing only specified nodes and their connecting edges."""
        subgraph = ProvenanceGraph()
        for node_id in node_ids:
            if node_id in self._nodes:
                node = self._nodes[node_id]
                subgraph._nodes[node_id] = node

        for edge in self._edges:
            if edge.source_id in node_ids and edge.target_id in node_ids:
                subgraph._edges.append(edge)
                subgraph._adjacency[edge.source_id].add(edge.target_id)
                subgraph._reverse_adjacency[edge.target_id].add(edge.source_id)

        return subgraph

    def verify_integrity(self) -> bool:
        """Verify graph integrity (no cycles, all edges reference valid nodes)."""
        # Check all edges reference valid nodes
        for edge in self._edges:
            if edge.source_id not in self._nodes or edge.target_id not in self._nodes:
                return False

        # Check for cycles using Kahn's algorithm
        in_degree = defaultdict(int)
        for edge in self._edges:
            in_degree[edge.target_id] += 1

        queue = deque([nid for nid in self._nodes if in_degree[nid] == 0])
        processed = 0

        while queue:
            current = queue.popleft()
            processed += 1
            for target in self._adjacency.get(current, set()):
                in_degree[target] -= 1
                if in_degree[target] == 0:
                    queue.append(target)

        return processed == len(self._nodes)

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph to dictionary."""
        return {
            "nodes": {nid: node.to_dict() for nid, node in self._nodes.items()},
            "edges": [edge.to_dict() for edge in self._edges],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProvenanceGraph:
        """Deserialize graph from dictionary."""
        graph = cls()
        for nid, node_data in data.get("nodes", {}).items():
            graph._nodes[nid] = ProvenanceNode.from_dict(node_data)
        for edge_data in data.get("edges", []):
            edge = ProvenanceEdge.from_dict(edge_data)
            graph._edges.append(edge)
            graph._adjacency[edge.source_id].add(edge.target_id)
            graph._reverse_adjacency[edge.target_id].add(edge.source_id)
        return graph

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, node_id: str) -> bool:
        return node_id in self._nodes


def create_evidence_node(
    graph: ProvenanceGraph,
    evidence_type: str,
    content: Any,
    operation: str,
    *,
    parents: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    actor: str | None = None,
) -> ProvenanceNode:
    """Convenience function to create a node and link it to parent nodes.

    Args:
        graph: ProvenanceGraph to add node to.
        evidence_type: Type of evidence.
        content: Content to hash.
        operation: Operation that produced this evidence.
        parents: Optional list of parent node IDs.
        metadata: Additional metadata.
        actor: Optional actor identity.

    Returns:
        The created ProvenanceNode.
    """
    node = graph.add_node(evidence_type, content, operation, metadata=metadata, actor=actor)

    if parents:
        for parent_id in parents:
            graph.add_edge(parent_id, node.node_id, "derived_from")

    return node


def save_graph(graph: ProvenanceGraph, path: str | Path) -> None:
    """Save graph to JSON file."""
    Path(path).write_text(
        json.dumps(graph.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def load_graph(path: str | Path) -> ProvenanceGraph:
    """Load graph from JSON file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ProvenanceGraph.from_dict(data)
