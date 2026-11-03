"""Tests for Evidence Provenance Graph."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from textforensics.provenance_graph import (
    ProvenanceEdge,
    ProvenanceGraph,
    ProvenanceGraphError,
    ProvenanceNode,
    create_evidence_node,
    load_graph,
    save_graph,
)


class TestProvenanceNode:
    def test_node_creation(self):
        """Node creation should work with all fields."""
        node = ProvenanceNode(
            node_id="test:abc123",
            node_type="detector_result",
            content_hash="a" * 64,
            timestamp="2024-01-01T00:00:00+00:00",
            metadata={"detector": "test"},
            operation="scan",
            actor="user1",
        )
        assert node.node_id == "test:abc123"
        assert node.node_type == "detector_result"

    def test_node_roundtrip(self):
        """Node serialization/deserialization should preserve data."""
        node = ProvenanceNode(
            node_id="test:abc123",
            node_type="detector_result",
            content_hash="a" * 64,
            timestamp="2024-01-01T00:00:00+00:00",
            metadata={"detector": "test"},
            operation="scan",
            actor="user1",
        )
        d = node.to_dict()
        node2 = ProvenanceNode.from_dict(d)
        assert node2.node_id == node.node_id
        assert node2.node_type == node.node_type
        assert node2.content_hash == node.content_hash
        assert node2.metadata == node.metadata


class TestProvenanceEdge:
    def test_edge_creation(self):
        """Edge creation should work."""
        edge = ProvenanceEdge(
            source_id="node1",
            target_id="node2",
            edge_type="derived_from",
            metadata={"reason": "calibration"},
        )
        assert edge.source_id == "node1"
        assert edge.target_id == "node2"
        assert edge.edge_type == "derived_from"

    def test_edge_roundtrip(self):
        """Edge serialization/deserialization should preserve data."""
        edge = ProvenanceEdge(
            source_id="node1",
            target_id="node2",
            edge_type="derived_from",
            metadata={"reason": "calibration"},
        )
        d = edge.to_dict()
        edge2 = ProvenanceEdge.from_dict(d)
        assert edge2.source_id == edge.source_id
        assert edge2.target_id == edge.target_id
        assert edge2.edge_type == edge.edge_type


class TestProvenanceGraph:
    def test_empty_graph(self):
        """Empty graph should be valid."""
        graph = ProvenanceGraph()
        assert len(graph) == 0
        assert graph.verify_integrity() is True

    def test_add_node(self):
        """Adding a node should work."""
        graph = ProvenanceGraph()
        node = graph.add_node("detector_result", {"score": 0.8}, "scan")

        assert len(graph) == 1
        assert node.node_id in graph
        assert graph.get_node(node.node_id) == node

    def test_add_node_deterministic_id(self):
        """Node ID should be deterministic for same content."""
        graph = ProvenanceGraph()
        node1 = graph.add_node("detector_result", {"score": 0.8}, "scan")
        node2 = graph.add_node("detector_result", {"score": 0.8}, "scan")

        assert node1.node_id == node2.node_id
        assert len(graph) == 1

    def test_add_node_collision_error(self):
        """Adding node with same ID but different content should fail."""
        graph = ProvenanceGraph()
        graph.add_node("detector_result", {"score": 0.8}, "scan", node_id="custom:id")

        with pytest.raises(ProvenanceGraphError):
            graph.add_node("detector_result", {"score": 0.9}, "scan", node_id="custom:id")

    def test_add_edge(self):
        """Adding an edge should work."""
        graph = ProvenanceGraph()
        node1 = graph.add_node("scan_input", {"text": "test"}, "scan")
        node2 = graph.add_node("detector_result", {"score": 0.8}, "scan")

        edge = graph.add_edge(node1.node_id, node2.node_id, "derived_from")

        assert edge.source_id == node1.node_id
        assert edge.target_id == node2.node_id
        assert edge.edge_type == "derived_from"

    def test_edge_cycle_detection(self):
        """Adding edge that creates cycle should fail."""
        graph = ProvenanceGraph()
        node1 = graph.add_node("a", {"v": 1}, "op1")
        node2 = graph.add_node("b", {"v": 2}, "op2")

        graph.add_edge(node1.node_id, node2.node_id, "derived_from")

        # This would create a cycle
        with pytest.raises(ProvenanceGraphError):
            graph.add_edge(node2.node_id, node1.node_id, "derived_from")

    def test_get_parents(self):
        """Getting parents should work."""
        graph = ProvenanceGraph()
        node1 = graph.add_node("a", {"v": 1}, "op1")
        node2 = graph.add_node("b", {"v": 2}, "op2")
        node3 = graph.add_node("c", {"v": 3}, "op3")

        graph.add_edge(node1.node_id, node2.node_id, "derived_from")
        graph.add_edge(node1.node_id, node3.node_id, "derived_from")

        parents = graph.get_parents(node2.node_id)
        assert len(parents) == 1
        assert parents[0].node_id == node1.node_id

    def test_get_children(self):
        """Getting children should work."""
        graph = ProvenanceGraph()
        node1 = graph.add_node("a", {"v": 1}, "op1")
        node2 = graph.add_node("b", {"v": 2}, "op2")
        node3 = graph.add_node("c", {"v": 3}, "op3")

        graph.add_edge(node1.node_id, node2.node_id, "derived_from")
        graph.add_edge(node1.node_id, node3.node_id, "derived_from")

        children = graph.get_children(node1.node_id)
        assert len(children) == 2

    def test_get_ancestors(self):
        """Getting transitive ancestors should work."""
        graph = ProvenanceGraph()
        node1 = graph.add_node("a", {"v": 1}, "op1")
        node2 = graph.add_node("b", {"v": 2}, "op2")
        node3 = graph.add_node("c", {"v": 3}, "op3")
        node4 = graph.add_node("d", {"v": 4}, "op4")

        graph.add_edge(node1.node_id, node2.node_id, "derived_from")
        graph.add_edge(node2.node_id, node3.node_id, "derived_from")
        graph.add_edge(node3.node_id, node4.node_id, "derived_from")

        ancestors = graph.get_ancestors(node4.node_id)
        assert len(ancestors) == 3

    def test_get_descendants(self):
        """Getting transitive descendants should work."""
        graph = ProvenanceGraph()
        node1 = graph.add_node("a", {"v": 1}, "op1")
        node2 = graph.add_node("b", {"v": 2}, "op2")
        node3 = graph.add_node("c", {"v": 3}, "op3")
        node4 = graph.add_node("d", {"v": 4}, "op4")

        graph.add_edge(node1.node_id, node2.node_id, "derived_from")
        graph.add_edge(node2.node_id, node3.node_id, "derived_from")
        graph.add_edge(node3.node_id, node4.node_id, "derived_from")

        descendants = graph.get_descendants(node1.node_id)
        assert len(descendants) == 3

    def test_get_lineage(self):
        """Getting complete lineage should work."""
        graph = ProvenanceGraph()
        node1 = graph.add_node("a", {"v": 1}, "op1")
        node2 = graph.add_node("b", {"v": 2}, "op2")
        node3 = graph.add_node("c", {"v": 3}, "op3")

        graph.add_edge(node1.node_id, node2.node_id, "derived_from")
        graph.add_edge(node2.node_id, node3.node_id, "derived_from")

        lineage = graph.get_lineage(node2.node_id)

        assert lineage["node"]["node_id"] == node2.node_id
        assert len(lineage["ancestors"]) == 1
        assert len(lineage["descendants"]) == 1  # node3 is a descendant
        assert lineage["descendants"][0]["node_id"] == node3.node_id

    def test_get_subgraph(self):
        """Extracting subgraph should work."""
        graph = ProvenanceGraph()
        node1 = graph.add_node("a", {"v": 1}, "op1")
        node2 = graph.add_node("b", {"v": 2}, "op2")
        node3 = graph.add_node("c", {"v": 3}, "op3")

        graph.add_edge(node1.node_id, node2.node_id, "derived_from")
        graph.add_edge(node2.node_id, node3.node_id, "derived_from")

        subgraph = graph.get_subgraph({node1.node_id, node2.node_id})

        assert len(subgraph) == 2
        assert node1.node_id in subgraph
        assert node2.node_id in subgraph
        assert node3.node_id not in subgraph

    def test_verify_integrity_valid(self):
        """Valid graph should pass integrity check."""
        graph = ProvenanceGraph()
        node1 = graph.add_node("a", {"v": 1}, "op1")
        node2 = graph.add_node("b", {"v": 2}, "op2")
        graph.add_edge(node1.node_id, node2.node_id, "derived_from")

        assert graph.verify_integrity() is True

    def test_verify_integrity_cycle(self):
        """Graph with cycle should fail integrity check."""
        graph = ProvenanceGraph()
        node1 = graph.add_node("a", {"v": 1}, "op1")
        node2 = graph.add_node("b", {"v": 2}, "op2")

        # Manually add cycle (bypass add_edge check)
        graph._edges.append(ProvenanceEdge(node1.node_id, node2.node_id, "derived_from"))
        graph._edges.append(ProvenanceEdge(node2.node_id, node1.node_id, "derived_from"))
        graph._adjacency[node1.node_id].add(node2.node_id)
        graph._adjacency[node2.node_id].add(node1.node_id)
        graph._reverse_adjacency[node2.node_id].add(node1.node_id)
        graph._reverse_adjacency[node1.node_id].add(node2.node_id)

        assert graph.verify_integrity() is False

    def test_serialization(self):
        """Graph serialization/deserialization should work."""
        graph = ProvenanceGraph()
        node1 = graph.add_node("a", {"v": 1}, "op1")
        node2 = graph.add_node("b", {"v": 2}, "op2")
        graph.add_edge(node1.node_id, node2.node_id, "derived_from")

        d = graph.to_dict()
        graph2 = ProvenanceGraph.from_dict(d)

        assert len(graph2) == 2
        assert graph2.get_node(node1.node_id) is not None
        assert graph2.get_node(node2.node_id) is not None
        assert len(graph2._edges) == 1

    def test_file_save_load(self):
        """Saving and loading from file should work."""
        graph = ProvenanceGraph()
        node1 = graph.add_node("a", {"v": 1}, "op1")
        node2 = graph.add_node("b", {"v": 2}, "op2")
        graph.add_edge(node1.node_id, node2.node_id, "derived_from")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "graph.json"
            save_graph(graph, path)
            loaded = load_graph(path)

            assert len(loaded) == 2
            assert loaded.get_node(node1.node_id) is not None


class TestCreateEvidenceNode:
    def test_create_with_parents(self):
        """Creating node with parents should auto-link."""
        graph = ProvenanceGraph()
        parent = graph.add_node("scan_input", {"text": "test"}, "scan")

        node = create_evidence_node(
            graph, "detector_result", {"score": 0.8}, "scan", parents=[parent.node_id]
        )

        assert node.node_id in graph
        assert parent.node_id in graph._reverse_adjacency[node.node_id]

    def test_create_without_parents(self):
        """Creating node without parents should work."""
        graph = ProvenanceGraph()

        node = create_evidence_node(graph, "scan_input", {"text": "test"}, "scan")

        assert node.node_id in graph
        assert len(graph._reverse_adjacency[node.node_id]) == 0


class TestProvenanceGraphError:
    def test_error_exception(self):
        """ProvenanceGraphError should be raised on errors."""
        graph = ProvenanceGraph()

        with pytest.raises(ProvenanceGraphError):
            graph.add_edge("nonexistent", "alsononexistent", "derived_from")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
