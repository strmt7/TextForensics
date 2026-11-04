"""Tests for Model Card Generator."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from textforensics.model_card import (
    Caveat,
    EthicalConsideration,
    EvaluationDataset,
    IntendedUse,
    ModelCard,
    ModelCardGenerator,
    ModelCardMetadata,
    ModelDetails,
    PerformanceMetric,
    RiskLevel,
    create_model_card,
)


class TestModelCard:
    def test_model_card_creation(self):
        """Test basic model card creation."""
        IntendedUse(
            primary_use_cases=["AI text detection in academic papers"],
            out_of_scope=["Creative writing", "Code generation"],
            target_users=["Researchers", "Publishers"],
        )

        card = ModelCard(
            metadata=ModelCardMetadata(
                version="1.0.0",
                generated_at="2024-01-01T00:00:00+00:00",
                generated_by="Test",
                schema_version="1.0.0",
                language="en",
            ),
            model_details=ModelDetails(
                name="Test Detector",
                version="1.0.0",
                detector_id="test/detector",
                detector_family="test",
                architecture="transformer",
                framework="pytorch",
                license="Apache-2.0",
                owner="Test",
                contact="test@test.com",
                references=[],
                tags=[],
            ),
            intended_use=IntendedUse(
                primary_use_cases=["AI text detection"],
                out_of_scope=["Creative writing"],
                target_users=["Researchers"],
            ),
        )

        assert card.model_details.name == "Test Detector"
        assert card.intended_use.primary_use_cases == ["AI text detection"]

    def test_model_card_serialization(self):
        """Test JSON and Markdown serialization."""
        IntendedUse(
            primary_use_cases=["AI text detection"],
            out_of_scope=["Creative writing"],
            target_users=["Researchers"],
        )

        card = ModelCard(
            metadata=ModelCardMetadata(
                version="1.0.0",
                generated_at="2024-01-01T00:00:00+00:00",
                generated_by="Test",
                schema_version="1.0.0",
                language="en",
            ),
            model_details=ModelDetails(
                name="Test Detector",
                version="1.0.0",
                detector_id="test/detector",
                detector_family="test",
                architecture="transformer",
                framework="pytorch",
                license="Apache-2.0",
                owner="Test",
                contact="test@test.com",
                references=[],
                tags=[],
            ),
            intended_use=IntendedUse(
                primary_use_cases=["AI text detection"],
                out_of_scope=["Creative writing"],
                target_users=["Researchers"],
            ),
        )

        json_str = card.to_json()
        assert "Test Detector" in json_str
        assert "test/detector" in json_str

        md = card.to_markdown()
        assert "# Model Card" in md
        assert "Test Detector" in md

    def test_model_card_json_save_load(self, tmp_path):
        """Test saving and loading JSON."""
        card = ModelCard(
            metadata=ModelCardMetadata(
                version="1.0.0",
                generated_at="2024-01-01T00:00:00+00:00",
                generated_by="Test",
                schema_version="1.0.0",
                language="en",
            ),
            model_details=ModelDetails(
                name="Test Detector",
                version="1.0.0",
                detector_id="test/detector",
                detector_family="test",
                architecture="transformer",
                framework="pytorch",
                license="Apache-2.0",
                owner="Test",
                contact="test@test.com",
                references=[],
                tags=[],
            ),
            intended_use=IntendedUse(
                primary_use_cases=["AI text detection"],
                out_of_scope=["Creative writing"],
                target_users=["Researchers"],
            ),
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "model_card.json"
            assert card.save_json(path)

            # Verify content
            loaded = json.loads(path.read_text())
            assert loaded["model_details"]["name"] == "Test Detector"
            assert loaded["model_details"]["version"] == "1.0.0"

    def test_markdown_export(self):
        """Test markdown export."""
        IntendedUse(
            primary_use_cases=["AI text detection"],
            out_of_scope=["Creative writing"],
            target_users=["Researchers"],
        )

        card = ModelCard(
            metadata=ModelCardMetadata(
                version="1.0.0",
                generated_at="2024-01-01T00:00:00+00:00",
                generated_by="Test",
                schema_version="1.0.0",
                language="en",
            ),
            model_details=ModelDetails(
                name="Test Detector",
                version="1.0.0",
                detector_id="test/detector",
                detector_family="test",
                architecture="transformer",
                framework="pytorch",
                license="Apache-2.0",
                owner="Test",
                contact="test@test.com",
                references=[],
                tags=[],
            ),
            intended_use=IntendedUse(
                primary_use_cases=["AI text detection"],
                out_of_scope=["Creative writing"],
                target_users=["Researchers"],
            ),
        )

        md = card.to_markdown()
        assert "# Model Card" in md
        assert "Test Detector" in md
        assert "## Model Details" in md
        assert "## Intended Use" in md


class TestModelCardGenerator:
    def test_generator_creation(self):
        generator = ModelCardGenerator()
        assert generator is not None

    def test_generate_basic_card(self):
        generator = ModelCardGenerator()

        IntendedUse(
            primary_use_cases=["AI text detection"],
            out_of_scope=["Creative writing"],
            target_users=["Researchers"],
        )

        card = generator.generate(
            detector_id="test/detector",
            detector_version="1.0.0",
            detector_family="transformer",
            architecture="transformer",
            framework="pytorch",
            license="Apache-2.0",
            owner="TestOrg",
            contact="test@test.com",
            intended_use=IntendedUse(
                primary_use_cases=["AI text detection"],
                out_of_scope=["Creative writing"],
                target_users=["Researchers"],
            ),
        )

        assert card.model_details.detector_id == "test/detector"
        assert card.model_details.version == "1.0.0"
        assert card.model_details.detector_family == "transformer"
        assert len(card.ethical_considerations) >= 5  # Default ethical considerations
        assert len(card.caveats_and_recommendations) >= 6  # Default caveats
        assert "risk_classification" in card.eu_ai_act_compliance

    def test_generate_with_custom_intended_use(self):
        generator = ModelCardGenerator()

        intended_use = IntendedUse(
            primary_use_cases=["Content moderation", "Academic integrity"],
            out_of_scope=["Creative writing"],
            target_users=["Platform moderators", "Educators"],
            deployment_environments=["Cloud", "On-premise"],
            constraints=["Real-time processing required"],
        )

        card = generator.generate(
            detector_id="moderation/detector",
            detector_version="2.0.0",
            detector_family="transformer",
            architecture="transformer",
            framework="tensorflow",
            license="MIT",
            owner="ModerationCorp",
            contact="moderation@corp.com",
            intended_use=intended_use,
        )

        assert card.intended_use.primary_use_cases == ["Content moderation", "Academic integrity"]
        assert card.intended_use.deployment_environments == ["Cloud", "On-premise"]
        assert card.intended_use.constraints == ["Real-time processing required"]

    def test_eu_ai_act_compliance_section(self):
        generator = ModelCardGenerator()

        card = generator.generate(
            detector_id="test/detector",
            detector_version="1.0.0",
            detector_family="transformer",
            architecture="transformer",
            framework="pytorch",
            license="Apache-2.0",
            owner="TestOrg",
            contact="test@test.com",
            intended_use=IntendedUse(
                primary_use_cases=["AI text detection"],
                out_of_scope=["Creative writing"],
                target_users=["Researchers"],
            ),
        )

        eu = card.eu_ai_act_compliance
        assert eu["risk_classification"] == "limited"
        assert "transparency_obligations" in eu
        assert eu["human_oversight"] == "required"
        assert "accuracy_robustness" in eu
        assert "data_governance" in eu
        assert "transparency_register" in eu
        assert "post_market_monitoring" in eu
        assert "incident_reporting" in eu

    def test_default_ethical_considerations(self):
        generator = ModelCardGenerator()

        card = generator.generate(
            detector_id="test/detector",
            detector_version="1.0.0",
            detector_family="transformer",
            architecture="transformer",
            framework="pytorch",
            license="Apache-2.0",
            owner="TestOrg",
            contact="test@test.com",
            intended_use=IntendedUse(
                primary_use_cases=["AI text detection"],
                out_of_scope=["Creative writing"],
                target_users=["Researchers"],
            ),
        )

        categories = {ec.category for ec in card.ethical_considerations}
        assert "bias" in categories
        assert "privacy" in categories
        assert "fairness" in categories
        assert "transparency" in categories
        assert "security" in categories

        # Check risk levels
        for ec in card.ethical_considerations:
            assert ec.risk_level in [RiskLevel.HIGH, RiskLevel.LIMITED]
            assert ec.mitigation
            assert ec.references

    def test_default_caveats(self):
        generator = ModelCardGenerator()

        card = generator.generate(
            detector_id="test/detector",
            detector_version="1.0.0",
            detector_family="transformer",
            architecture="transformer",
            framework="pytorch",
            license="Apache-2.0",
            owner="TestOrg",
            contact="test@test.com",
            intended_use=IntendedUse(
                primary_use_cases=["AI text detection"],
                out_of_scope=["Creative writing"],
                target_users=["Researchers"],
            ),
        )

        priorities = {c.priority for c in card.caveats_and_recommendations}
        categories = {c.category for c in card.caveats_and_recommendations}

        assert "critical" in priorities
        assert "high" in priorities
        assert "limitation" in categories
        assert "caveat" in categories
        assert "recommendation" in categories


class TestCreateModelCard:
    def test_create_model_card_convenience(self):
        card = create_model_card(
            detector_id="test/detector",
            detector_version="1.0.0",
            detector_family="transformer",
            architecture="transformer",
            framework="pytorch",
            intended_use=IntendedUse(
                primary_use_cases=["AI text detection"],
                out_of_scope=[],
                target_users=["Researchers"],
            ),
            license="Apache-2.0",
            owner="TestOrg",
            contact="test@test.com",
        )

        assert card.model_details.detector_id == "test/detector"
        assert card.model_details.version == "1.0.0"
        assert card.model_details.detector_family == "transformer"

    def test_model_card_markdown_save(self, tmp_path):
        card = ModelCard(
            metadata=ModelCardMetadata(
                version="1.0.0",
                generated_at="2024-01-01T00:00:00+00:00",
                generated_by="Test",
                schema_version="1.0.0",
                language="en",
            ),
            model_details=ModelDetails(
                name="Test Detector",
                version="1.0.0",
                detector_id="test/detector",
                detector_family="test",
                architecture="transformer",
                framework="pytorch",
                license="Apache-2.0",
                owner="Test",
                contact="test@test.com",
                references=[],
                tags=[],
            ),
            intended_use=IntendedUse(
                primary_use_cases=["AI text detection"],
                out_of_scope=["Creative writing"],
                target_users=["Researchers"],
            ),
        )

        path = Path(tmp_path) / "model_card.md"
        assert card.save_markdown(path)

        content = path.read_text()
        assert "# Model Card" in content
        assert "Test Detector" in content


class TestRiskLevel:
    def test_risk_level_values(self):
        assert RiskLevel.UNACCEPTABLE.value == "unacceptable"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.LIMITED.value == "limited"
        assert RiskLevel.MINIMAL.value == "minimal"


class TestIntendedUse:
    def test_creation(self):
        intended = IntendedUse(
            primary_use_cases=["AI detection"],
            out_of_scope=["Creative writing"],
            target_users=["Researchers"],
        )
        assert intended.primary_use_cases == ["AI detection"]
        assert intended.out_of_scope == ["Creative writing"]


class TestEthicalConsideration:
    def test_creation(self):
        ec = EthicalConsideration(
            category="bias",
            description="Test bias concern",
            risk_level=RiskLevel.HIGH,
            mitigation="Regular audits",
        )
        assert ec.category == "bias"
        assert ec.risk_level == RiskLevel.HIGH


class TestCaveat:
    def test_creation(self):
        caveat = Caveat(
            description="Test limitation",
            priority="high",
            category="limitation",
        )
        assert caveat.priority == "high"
        assert caveat.category == "limitation"


class TestPerformanceMetric:
    def test_creation(self):
        metric = PerformanceMetric(
            name="accuracy",
            value=0.95,
            unit="ratio",
            confidence_interval=(0.93, 0.97),
            benchmark_dataset="RAID",
            split="test",
        )
        assert metric.name == "accuracy"
        assert metric.value == 0.95
        assert metric.confidence_interval == (0.93, 0.97)


class TestEvaluationDataset:
    def test_creation(self):
        dataset = EvaluationDataset(
            name="RAID",
            version="1.0",
            size=10000,
            languages=["en"],
            domains=["academic", "news"],
            split_ratios={"train": 0.8, "test": 0.2},
            source="HuggingFace",
            license="Apache-2.0",
            collection_date="2024-01-01",
        )
        assert dataset.name == "RAID"
        assert dataset.size == 10000


class TestModelCardSaveLoad:
    def test_save_load_json(self, tmp_path):
        card = ModelCard(
            metadata=ModelCardMetadata(
                version="1.0.0",
                generated_at="2024-01-01T00:00:00+00:00",
                generated_by="Test",
                schema_version="1.0.0",
                language="en",
            ),
            model_details=ModelDetails(
                name="Test Detector",
                version="1.0.0",
                detector_id="test/detector",
                detector_family="test",
                architecture="transformer",
                framework="pytorch",
                license="Apache-2.0",
                owner="Test",
                contact="test@test.com",
                references=[],
                tags=[],
            ),
            intended_use=IntendedUse(
                primary_use_cases=["AI text detection"],
                out_of_scope=["Creative writing"],
                target_users=["Researchers"],
            ),
        )

        path = tmp_path / "model_card.json"
        assert card.save_json(path)

        loaded = json.loads(path.read_text())
        assert loaded["model_details"]["name"] == "Test Detector"
        assert loaded["model_details"]["version"] == "1.0.0"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
