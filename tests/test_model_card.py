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
    QuantitativeAnalysis,
    RiskLevel,
    TrainingData,
    create_model_card,
    load_model_card,
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
        assert "risk_classification" in card.eu_ai_act_transparency_notes

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

    def test_eu_ai_act_transparency_notes_section(self):
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

        eu = card.eu_ai_act_transparency_notes
        # Transparency notes, not compliance claims: nothing here asserts
        # a risk class, a conformity assessment, or a CE marking.
        assert eu["risk_classification"] == "not_assessed"
        assert eu["conformity_assessment"] == "not_assessed"
        assert eu["ce_marking"] == "not_claimed"
        assert "not certify regulatory compliance" in eu["note"]
        assert "transparency_obligations" in eu
        # Metrics are not populated by the generator, so the notes must
        # not claim they are published.
        assert "Performance metrics published" not in eu["transparency_obligations"]
        # No training/evaluation data was supplied, so nothing is
        # documented as such.
        assert eu["data_governance"]["training_data_documented"] is False
        assert eu["data_governance"]["evaluation_data_documented"] is False
        assert eu["human_oversight"] == "required"
        assert "accuracy_robustness" in eu
        assert "data_governance" in eu
        assert "transparency_register" in eu
        assert "post_market_monitoring" in eu
        assert "incident_reporting" in eu

    def test_transparency_notes_reflect_supplied_data(self):
        generator = ModelCardGenerator()
        evaluation = EvaluationDataset(
            name="eval",
            version="1.0",
            size=100,
            languages=["en"],
            domains=["academic"],
            split_ratios={"test": 1.0},
            source="test",
            license="CC0-1.0",
            collection_date="2024-01-01",
        )

        card = generator.generate(
            detector_id="test/detector",
            detector_version="1.0.0",
            detector_family="transformer",
            architecture="transformer",
            framework="pytorch",
            intended_use=IntendedUse(
                primary_use_cases=["AI text detection"],
                out_of_scope=["Creative writing"],
                target_users=["Researchers"],
            ),
            evaluation_data=evaluation,
            training_data=TrainingData(
                datasets=[evaluation],
                total_size=100,
                preprocessing_pipeline=[],
            ),
        )

        notes = card.eu_ai_act_transparency_notes
        assert notes["data_governance"]["training_data_documented"] is True
        assert notes["data_governance"]["evaluation_data_documented"] is True

    def test_default_license_is_project_license(self):
        # The project is AGPL-3.0-or-later (pyproject.toml); the card
        # default must say so instead of the old Apache-2.0 placeholder.
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
        )

        assert card.model_details.license == "AGPL-3.0-or-later"

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


class TestModelCardLoad:
    """Save -> load round-trip and loader failure modes (defect #5)."""

    def _full_card(self) -> ModelCard:
        evaluation = EvaluationDataset(
            name="RAID",
            version="1.0",
            size=10000,
            languages=["en"],
            domains=["academic", "news"],
            split_ratios={"train": 0.8, "test": 0.2},
            source="HuggingFace",
            license="Apache-2.0",
            collection_date="2024-01-01",
            preprocessing=["lowercase"],
            known_biases=["domain skew"],
        )
        metric = PerformanceMetric(
            name="accuracy",
            value=0.95,
            unit="ratio",
            confidence_interval=(0.93, 0.97),
            benchmark_dataset="RAID",
            split="test",
            metadata={"seed": 42},
        )
        return ModelCard(
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
                references=["https://example.invalid/ref"],
                tags=["test"],
            ),
            intended_use=IntendedUse(
                primary_use_cases=["AI text detection"],
                out_of_scope=["Creative writing"],
                target_users=["Researchers"],
                deployment_environments=["On-premise"],
                constraints=["Real-time processing required"],
            ),
            factors=["Input text length", "Language"],
            metrics=[metric],
            evaluation_data=evaluation,
            training_data=TrainingData(
                datasets=[evaluation],
                total_size=10000,
                preprocessing_pipeline=["tokenize"],
                augmentation_techniques=["paraphrase"],
                known_biases=["domain skew"],
            ),
            quantitative_analysis=QuantitativeAnalysis(
                metrics=[metric],
                confusion_matrix={"tp": 90, "fp": 5, "tn": 95, "fn": 10},
                roc_auc=0.97,
                pr_auc=0.96,
                calibration_error=0.02,
                subgroup_analysis={"news": [metric]},
                error_analysis={"short_text": "degraded"},
            ),
            ethical_considerations=[
                EthicalConsideration(
                    category="bias",
                    description="Test bias concern",
                    risk_level=RiskLevel.HIGH,
                    mitigation="Regular audits",
                    references=["https://example.invalid/bias"],
                )
            ],
            caveats_and_recommendations=[
                Caveat(
                    description="Test limitation",
                    priority="high",
                    category="limitation",
                    applies_to=["short_text"],
                )
            ],
            additional_information={"reviewed_by": "Test"},
            eu_ai_act_transparency_notes={"risk_classification": "not_assessed"},
        )

    def test_from_dict_round_trip_preserves_all_sections(self):
        card = self._full_card()
        restored = ModelCard.from_dict(card.to_dict())
        assert restored.to_dict() == card.to_dict()
        assert restored.model_details.name == "Test Detector"
        assert restored.metrics[0].confidence_interval == (0.93, 0.97)
        assert restored.quantitative_analysis is not None
        assert restored.quantitative_analysis.roc_auc == 0.97
        assert restored.quantitative_analysis.subgroup_analysis["news"][0].name == "accuracy"
        assert restored.training_data is not None
        assert restored.training_data.datasets[0].name == "RAID"
        assert restored.ethical_considerations[0].risk_level is RiskLevel.HIGH

    def test_save_json_then_load_round_trip(self, tmp_path):
        card = self._full_card()
        path = tmp_path / "model_card.json"
        assert card.save_json(path)

        loaded = ModelCard.load(path)
        assert loaded.to_dict() == card.to_dict()

        loaded_via_function = load_model_card(path)
        assert loaded_via_function.to_dict() == card.to_dict()

    def test_load_missing_file_raises_file_not_found(self, tmp_path):
        missing = tmp_path / "does-not-exist.json"
        with pytest.raises(FileNotFoundError):
            ModelCard.load(missing)
        with pytest.raises(FileNotFoundError):
            load_model_card(missing)

    def test_load_invalid_json_raises_value_error(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{ not json", encoding="utf-8")
        with pytest.raises(ValueError, match="invalid JSON"):
            ModelCard.load(path)
        with pytest.raises(ValueError, match="invalid JSON"):
            load_model_card(path)

    def test_from_dict_rejects_non_mapping(self):
        with pytest.raises(ValueError, match="must be a mapping"):
            ModelCard.from_dict(["not", "a", "mapping"])  # type: ignore[arg-type]

    def test_from_dict_rejects_missing_required_section(self):
        data = self._full_card().to_dict()
        del data["model_details"]
        with pytest.raises(ValueError, match="missing required field"):
            ModelCard.from_dict(data)

    def test_from_dict_rejects_wrong_field_type(self):
        data = self._full_card().to_dict()
        data["metrics"] = "not-a-list"
        with pytest.raises(ValueError, match="must be a list"):
            ModelCard.from_dict(data)

    def test_from_dict_rejects_unknown_risk_level(self):
        data = self._full_card().to_dict()
        data["ethical_considerations"][0]["risk_level"] = "catastrophic"
        with pytest.raises(ValueError, match="unknown value"):
            ModelCard.from_dict(data)

    def test_from_dict_rejects_unknown_schema_version(self):
        data = self._full_card().to_dict()
        data["schema_version"] = "9.9.9"
        with pytest.raises(ValueError, match="unsupported model card schema_version"):
            ModelCard.from_dict(data)

    def test_from_dict_rejects_unknown_top_level_key(self):
        data = self._full_card().to_dict()
        data["surprise"] = 1
        with pytest.raises(ValueError, match="unknown field"):
            ModelCard.from_dict(data)

    def test_load_schema_invalid_json_raises_value_error(self, tmp_path):
        path = tmp_path / "schema-bad.json"
        path.write_text(json.dumps({"schema_version": "1.0.0"}), encoding="utf-8")
        with pytest.raises(ValueError, match="missing required field"):
            ModelCard.load(path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
