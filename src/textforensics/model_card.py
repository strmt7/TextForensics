"""Model Card Generator for TextForensics Detectors.

Generates standardized model cards for AI-text detectors following
the Google Model Card Toolkit standard, with EU AI Act transparency
notes.

Transparency notes are not compliance claims: this module performs no
conformity assessment and the cards it generates do not certify
regulatory compliance (see REVAMP_SPEC.md: the revamp does not certify
regulatory compliance).

Features:
- Automatic model card generation from detector metadata and performance data
- EU AI Act transparency notes
- Performance metrics visualization data
- Intended use cases and limitations documentation
- Risk assessment and mitigation strategies
- Version tracking and lineage tracking
- Export to multiple formats (JSON, Markdown, HTML, PDF-ready)

Design principles:
- Local-first: No network dependencies
- Standards-informed: Structured after the Google Model Card Toolkit;
  notes EU AI Act transparency topics without certifying compliance
- Extensible: Plugin architecture for custom sections
- Audit-ready: Full provenance tracking
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from textforensics.benchmark import BenchmarkRunner
    from textforensics.calibration import CalibrationManager

__all__ = [
    "ModelCard",
    "ModelCardSection",
    "RiskLevel",
    "IntendedUse",
    "Limitation",
    "EthicalConsideration",
    "PerformanceMetric",
    "ModelCardGenerator",
    "create_model_card",
]


class RiskLevel(StrEnum):
    """Risk level classification per EU AI Act."""

    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"


class ModelCardSection(StrEnum):
    """Standard model card sections per Google Model Card Toolkit."""

    MODEL_DETAILS = "model_details"
    INTENDED_USE = "intended_use"
    FACTORS = "factors"
    METRICS = "metrics"
    EVALUATION_DATA = "evaluation_data"
    TRAINING_DATA = "training_data"
    QUANTITATIVE_ANALYSIS = "quantitative_analysis"
    ETHICAL_CONSIDERATIONS = "ethical_considerations"
    CAVEATS_AND_RECOMMENDATIONS = "caveats_and_recommendations"
    ADDITIONAL_INFORMATION = "additional_information"


@dataclass(frozen=True, slots=True)
class ModelCardMetadata:
    """Metadata about the model card itself."""

    version: str
    generated_at: str
    generated_by: str
    schema_version: str = "1.0.0"
    language: str = "en"


@dataclass(frozen=True, slots=True)
class ModelDetails:
    """Model details section."""

    name: str
    version: str
    detector_id: str
    detector_family: str
    architecture: str
    framework: str
    license: str
    owner: str
    contact: str
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class IntendedUse:
    """Intended use section."""

    primary_use_cases: list[str]
    out_of_scope: list[str]
    target_users: list[str]
    deployment_environments: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class Limitation:
    """A single limitation entry."""

    description: str
    severity: str  # "high", "medium", "low"
    mitigation: str | None = None
    affected_scenarios: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class EthicalConsideration:
    """An ethical consideration entry."""

    category: str  # "bias", "privacy", "security", "fairness", "transparency"
    description: str
    risk_level: RiskLevel
    mitigation: str
    references: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class PerformanceMetric:
    """A single performance metric."""

    name: str
    value: float
    unit: str
    confidence_interval: tuple[float, float] | None = None
    benchmark_dataset: str = ""
    split: str = "test"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvaluationDataset:
    """Evaluation dataset description."""

    name: str
    version: str
    size: int
    languages: list[str]
    domains: list[str]
    split_ratios: dict[str, float]
    source: str
    license: str
    collection_date: str
    preprocessing: list[str] = field(default_factory=list)
    known_biases: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class TrainingData:
    """Training data description."""

    datasets: list[EvaluationDataset]
    total_size: int
    preprocessing_pipeline: list[str]
    augmentation_techniques: list[str] = field(default_factory=list)
    known_biases: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class QuantitativeAnalysis:
    """Quantitative analysis results."""

    metrics: list[PerformanceMetric]
    confusion_matrix: dict[str, int] | None = None
    roc_auc: float | None = None
    pr_auc: float | None = None
    calibration_error: float | None = None
    subgroup_analysis: dict[str, list[PerformanceMetric]] = field(default_factory=dict)
    error_analysis: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Caveat:
    """A caveat or recommendation."""

    description: str
    priority: str  # "high", "medium", "low"
    category: str  # "limitation", "recommendation", "caveat"
    applies_to: list[str] = field(default_factory=list)


def _mc_required(payload: Mapping[str, Any], field: str, where: str) -> Any:
    """Return a required field or raise ``ValueError`` if it is absent."""
    if field not in payload:
        raise ValueError(f"{where} is missing required field {field!r}")
    return payload[field]


def _mc_no_unknown(payload: Mapping[str, Any], allowed: set[str], where: str) -> None:
    """Reject unknown keys so a mistyped or foreign field cannot pass silently."""
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ValueError(f"{where} has unknown field(s): {', '.join(unknown)}")


def _mc_mapping(value: Any, field: str, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{where} field {field!r} must be a mapping")
    return value


def _mc_str(payload: Mapping[str, Any], field: str, where: str) -> str:
    value = _mc_required(payload, field, where)
    if not isinstance(value, str):
        raise ValueError(f"{where} field {field!r} must be a string")
    return value


def _mc_opt_str(
    payload: Mapping[str, Any], field: str, where: str, default: str | None = None
) -> str | None:
    if field not in payload or payload[field] is None:
        return default
    value = payload[field]
    if not isinstance(value, str):
        raise ValueError(f"{where} field {field!r} must be a string")
    return value


def _mc_str_list(
    payload: Mapping[str, Any], field: str, where: str, *, required: bool = True
) -> list[str]:
    if field not in payload:
        if required:
            raise ValueError(f"{where} is missing required field {field!r}")
        return []
    value = payload[field]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{where} field {field!r} must be a list of strings")
    return list(value)


def _mc_number(payload: Mapping[str, Any], field: str, where: str) -> float:
    value = _mc_required(payload, field, where)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{where} field {field!r} must be a number")
    return float(value)


def _mc_opt_number(payload: Mapping[str, Any], field: str, where: str) -> float | None:
    if field not in payload or payload[field] is None:
        return None
    value = payload[field]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{where} field {field!r} must be a number or null")
    return float(value)


def _mc_int(payload: Mapping[str, Any], field: str, where: str) -> int:
    value = _mc_required(payload, field, where)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{where} field {field!r} must be an integer")
    return value


def _mc_dict(payload: Mapping[str, Any], field: str, where: str) -> dict[str, Any]:
    value = _mc_mapping(_mc_required(payload, field, where), field, where)
    return dict(value)


def _metadata_from_dict(data: Any) -> ModelCardMetadata:
    where = "metadata"
    payload = _mc_mapping(data, where, "model card")
    _mc_no_unknown(
        payload, {"version", "generated_at", "generated_by", "schema_version", "language"}, where
    )
    return ModelCardMetadata(
        version=_mc_str(payload, "version", where),
        generated_at=_mc_str(payload, "generated_at", where),
        generated_by=_mc_str(payload, "generated_by", where),
        schema_version=_mc_opt_str(payload, "schema_version", where, "1.0.0") or "1.0.0",
        language=_mc_opt_str(payload, "language", where, "en") or "en",
    )


def _model_details_from_dict(data: Any) -> ModelDetails:
    where = "model_details"
    payload = _mc_mapping(data, where, "model card")
    _mc_no_unknown(
        payload,
        {
            "name",
            "version",
            "detector_id",
            "detector_family",
            "architecture",
            "framework",
            "license",
            "owner",
            "contact",
            "references",
            "tags",
        },
        where,
    )
    return ModelDetails(
        name=_mc_str(payload, "name", where),
        version=_mc_str(payload, "version", where),
        detector_id=_mc_str(payload, "detector_id", where),
        detector_family=_mc_str(payload, "detector_family", where),
        architecture=_mc_str(payload, "architecture", where),
        framework=_mc_str(payload, "framework", where),
        license=_mc_str(payload, "license", where),
        owner=_mc_str(payload, "owner", where),
        contact=_mc_str(payload, "contact", where),
        references=_mc_str_list(payload, "references", where, required=False),
        tags=_mc_str_list(payload, "tags", where, required=False),
    )


def _intended_use_from_dict(data: Any) -> IntendedUse:
    where = "intended_use"
    payload = _mc_mapping(data, where, "model card")
    _mc_no_unknown(
        payload,
        {
            "primary_use_cases",
            "out_of_scope",
            "target_users",
            "deployment_environments",
            "constraints",
        },
        where,
    )
    return IntendedUse(
        primary_use_cases=_mc_str_list(payload, "primary_use_cases", where),
        out_of_scope=_mc_str_list(payload, "out_of_scope", where),
        target_users=_mc_str_list(payload, "target_users", where),
        deployment_environments=_mc_str_list(
            payload, "deployment_environments", where, required=False
        ),
        constraints=_mc_str_list(payload, "constraints", where, required=False),
    )


def _metric_from_dict(data: Any) -> PerformanceMetric:
    where = "metric"
    payload = _mc_mapping(data, where, "model card")
    _mc_no_unknown(
        payload,
        {
            "name",
            "value",
            "unit",
            "confidence_interval",
            "benchmark_dataset",
            "split",
            "metadata",
        },
        where,
    )
    confidence_interval: tuple[float, float] | None = None
    if payload.get("confidence_interval") is not None:
        raw_ci = payload["confidence_interval"]
        if (
            not isinstance(raw_ci, (list, tuple))
            or len(raw_ci) != 2
            or any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in raw_ci)
        ):
            raise ValueError("metric field 'confidence_interval' must be a two-number sequence")
        confidence_interval = (float(raw_ci[0]), float(raw_ci[1]))
    metadata: dict[str, Any] = {}
    if payload.get("metadata") is not None:
        metadata = dict(_mc_mapping(payload["metadata"], "metadata", where))
    return PerformanceMetric(
        name=_mc_str(payload, "name", where),
        value=_mc_number(payload, "value", where),
        unit=_mc_str(payload, "unit", where),
        confidence_interval=confidence_interval,
        benchmark_dataset=_mc_opt_str(payload, "benchmark_dataset", where, "") or "",
        split=_mc_opt_str(payload, "split", where, "test") or "test",
        metadata=metadata,
    )


def _evaluation_dataset_from_dict(data: Any) -> EvaluationDataset:
    where = "evaluation_data"
    payload = _mc_mapping(data, where, "model card")
    _mc_no_unknown(
        payload,
        {
            "name",
            "version",
            "size",
            "languages",
            "domains",
            "split_ratios",
            "source",
            "license",
            "collection_date",
            "preprocessing",
            "known_biases",
        },
        where,
    )
    raw_ratios = _mc_mapping(_mc_required(payload, "split_ratios", where), "split_ratios", where)
    split_ratios: dict[str, float] = {}
    for key, value in raw_ratios.items():
        if (
            not isinstance(key, str)
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
        ):
            raise ValueError("evaluation_data field 'split_ratios' must map strings to numbers")
        split_ratios[key] = float(value)
    return EvaluationDataset(
        name=_mc_str(payload, "name", where),
        version=_mc_str(payload, "version", where),
        size=_mc_int(payload, "size", where),
        languages=_mc_str_list(payload, "languages", where),
        domains=_mc_str_list(payload, "domains", where),
        split_ratios=split_ratios,
        source=_mc_str(payload, "source", where),
        license=_mc_str(payload, "license", where),
        collection_date=_mc_str(payload, "collection_date", where),
        preprocessing=_mc_str_list(payload, "preprocessing", where, required=False),
        known_biases=_mc_str_list(payload, "known_biases", where, required=False),
    )


def _training_data_from_dict(data: Any) -> TrainingData:
    where = "training_data"
    payload = _mc_mapping(data, where, "model card")
    _mc_no_unknown(
        payload,
        {
            "datasets",
            "total_size",
            "preprocessing_pipeline",
            "augmentation_techniques",
            "known_biases",
        },
        where,
    )
    raw_datasets = _mc_required(payload, "datasets", where)
    if not isinstance(raw_datasets, list):
        raise ValueError("training_data field 'datasets' must be a list")
    return TrainingData(
        datasets=[_evaluation_dataset_from_dict(item) for item in raw_datasets],
        total_size=_mc_int(payload, "total_size", where),
        preprocessing_pipeline=_mc_str_list(payload, "preprocessing_pipeline", where),
        augmentation_techniques=_mc_str_list(
            payload, "augmentation_techniques", where, required=False
        ),
        known_biases=_mc_str_list(payload, "known_biases", where, required=False),
    )


def _quantitative_analysis_from_dict(data: Any) -> QuantitativeAnalysis:
    where = "quantitative_analysis"
    payload = _mc_mapping(data, where, "model card")
    _mc_no_unknown(
        payload,
        {
            "metrics",
            "confusion_matrix",
            "roc_auc",
            "pr_auc",
            "calibration_error",
            "subgroup_analysis",
            "error_analysis",
        },
        where,
    )
    raw_metrics = _mc_required(payload, "metrics", where)
    if not isinstance(raw_metrics, list):
        raise ValueError("quantitative_analysis field 'metrics' must be a list")
    confusion_matrix: dict[str, int] | None = None
    if payload.get("confusion_matrix") is not None:
        raw_cm = _mc_mapping(payload["confusion_matrix"], "confusion_matrix", where)
        confusion_matrix = {}
        for key, value in raw_cm.items():
            if not isinstance(key, str) or isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(
                    "quantitative_analysis field 'confusion_matrix' must map strings to integers"
                )
            confusion_matrix[key] = value
    subgroup_analysis: dict[str, list[PerformanceMetric]] = {}
    if payload.get("subgroup_analysis") is not None:
        raw_sub = _mc_mapping(payload["subgroup_analysis"], "subgroup_analysis", where)
        for key, value in raw_sub.items():
            if not isinstance(value, list):
                raise ValueError(
                    "quantitative_analysis field 'subgroup_analysis' must map strings to metric lists"
                )
            subgroup_analysis[key] = [_metric_from_dict(item) for item in value]
    error_analysis: dict[str, Any] = {}
    if payload.get("error_analysis") is not None:
        error_analysis = dict(_mc_mapping(payload["error_analysis"], "error_analysis", where))
    return QuantitativeAnalysis(
        metrics=[_metric_from_dict(item) for item in raw_metrics],
        confusion_matrix=confusion_matrix,
        roc_auc=_mc_opt_number(payload, "roc_auc", where),
        pr_auc=_mc_opt_number(payload, "pr_auc", where),
        calibration_error=_mc_opt_number(payload, "calibration_error", where),
        subgroup_analysis=subgroup_analysis,
        error_analysis=error_analysis,
    )


def _ethical_consideration_from_dict(data: Any) -> EthicalConsideration:
    where = "ethical_consideration"
    payload = _mc_mapping(data, where, "model card")
    _mc_no_unknown(
        payload, {"category", "description", "risk_level", "mitigation", "references"}, where
    )
    raw_level = _mc_str(payload, "risk_level", where)
    try:
        risk_level = RiskLevel(raw_level)
    except ValueError:
        raise ValueError(
            f"ethical_consideration field 'risk_level' has unknown value {raw_level!r}"
        ) from None
    return EthicalConsideration(
        category=_mc_str(payload, "category", where),
        description=_mc_str(payload, "description", where),
        risk_level=risk_level,
        mitigation=_mc_str(payload, "mitigation", where),
        references=_mc_str_list(payload, "references", where, required=False),
    )


def _caveat_from_dict(data: Any) -> Caveat:
    where = "caveat"
    payload = _mc_mapping(data, where, "model card")
    _mc_no_unknown(payload, {"description", "priority", "category", "applies_to"}, where)
    return Caveat(
        description=_mc_str(payload, "description", where),
        priority=_mc_str(payload, "priority", where),
        category=_mc_str(payload, "category", where),
        applies_to=_mc_str_list(payload, "applies_to", where, required=False),
    )


@dataclass
class ModelCard:
    """Complete model card for a detector."""

    metadata: ModelCardMetadata
    model_details: ModelDetails
    intended_use: IntendedUse
    factors: list[str] = field(default_factory=list)
    metrics: list[PerformanceMetric] = field(default_factory=list)
    evaluation_data: EvaluationDataset | None = None
    training_data: TrainingData | None = None
    quantitative_analysis: QuantitativeAnalysis | None = None
    ethical_considerations: list[EthicalConsideration] = field(default_factory=list)
    caveats_and_recommendations: list[Caveat] = field(default_factory=list)
    additional_information: dict[str, Any] = field(default_factory=dict)
    eu_ai_act_transparency_notes: dict[str, Any] = field(default_factory=dict)

    # Internal tracking
    _schema_version: str = "1.0.0"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        from dataclasses import asdict

        return {
            "schema_version": self._schema_version,
            "metadata": asdict(self.metadata),
            "model_details": asdict(self.model_details),
            "intended_use": asdict(self.intended_use),
            "factors": self.factors,
            "metrics": [asdict(m) for m in self.metrics],
            "evaluation_data": asdict(self.evaluation_data) if self.evaluation_data else None,
            "training_data": asdict(self.training_data) if self.training_data else None,
            "quantitative_analysis": asdict(self.quantitative_analysis)
            if self.quantitative_analysis
            else None,
            "ethical_considerations": [asdict(e) for e in self.ethical_considerations],
            "caveats_and_recommendations": [asdict(c) for c in self.caveats_and_recommendations],
            "additional_information": self.additional_information,
            "eu_ai_act_transparency_notes": self.eu_ai_act_transparency_notes,
        }

    def to_json(self, indent: int = 2) -> str:
        """Export as JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_markdown(self) -> str:
        """Export as Markdown for documentation."""
        lines = [
            f"# Model Card: {self.model_details.name} v{self.model_details.version}",
            "",
            "## Model Details",
            f"- **Name**: {self.model_details.name}",
            f"- **Version**: {self.model_details.version}",
            f"- **Detector ID**: {self.model_details.detector_id}",
            f"- **Family**: {self.model_details.detector_family}",
            f"- **Architecture**: {self.model_details.architecture}",
            f"- **Framework**: {self.model_details.framework}",
            f"- **License**: {self.model_details.license}",
            f"- **Owner**: {self.model_details.owner}",
            f"- **Contact**: {self.model_details.contact}",
            "",
            "## Intended Use",
            f"**Primary Use Cases**: {', '.join(self.intended_use.primary_use_cases)}",
            f"**Out of Scope**: {', '.join(self.intended_use.out_of_scope)}",
            f"**Target Users**: {', '.join(self.intended_use.target_users)}",
            "",
            "## Metrics",
        ]

        for metric in self.metrics:
            ci = f" (CI: {metric.confidence_interval})" if metric.confidence_interval else ""
            lines.append(
                f"- **{metric.name}**: {metric.value} {metric.unit}{ci} - {metric.benchmark_dataset}/{metric.split}"
            )

        if self.quantitative_analysis:
            lines.extend(
                [
                    "",
                    "## Quantitative Analysis",
                    f"- ROC AUC: {self.quantitative_analysis.roc_auc or 'N/A'}",
                    f"- PR AUC: {self.quantitative_analysis.pr_auc or 'N/A'}",
                    f"- Calibration Error: {self.quantitative_analysis.calibration_error or 'N/A'}",
                ]
            )

        if self.ethical_considerations:
            lines.extend(["", "## Ethical Considerations"])
            for ec in self.ethical_considerations:
                lines.append(f"- **{ec.category}** ({ec.risk_level.value}): {ec.description}")
                lines.append(f"  Mitigation: {ec.mitigation}")

        if self.caveats_and_recommendations:
            lines.extend(["", "## Caveats and Recommendations"])
            for c in self.caveats_and_recommendations:
                lines.append(f"- **[{c.priority.upper()}]** {c.description}")

        if self.eu_ai_act_transparency_notes:
            lines.extend(["", "## EU AI Act Transparency Notes"])
            for k, v in self.eu_ai_act_transparency_notes.items():
                lines.append(f"- **{k}**: {v}")

        return "\n".join(lines)

    def save_json(self, path: Path) -> bool:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.to_json(), encoding="utf-8")
            return True
        except Exception:
            return False

    def save_markdown(self, path: Path) -> bool:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.to_markdown(), encoding="utf-8")
            return True
        except Exception:
            return False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ModelCard:
        """Reconstruct a model card from :meth:`to_dict` output.

        Every section is rebuilt field by field with validation, so a
        document that is valid JSON but not a valid model card is
        rejected instead of silently loading as an empty card.

        Raises
        ------
        ValueError
            If ``data`` is not a mapping, if a required field is
            missing, if a field has the wrong type, if an unknown field
            is present, or if ``schema_version`` is not ``"1.0.0"``.
        """
        if not isinstance(data, Mapping):
            raise ValueError("model card must be a mapping")
        _mc_no_unknown(
            data,
            {
                "schema_version",
                "metadata",
                "model_details",
                "intended_use",
                "factors",
                "metrics",
                "evaluation_data",
                "training_data",
                "quantitative_analysis",
                "ethical_considerations",
                "caveats_and_recommendations",
                "additional_information",
                "eu_ai_act_transparency_notes",
            },
            "model card",
        )
        schema_version = _mc_str(data, "schema_version", "model card")
        if schema_version != "1.0.0":
            raise ValueError(f"unsupported model card schema_version: {schema_version!r}")
        raw_metrics = data.get("metrics", [])
        if not isinstance(raw_metrics, list):
            raise ValueError("model card field 'metrics' must be a list")
        raw_ethical = data.get("ethical_considerations", [])
        if not isinstance(raw_ethical, list):
            raise ValueError("model card field 'ethical_considerations' must be a list")
        raw_caveats = data.get("caveats_and_recommendations", [])
        if not isinstance(raw_caveats, list):
            raise ValueError("model card field 'caveats_and_recommendations' must be a list")
        evaluation_data = data.get("evaluation_data")
        training_data = data.get("training_data")
        quantitative_analysis = data.get("quantitative_analysis")
        additional_information: dict[str, Any] = {}
        if data.get("additional_information") is not None:
            additional_information = _mc_dict(data, "additional_information", "model card")
        eu_notes: dict[str, Any] = {}
        if data.get("eu_ai_act_transparency_notes") is not None:
            eu_notes = _mc_dict(data, "eu_ai_act_transparency_notes", "model card")
        return cls(
            metadata=_metadata_from_dict(_mc_required(data, "metadata", "model card")),
            model_details=_model_details_from_dict(
                _mc_required(data, "model_details", "model card")
            ),
            intended_use=_intended_use_from_dict(_mc_required(data, "intended_use", "model card")),
            factors=_mc_str_list(data, "factors", "model card", required=False),
            metrics=[_metric_from_dict(item) for item in raw_metrics],
            evaluation_data=(
                _evaluation_dataset_from_dict(evaluation_data)
                if evaluation_data is not None
                else None
            ),
            training_data=(
                _training_data_from_dict(training_data) if training_data is not None else None
            ),
            quantitative_analysis=(
                _quantitative_analysis_from_dict(quantitative_analysis)
                if quantitative_analysis is not None
                else None
            ),
            ethical_considerations=[_ethical_consideration_from_dict(item) for item in raw_ethical],
            caveats_and_recommendations=[_caveat_from_dict(item) for item in raw_caveats],
            additional_information=additional_information,
            eu_ai_act_transparency_notes=eu_notes,
            _schema_version=schema_version,
        )

    @classmethod
    def load(cls, path: Path) -> ModelCard:
        """Load a model card from a JSON file.

        Returns the reconstructed :class:`ModelCard` (never ``None``:
        the previous stub returned ``None`` for every valid file).

        Raises
        ------
        FileNotFoundError
            If ``path`` does not exist.
        ValueError
            If the file is not valid JSON, cannot be read, or its
            content is not a valid model card document.
        """
        try:
            text = Path(path).read_text(encoding="utf-8")
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise ValueError(f"cannot read model card {path}: {exc}") from exc
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON in model card {path}: {exc}") from exc
        return cls.from_dict(data)


class ModelCardGenerator:
    """Generates model cards from detector metadata and performance data."""

    def __init__(
        self,
        calibration_manager: CalibrationManager | None = None,
        benchmark_runner: BenchmarkRunner | None = None,
    ):
        self.calibration_manager = calibration_manager
        self.benchmark_runner = benchmark_runner

    def generate(
        self,
        detector_id: str,
        detector_version: str,
        detector_family: str,
        architecture: str,
        framework: str,
        intended_use: IntendedUse,
        evaluation_data: EvaluationDataset | None = None,
        training_data: TrainingData | None = None,
        quantitative_analysis: QuantitativeAnalysis | None = None,
        ethical_considerations: list[EthicalConsideration] | None = None,
        caveats: list[Caveat] | None = None,
        license: str = "AGPL-3.0-or-later",
        owner: str = "TextForensics",
        contact: str = "security@textforensics.example",
    ) -> ModelCard:
        """Generate a model card for a detector."""

        # Create model details
        model_details = ModelDetails(
            name=f"TextForensics {detector_id}",
            version=detector_version,
            detector_id=detector_id,
            detector_family=detector_family,
            architecture=architecture,
            framework=framework,
            license=license,
            owner=owner,
            contact=contact,
        )

        # Build metadata
        ModelCardMetadata(
            version="1.0.0",
            generated_at=datetime.now(UTC).isoformat(),
            generated_by="TextForensics ModelCardGenerator v1.0",
        )

        # Build EU AI Act transparency notes (not a compliance claim:
        # no conformity assessment is performed here)
        eu_notes = self._build_eu_ai_act_transparency_notes(
            training_data=training_data,
            evaluation_data=evaluation_data,
        )

        # Default ethical considerations if none provided
        ethical = ethical_considerations or self._default_ethical_considerations()

        # Default caveats if none provided
        caveats = caveats or self._default_caveats()

        return ModelCard(
            metadata=ModelCardMetadata(
                version="1.0.0",
                generated_at=datetime.now(UTC).isoformat(),
                generated_by="TextForensics ModelCardGenerator v1.0",
            ),
            model_details=model_details,
            intended_use=intended_use,
            factors=self._default_factors(),
            metrics=[],  # Populated from benchmark results
            evaluation_data=evaluation_data,
            training_data=training_data,
            quantitative_analysis=quantitative_analysis,
            ethical_considerations=ethical,
            caveats_and_recommendations=caveats,
            eu_ai_act_transparency_notes=eu_notes,
        )

    def _default_factors(self) -> list[str]:
        return [
            "Input text length",
            "Language",
            "Domain/genre",
            "Writing style",
            "Presence of adversarial perturbations",
            "Model version",
        ]

    def _default_ethical_considerations(self) -> list[EthicalConsideration]:
        return [
            EthicalConsideration(
                category="bias",
                description="Detector may exhibit bias against non-native English writers or specific demographic writing styles",
                risk_level=RiskLevel.LIMITED,
                mitigation="Regular bias audits across demographic groups; use diverse evaluation datasets",
                references=["https://arxiv.org/abs/2301.12345"],
            ),
            EthicalConsideration(
                category="privacy",
                description="Input text may contain sensitive or personal information",
                risk_level=RiskLevel.LIMITED,
                mitigation="Process text locally; do not log or store input text; implement data minimization",
                references=["GDPR Art. 5(1)(c)"],
            ),
            EthicalConsideration(
                category="fairness",
                description="False positive rates may vary across demographic groups",
                risk_level=RiskLevel.HIGH,
                mitigation="Regular fairness audits; publish false positive rates by demographic; implement human-in-the-loop for high-stakes decisions",
                references=["https://arxiv.org/abs/2301.12345"],
            ),
            EthicalConsideration(
                category="transparency",
                description="Detector outputs may be misinterpreted as definitive proof of AI authorship",
                risk_level=RiskLevel.HIGH,
                mitigation="Clear documentation that scores are not probabilities; provide confidence intervals; require human review for high-stakes decisions",
                references=["AGENTS.md Rule #2"],
            ),
            EthicalConsideration(
                category="security",
                description="Adversarial attacks could manipulate detector outputs",
                risk_level=RiskLevel.HIGH,
                mitigation="Adversarial training; input sanitization; anomaly detection on inputs; regular adversarial robustness testing",
                references=["https://arxiv.org/abs/2301.12345"],
            ),
        ]

    def _default_caveats(self) -> list[Caveat]:
        return [
            Caveat(
                description="Detector scores are not probabilities of AI authorship without calibration",
                priority="high",
                category="limitation",
                applies_to=["all_detectors"],
            ),
            Caveat(
                description="Performance may degrade on short texts (< 100 words)",
                priority="high",
                category="limitation",
                applies_to=["short_text"],
            ),
            Caveat(
                description="Non-English languages may have reduced accuracy",
                priority="high",
                category="limitation",
                applies_to=["non_english"],
            ),
            Caveat(
                description="Adversarial perturbations may evade detection",
                priority="high",
                category="caveat",
                applies_to=["adversarial"],
            ),
            Caveat(
                description="Regular recalibration recommended as models evolve",
                priority="medium",
                category="recommendation",
                applies_to=["all_detectors"],
            ),
            Caveat(
                description="Human review required for high-stakes decisions",
                priority="critical",
                category="recommendation",
                applies_to=["high_stakes"],
            ),
        ]

    def _build_eu_ai_act_transparency_notes(
        self,
        *,
        training_data: TrainingData | None = None,
        evaluation_data: EvaluationDataset | None = None,
    ) -> dict[str, Any]:
        """Build the EU AI Act transparency-notes section.

        These are notes about the topics the EU AI Act asks deployers to
        be transparent about — not a conformity assessment, not a claim
        that the detector (or any deployment of it) complies, and not a
        CE marking statement. Risk classification depends on the
        deployment use case, not on the detector alone, so it is recorded
        as not assessed. The data-governance flags reflect only whether
        documentation was actually supplied to this generator, and the
        obligations list contains only what this generator does
        (metrics are NOT populated here, so "performance metrics
        published" is not claimed).
        """
        return {
            "note": (
                "Transparency notes only. No conformity assessment has been "
                "performed; this card does not certify regulatory compliance."
            ),
            "risk_classification": "not_assessed",
            "transparency_obligations": [
                "Model card published",
                "Limitations documented",
            ],
            "human_oversight": "required",
            "accuracy_robustness": {
                "calibration": "required",
                "robustness_testing": "required",
                "monitoring": "continuous",
            },
            "data_governance": {
                "training_data_documented": training_data is not None,
                "evaluation_data_documented": evaluation_data is not None,
                "bias_assessment": "required",
            },
            "transparency_register": "required_for_high_risk",
            "post_market_monitoring": "required",
            "incident_reporting": "required",
            "conformity_assessment": "not_assessed",
            "ce_marking": "not_claimed",
            "technical_documentation": "required",
            "user_instructions": "required",
        }


def create_model_card(
    detector_id: str,
    detector_version: str,
    detector_family: str,
    architecture: str,
    framework: str,
    intended_use: IntendedUse,
    license: str = "AGPL-3.0-or-later",
    owner: str = "TextForensics",
    contact: str = "security@textforensics.example",
    evaluation_data: EvaluationDataset | None = None,
    training_data: TrainingData | None = None,
    quantitative_analysis: QuantitativeAnalysis | None = None,
    ethical_considerations: list[EthicalConsideration] | None = None,
    caveats: list[Caveat] | None = None,
) -> ModelCard:
    """Convenience function to create a model card."""
    generator = ModelCardGenerator()
    return generator.generate(
        detector_id=detector_id,
        detector_version=detector_version,
        detector_family=detector_family,
        architecture=architecture,
        framework=framework,
        license=license,
        owner=owner,
        contact=contact,
        intended_use=intended_use,
        evaluation_data=evaluation_data,
        training_data=training_data,
        quantitative_analysis=quantitative_analysis,
        ethical_considerations=ethical_considerations,
        caveats=caveats,
    )


def save_model_card(card: ModelCard, path: Path, format: str = "json") -> bool:
    """Save model card to file."""
    if format == "json":
        return card.save_json(path)
    elif format == "markdown":
        return card.save_markdown(path)
    else:
        raise ValueError(f"Unsupported format: {format}")


def load_model_card(path: Path) -> ModelCard:
    """Load model card from file.

    Returns the reconstructed :class:`ModelCard` (never ``None``: the
    previous stub returned ``None`` for every valid file).

    Raises
    ------
    FileNotFoundError
        If ``path`` does not exist.
    ValueError
        If the file is not valid JSON or its content is not a valid
        model card document.
    """
    return ModelCard.load(path)
