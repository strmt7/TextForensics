"""TextForensics: independent audit layer for AI-text detectors.

TextForensics reports what detectors observed, which validation evidence covers
the input's conditions, and how trustworthy that coverage is.  It does not
claim to prove authorship, and a detector score is never silently promoted to
a probability.
"""

from ._build_info import (
    BUILD_INFO,
    get_build_info,
    get_build_info_json,
    initialize_build_info,
    verify_build_identity,
)
from .adversarial import (
    AdversarialDetector,
    AdversarialFinding,
    HumanizationPatternLibrary,
    HumanizationReport,
    detect_humanization,
    detect_humanization_simple,
)
from .benchmark_fingerprint import (
    DatasetFingerprint,
    check_disjointness,
    fingerprint_dataset,
    load_fingerprint,
    save_fingerprint,
    validate_disjointness,
    verify_fingerprint,
)
from .calibration import (
    CalibrationArtifact,
    CalibrationCurve,
    CalibrationError,
    CalibrationManager,
    CalibrationResult,
    DatasetReference,
    load_calibration_artifact,
    save_calibration_artifact,
    validate_calibration_artifact,
)
from .capability_ledger import (
    CapabilityClaim,
    CapabilityLedger,
    EvidenceLabel,
    EvidenceRef,
    EvidenceTier,
    ledger_to_trust_dimension,
    validate_claim,
)
from .casefile import (
    replay_case_file,
    replay_case_file_path,
    seal_case_file,
    verify_case_file,
    verify_case_file_path,
    write_case_file,
)
from .compare import compare_texts
from .conditions import (
    CONDITIONS_SCHEMA,
    InputConditions,
    conditions_from_dict,
    extract_conditions,
    length_band,
)
from .constants import (
    EXIT_DOWNGRADED,
    EXIT_ERROR,
    EXIT_INCOMPLETE,
    EXIT_OK,
    exit_code_description,
    exit_code_name,
    validate_exit_code,
)
from .detectors import (
    DETECTOR_EVIDENCE_SCHEMA,
    DETECTOR_SCHEMA_V1,
    DETECTOR_SCHEMA_V2,
    BuiltinHeuristicDetector,
    Detector,
    DetectorContractError,
    DetectorFailure,
    DetectorPrediction,
    DetectorRegistry,
    discover_detector_registry,
    execute_detector,
    list_detector_health,
    list_detector_metadata,
    normalize_prediction,
    validate_prediction,
)
from .drift import DriftObservatory
from .engine import analyze_text
from .evidence import (
    EVIDENCE_SCHEMA,
    REGISTRY_SCHEMA,
    BenchmarkProvenance,
    DetectorCoverage,
    DimensionCoverage,
    EvidenceError,
    EvidenceRecord,
    EvidenceRegistry,
    MetricEstimate,
    RegistryVerification,
    RunProvenance,
    SliceConditions,
    ValidationSlice,
    assess_detector_coverage,
    coverage_for_predictions,
    empty_registry,
    load_registry,
)
from .explain import (
    CounterfactualExplainer,
    ExplanationReport,
    SegmentAttribution,
    explain_verdict,
    load_explanation_report,
    save_explanation_report,
    split_sentences,
)
from .report import ForensicBundle, VerdictIntegrity, build_forensic_bundle
from .semantic import (
    SemanticConsistencyChecker,
    SemanticConsistencyReport,
    SemanticSegment,
    analyze_semantic_consistency,
)
from .threshold_selection import evaluate_threshold, select_threshold
from .trust import (
    TRUST_DIMENSIONS,
    TRUST_SCHEMA,
    TRUST_STATES,
    TrustDimension,
    TrustMap,
    assess_trust_map,
    build_trust_map,
    trust_map_from_capability_ledger,
)
from .verify import (
    VerificationReport,
    verify_all,
    verify_benchmark,
    verify_calibration,
)
from .verify import verify_case_file as verify_case_file_legacy
from .version import get_version

__all__ = [
    "BUILD_INFO",
    "AdversarialDetector",
    "AdversarialFinding",
    "BenchmarkProvenance",
    "BuiltinHeuristicDetector",
    "CONDITIONS_SCHEMA",
    "CalibrationArtifact",
    "CalibrationCurve",
    "CalibrationError",
    "CalibrationManager",
    "CalibrationResult",
    "CapabilityClaim",
    "CapabilityLedger",
    "CounterfactualExplainer",
    "DETECTOR_EVIDENCE_SCHEMA",
    "DETECTOR_SCHEMA_V1",
    "DETECTOR_SCHEMA_V2",
    "DatasetFingerprint",
    "DatasetReference",
    "Detector",
    "DetectorContractError",
    "DetectorCoverage",
    "DetectorFailure",
    "DetectorPrediction",
    "DetectorRegistry",
    "DimensionCoverage",
    "DriftObservatory",
    "EVIDENCE_SCHEMA",
    "EXIT_DOWNGRADED",
    "EXIT_ERROR",
    "EXIT_INCOMPLETE",
    "EXIT_OK",
    "EvidenceError",
    "EvidenceLabel",
    "EvidenceRecord",
    "EvidenceRef",
    "EvidenceRegistry",
    "EvidenceTier",
    "ExplanationReport",
    "ForensicBundle",
    "HumanizationPatternLibrary",
    "HumanizationReport",
    "InputConditions",
    "MetricEstimate",
    "REGISTRY_SCHEMA",
    "RegistryVerification",
    "RunProvenance",
    "SegmentAttribution",
    "SemanticConsistencyChecker",
    "SemanticConsistencyReport",
    "SemanticSegment",
    "SliceConditions",
    "TRUST_DIMENSIONS",
    "TRUST_SCHEMA",
    "TRUST_STATES",
    "TrustDimension",
    "TrustMap",
    "ValidationSlice",
    "VerdictIntegrity",
    "VerificationReport",
    "analyze_semantic_consistency",
    "analyze_text",
    "assess_detector_coverage",
    "assess_trust_map",
    "build_forensic_bundle",
    "build_trust_map",
    "check_disjointness",
    "compare_texts",
    "conditions_from_dict",
    "coverage_for_predictions",
    "detect_humanization",
    "detect_humanization_simple",
    "discover_detector_registry",
    "empty_registry",
    "evaluate_threshold",
    "execute_detector",
    "exit_code_description",
    "exit_code_name",
    "explain_verdict",
    "extract_conditions",
    "fingerprint_dataset",
    "get_build_info",
    "get_build_info_json",
    "get_version",
    "initialize_build_info",
    "ledger_to_trust_dimension",
    "length_band",
    "list_detector_health",
    "list_detector_metadata",
    "load_calibration_artifact",
    "load_explanation_report",
    "load_fingerprint",
    "load_registry",
    "normalize_prediction",
    "replay_case_file",
    "replay_case_file_path",
    "save_calibration_artifact",
    "save_explanation_report",
    "save_fingerprint",
    "seal_case_file",
    "select_threshold",
    "split_sentences",
    "trust_map_from_capability_ledger",
    "validate_calibration_artifact",
    "validate_claim",
    "validate_disjointness",
    "validate_exit_code",
    "validate_prediction",
    "verify_all",
    "verify_benchmark",
    "verify_build_identity",
    "verify_calibration",
    "verify_case_file",
    "verify_case_file_legacy",
    "verify_case_file_path",
    "verify_fingerprint",
    "write_case_file",
]

__version__ = get_version()


def _import_enterprise_policy():
    """Lazily import the optional enterprise-policy module."""
    from . import enterprise_policy

    return enterprise_policy


def _import_telemetry():
    """Lazily import the optional telemetry module."""
    from . import telemetry

    return telemetry


def __getattr__(name: str):
    enterprise_names = {
        "EnterprisePolicy",
        "EnterprisePolicyEngine",
        "PolicyRevisionFloor",
        "PolicyState",
        "compute_policy_digest",
        "validate_enterprise_policy",
    }
    if name in enterprise_names:
        policy = _import_enterprise_policy()
        return getattr(policy, name)
    if name in {
        "AnalysisTimer",
        "initialize_telemetry",
        "is_telemetry_initialized",
        "record_analysis",
        "record_error",
        "shutdown_telemetry",
        "timed_analysis",
    }:
        telemetry = _import_telemetry()
        return getattr(telemetry, name)
    raise AttributeError(f"module 'textforensics' has no attribute '{name}'")
