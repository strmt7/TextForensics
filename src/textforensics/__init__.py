"""TextForensics: detector reliability and AI-text forensics."""

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
from .capability_ledger import (
    CapabilityClaim,
    CapabilityLedger,
    EvidenceLabel,
    EvidenceRef,
    EvidenceTier,
    ledger_to_trust_dimension,
    validate_claim,
)
from .casefile import seal_case_file, verify_case_file
from .compare import compare_texts
from .constants import (
    EXIT_DOWNGRADED,
    EXIT_ERROR,
    EXIT_INCOMPLETE,
    EXIT_OK,
    exit_code_description,
    exit_code_name,
    validate_exit_code,
)
from .drift import DriftObservatory
from .engine import analyze_text
from .explain import (
    CounterfactualExplainer,
    ExplanationReport,
    SegmentAttribution,
    explain_verdict,
    load_explanation_report,
    save_explanation_report,
    split_sentences,
)
from .report import build_forensic_bundle
from .semantic import (
    SemanticConsistencyChecker,
    SemanticConsistencyReport,
    SemanticSegment,
    analyze_semantic_consistency,
)
from .threshold_selection import (
    evaluate_threshold,
    select_threshold,
)
from .trust import trust_map_from_capability_ledger
from .verify import (
    VerificationReport,
    verify_all,
    verify_benchmark,
    verify_calibration,
    verify_case_file_path,
)
from .verify import (
    verify_case_file as verify_case_file_nversion,
)
from .version import get_version


# Lazy import for enterprise features (cryptography is optional)
def _import_enterprise_policy():
    """Lazily import enterprise policy module."""
    from . import enterprise_policy

    return enterprise_policy


# Lazy import for telemetry features (opentelemetry is optional)
def _import_telemetry():
    """Lazily import telemetry module."""
    from . import telemetry

    return telemetry


__all__ = [
    "BUILD_INFO",
    "AdversarialDetector",
    "AdversarialFinding",
    "analyze_text",
    "build_forensic_bundle",
    "CapabilityClaim",
    "CapabilityLedger",
    "check_disjointness",
    "compare_texts",
    "compute_policy_digest",
    "CounterfactualExplainer",
    "DatasetFingerprint",
    "DriftObservatory",
    "evaluate_threshold",
    "EnterprisePolicy",
    "EnterprisePolicyEngine",
    "EvidenceLabel",
    "EvidenceRef",
    "EvidenceTier",
    "ExplanationReport",
    "EXIT_DOWNGRADED",
    "EXIT_ERROR",
    "EXIT_INCOMPLETE",
    "EXIT_OK",
    "exit_code_description",
    "exit_code_name",
    "explain_verdict",
    "fingerprint_dataset",
    "get_build_info",
    "get_build_info_json",
    "get_version",
    "initialize_build_info",
    "ledger_to_trust_dimension",
    "load_explanation_report",
    "load_fingerprint",
    "PolicyRevisionFloor",
    "PolicyState",
    "save_explanation_report",
    "save_fingerprint",
    "SegmentAttribution",
    "select_threshold",
    "seal_case_file",
    "split_sentences",
    "trust_map_from_capability_ledger",
    "validate_claim",
    "validate_disjointness",
    "validate_enterprise_policy",
    "validate_exit_code",
    "verify_all",
    "verify_benchmark",
    "verify_calibration",
    "verify_build_identity",
    "verify_case_file",
    "verify_case_file_nversion",
    "verify_case_file_path",
    "verify_fingerprint",
    "VerificationReport",
    "AdversarialDetector",
    "AdversarialFinding",
    "HumanizationPatternLibrary",
    "HumanizationReport",
    "detect_humanization",
    "detect_humanization_simple",
    "HumanizationPatternLibrary",
    "SemanticConsistencyChecker",
    "SemanticConsistencyReport",
    "SemanticSegment",
    "analyze_semantic_consistency",
]

__version__ = get_version()


# Lazy __getattr__ for optional telemetry exports
def __getattr__(name: str):
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
