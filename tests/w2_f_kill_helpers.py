"""Shared probe grids for the W2 Worker F kill tests (audit-w2-f).

Each ``probe_*`` function calls one W2-changed function over an input grid
chosen to distinguish its killable mutants (see
hidden_files/audit-w2-f-classify-notes.md for the distinguishing input per
site) and returns the (input, output) rows. The kill-test files
(tests/test_audit_w2_worker_f_*.py) assert these rows equal the values
recorded on the original source; any mutant that changes any row fails.

GENERATED scaffolding: the probe functions were developed as analysis
scaffolding (hidden_files/audit-w2-f-probes.py) and are kept here so the
kill tests are self-contained. Do not hand-edit the grids — regenerate
via hidden_files/audit-w2-f-gen-kill-tests.py.
"""
"""Worker F: differential probes for the W2 domain-equivalent candidates.

Each probe is a zero-argument callable returning a JSON-serializable digest
(a list of (input-description, outcome) pairs, where outcome is the repr of
the return value or the exception type + message). The driver
(audit-w2-f-diffprobe2.py) runs each probe under the ORIGINAL source and
under the hand-applied mutant and requires identical digests.

Mul_Div `*,` candidates are NOT probed here: their equivalence rests on the
in-repo call-site survey (audit-w2-f-muldiv-survey2.py: 0 positional
callers), not on a behavioural probe.
"""
import itertools
import json
import re

_TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+00:00|Z)?")


def _scrub(text):
    # Timestamps (generated_at_utc etc.) vary per call and are not behaviour.
    return _TIME_RE.sub("TIME", text)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def outcome(fn, *args, **kwargs):
    try:
        return ("ok", repr(fn(*args, **kwargs)))
    except Exception as exc:  # noqa: BLE001 - probe must record, not raise
        return ("raise", type(exc).__name__, str(exc))


def digest(rows):
    return _scrub(json.dumps(rows, default=str, sort_keys=True))


# ---------------------------------------------------------------------------
# trust._overall_state
# ---------------------------------------------------------------------------

def probe_trust_overall_state():
    from textforensics.trust import TrustDimension, _overall_state, TRUST_DIMENSIONS
    rows = []
    states = ("supported", "partial", "unknown", "out_of_scope")
    # every count-tuple summing to 8 (165 combos)
    for tup in itertools.product(range(9), repeat=4):
        if sum(tup) != 8:
            continue
        dims = []
        i = 0
        for st, n in zip(states, tup):
            for _ in range(n):
                dims.append(TrustDimension(dimension=TRUST_DIMENSIONS[i % len(TRUST_DIMENSIONS)],
                                           state=st, reason="probe"))
                i += 1
        rows.append((tup, outcome(_overall_state, dims)))
    # dimension-set variants: exact DECLARED, subset, superset (rogue), empty.
    # _overall_state duck-types .dimension/.state, so rogue names go through
    # SimpleNamespace (TrustDimension.__post_init__ rejects unknown names).
    from types import SimpleNamespace
    for names in (list(TRUST_DIMENSIONS),
                  list(TRUST_DIMENSIONS)[:7],
                  list(TRUST_DIMENSIONS) + ["rogue_dim"],
                  []):
        dims = [SimpleNamespace(dimension=n, state="supported") for n in names]
        rows.append((("set", tuple(names)), outcome(_overall_state, dims)))
    # the exact C10 rogue-dimension scenario: 8 supported + 1 unknown + 1 rogue supported
    dims = ([SimpleNamespace(dimension=n, state="supported") for n in TRUST_DIMENSIONS]
            + [SimpleNamespace(dimension="rogue_dim", state="supported")])
    rows.append((("rogue",), outcome(_overall_state, dims)))
    # 9 DECLARED (8 supported + 1 unknown) + 1 rogue supported
    dims = ([SimpleNamespace(dimension=n, state="supported") for n in TRUST_DIMENSIONS[:7]]
            + [SimpleNamespace(dimension=TRUST_DIMENSIONS[7], state="unknown")]
            + [SimpleNamespace(dimension="rogue_dim", state="supported")])
    rows.append((("rogue2",), outcome(_overall_state, dims)))
    return rows


# ---------------------------------------------------------------------------
# trust.assess_trust_map (Is_Eq: registry_verified is False/True -> ==)
# ---------------------------------------------------------------------------

def probe_trust_assess():
    from textforensics.trust import assess_trust_map
    from textforensics.evidence import InputConditions
    from textforensics.detectors import DetectorPrediction
    cond = InputConditions(schema="textforensics.input-conditions/v1", language="en",
                           language_confidence="declared", script="latin",
                           word_count=200, char_count=1000, length_band="medium",
                           domain_genre="general", domain_confidence="declared",
                           editing_regime="human_only", generator=None,
                           human_population="unknown")
    pred = DetectorPrediction(schema="textforensics.detector-result/v2",
                              detector_id="detector", detector_version="1",
                              detector_family="family", execution="local",
                              score=0.8, score_semantics="test", verdict="ai_like",
                              threshold=0.5)
    rows = []
    for verified in (True, False, None):
        try:
            tm = assess_trust_map(cond, [pred], registry=None, registry_verified=verified)
            # timestamp-free: generated_at_utc varies per call; overall +
            # per-dimension states are the stable outputs.
            rows.append((verified, ("ok", tm.overall,
                                    [(d.dimension, d.state) for d in tm.dimensions])))
        except Exception as exc:  # noqa: BLE001
            rows.append((verified, ("raise", type(exc).__name__, str(exc))))
    return rows


# ---------------------------------------------------------------------------
# trust.trust_map_from_capability_ledger
# ---------------------------------------------------------------------------

def _ledger_claim(capability="language", tier_name="VALIDATED", valid_until=None, evidence=True):
    from textforensics.policy import CapabilityClaim, EvidenceLabel, EvidenceRef, EvidenceTier
    tier = getattr(EvidenceTier, tier_name)
    return CapabilityClaim(
        detector_id="a", capability=capability, tier=tier,
        evidence=[EvidenceRef(label=EvidenceLabel.EXECUTED, tier=tier, artifact="runs/1.json")]
        if evidence else [],
        valid_until=valid_until)


def _ledger_with(*claims):
    from textforensics.policy import CapabilityLedger
    ledger = CapabilityLedger()
    for claim in claims:
        ledger.register(claim)
    return ledger


def probe_trust_ledger():
    from textforensics.trust import trust_map_from_capability_ledger
    rows = []
    caps = ("language", "length", "domain", "editing", "generator", "human_population")
    for cap in caps:
        for tier in ("VALIDATED", "READABLE", "TOOL_BACKED"):
            ledger = _ledger_with(_ledger_claim(capability=cap, tier_name=tier))
            tm = trust_map_from_capability_ledger(ledger)
            rows.append(((cap, tier), tm.overall,
                         [(d.dimension, d.state) for d in tm.dimensions]))
    # expired / evidence-less / ineffective claims (the NumberReplacer:48/50/51 shapes)
    for kwargs in ({"valid_until": "2000-01-01"}, {"evidence": False},
                   {"tier_name": "READABLE", "evidence": False}):
        ledger = _ledger_with(_ledger_claim(**kwargs))
        tm = trust_map_from_capability_ledger(ledger)
        rows.append((("ineffective", tuple(sorted(kwargs.items()))), tm.overall,
                     [(d.dimension, d.state) for d in tm.dimensions]))
    # 6 dims with 2 unknown (the :50 shape) and 4 dims with 2 unknown (the :51 shape)
    for n_unknown in (0, 1, 2, 3, 4):
        claims = [_ledger_claim(capability=c) for c in caps[:6]]
        # make n_unknown of them ineffective by expiring them
        claims = [(_ledger_claim(capability=c, valid_until="2000-01-01") if i < n_unknown
                   else _ledger_claim(capability=c)) for i, c in enumerate(caps[:6])]
        tm = trust_map_from_capability_ledger(_ledger_with(*claims))
        rows.append((("unknown-count", n_unknown), tm.overall,
                     [(d.dimension, d.state) for d in tm.dimensions]))
    return rows


# ---------------------------------------------------------------------------
# validation._overall_state_v3 / verify._recompute_overall(_v3) /
# _standalone_verify._recompute_trust_map_overall
# ---------------------------------------------------------------------------

def _overall_grid(fn, make_dim, dim_names):
    rows = []
    states = ("supported", "partial", "unknown", "out_of_scope")
    for tup in itertools.product(range(9), repeat=4):
        if sum(tup) != 8:
            continue
        dims, i = [], 0
        for st, n in zip(states, tup):
            for _ in range(n):
                dims.append(make_dim(dim_names[i % len(dim_names)], st))
                i += 1
        rows.append((tup, outcome(fn, dims)))
    from types import SimpleNamespace
    for names in (list(dim_names), list(dim_names)[:7], list(dim_names) + ["rogue_dim"], []):
        # dict-shaped inputs (verify) take the rogue name directly; dataclass
        # inputs (validation) need duck-typed namespaces
        try:
            dims = [make_dim(n, "supported") for n in names]
        except ValueError:
            dims = [SimpleNamespace(dimension=n, state="supported") for n in names]
        rows.append((("set", tuple(names)), outcome(fn, dims)))
    return rows


def probe_validation_overall_v3():
    from textforensics.validation import _overall_state_v3
    from textforensics.trust import TRUST_DIMENSIONS
    # _overall_state_v3 takes the same TrustDimension list shape as trust
    from textforensics.trust import TrustDimension
    return _overall_grid(_overall_state_v3,
                         lambda name, st: TrustDimension(dimension=name, state=st, reason="probe"),
                         TRUST_DIMENSIONS)


def probe_verify_recompute():
    from textforensics.verify import _recompute_overall, _recompute_overall_v3
    rows = []
    for fn, label in ((_recompute_overall, "v2"), (_recompute_overall_v3, "v3")):
        sub = _overall_grid(fn,
                            lambda name, st: {"dimension": name, "state": st},
                            ("language", "text_length", "domain_genre", "editing_revision",
                             "generator_scope", "human_population",
                             "human_false_positive_evidence", "temporal_version_stability"))
        rows.append((label, sub))
    return rows


def probe_sa_recompute():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "standalone_verify", Path("/home/hatch/workspace/TextForensics-w2-f/src/textforensics/_standalone_verify.py"))
    sa = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sa)
    rows = []
    # trust_map shape: {"dimensions": {name: {"state": ...}}, "overall": ...}
    states = ("supported", "partial", "unknown", "out_of_scope")
    names = ("language", "text_length", "domain_genre", "editing_revision",
             "generator_scope", "human_population",
             "human_false_positive_evidence", "temporal_version_stability")
    for schema in (None, "textforensics.trust-map/v2", "textforensics.trust-map/v3"):
        for tup in itertools.product(range(9), repeat=4):
            if sum(tup) != 8:
                continue
            dims, i = [], 0
            for st, n in zip(states, tup):
                for _ in range(n):
                    dims.append({"dimension": names[i % len(names)], "state": st})
                    i += 1
            tm = {"dimensions": dims}
            if schema is not None:
                tm["schema"] = schema
            rows.append(((schema, tup), outcome(sa._recompute_trust_map_overall, tm)))
    return rows


# ---------------------------------------------------------------------------
# probe_metrics (pure functions)
# ---------------------------------------------------------------------------

def probe_pm_brier():
    from textforensics.probe_metrics import brier
    rows = []
    for probs, labels in (
            ([0.1, 0.9], [0, 1]), ([0.5, 0.5], [0, 1]),
            ([0.0, 1.0], [0, 1]), ([0.3, 0.3, 0.7], [0, 1, 1])):
        rows.append(((probs, labels), outcome(brier, probs, labels)))
    # mismatched lengths: must raise identically under both (strict never fires)
    rows.append((("mismatch",), outcome(brier, [0.1, 0.2], [0])))
    return rows


def probe_pm_ece():
    from textforensics.probe_metrics import ece
    rows = []
    for probs, labels, nb in (
            ([0.1, 0.9, 0.4, 0.6], [0, 1, 0, 1], 10),
            ([0.0, 1.0, 0.5], [0, 1, 1], 2),
            ([0.25, 0.75], [0, 1], 1),
            ([0.1, 0.9], [0, 1], 300)):
        rows.append(((probs, labels, nb), outcome(ece, probs, labels, n_bins=nb)))
    rows.append((("mismatch",), outcome(ece, [0.1, 0.2], [0])))
    return rows


def probe_pm_fpr():
    from textforensics.probe_metrics import fpr_at_threshold
    rows = []
    for scores, labels, thr, direction in (
            ([0.1, 0.9, 0.4, 0.6], [0, 1, 0, 1], 0.5, "higher_means_ai"),
            ([0.1, 0.9], [0, 1], 0.0, "higher_means_ai"),
            ([0.1, 0.9], [0, 1], 1.0, "lower_means_ai"),
            ([0.5, 0.5], [0, 1], 0.5, "higher_means_ai")):
        rows.append(((scores, labels, thr, direction),
                     outcome(fpr_at_threshold, scores, labels, thr, direction=direction)))
    rows.append((("mismatch",), outcome(fpr_at_threshold, [0.1], [0, 1], 0.5)))
    return rows


def probe_pm_is_ai_like():
    from textforensics.probe_metrics import is_ai_like
    rows = []
    for score, thr, direction in (
            (0.5, 0.5, "higher_means_ai"), (0.4, 0.5, "higher_means_ai"),
            (0.6, 0.5, "higher_means_ai"), (0.5, 0.5, "lower_means_ai"),
            (0.0, 0.0, "higher_means_ai"), (1.0, 1.0, "lower_means_ai")):
        rows.append(((score, thr, direction), outcome(is_ai_like, score, thr, direction=direction)))
    return rows


def probe_pm_ks_pvalue():
    from textforensics.probe_metrics import ks_pvalue
    rows = []
    for d, n, m in ((0.0, 10, 10), (0.5, 10, 10), (1.0, 5, 7), (0.25, 100, 100), (0.0, 1, 1)):
        rows.append(((d, n, m), outcome(ks_pvalue, d, n, m)))
    return rows


def probe_pm_ks_statistic():
    from textforensics.probe_metrics import ks_statistic
    rows = []
    for a, b in (([1, 2, 3], [1, 2, 3]), ([1, 2], [3, 4, 5]),
                 ([0.5], [0.5, 0.6]), ([1, 1, 1], [2, 2, 2]),
                 (list(range(300)), list(range(300)))):
        rows.append(((a, b), outcome(ks_statistic, a, b)))
    return rows


def probe_pm_oriented():
    from textforensics.probe_metrics import oriented_scores
    rows = []
    for scores, direction in (([0.1, 0.9], "higher_means_ai"), ([0.1, 0.9], "lower_means_ai"),
                              ([], "higher_means_ai"), ([0.5], "lower_means_ai")):
        rows.append(((scores, direction), outcome(oriented_scores, scores, direction=direction)))
    rows.append((("mismatch",), outcome(oriented_scores, [0.1, 0.2], direction="higher_means_ai")))
    return rows


def probe_pm_tpr():
    from textforensics.probe_metrics import tpr_at_fpr
    rows = []
    for scores, labels, target, direction in (
            ([0.1, 0.9, 0.4, 0.6], [0, 1, 0, 1], 0.01, "higher_means_ai"),
            ([0.1, 0.9], [0, 1], 0.5, "higher_means_ai"),
            ([0.1, 0.9], [0, 1], 0.0, "lower_means_ai"),
            ([0.5, 0.5], [0, 1], 0.01, "higher_means_ai")):
        rows.append(((scores, labels, target, direction),
                     outcome(tpr_at_fpr, scores, labels, target_fpr=target, direction=direction)))
    return rows


# ---------------------------------------------------------------------------
# explain._coverage_label
# ---------------------------------------------------------------------------

def probe_explain_coverage_label():
    from textforensics.explain import _coverage_label
    from textforensics.execution_policy import CompletenessAccounting
    rows = []
    rows.append((("none",), outcome(_coverage_label, None)))
    for succeeded, selected in ((0, 0), (0, 5), (5, 5), (3, 5), (1, 300), (300, 300)):
        # attempted=selected, abstained=0, failed=attempted-succeeded (valid partition)
        acc = CompletenessAccounting(selected=selected, attempted=selected,
                                     succeeded=succeeded, abstained=0,
                                     failed=selected - succeeded)
        rows.append(((succeeded, selected), outcome(_coverage_label, acc)))
    return rows


# ---------------------------------------------------------------------------
# probe_runs.evaluate_tiers (GtE_Eq: consecutive >= 2 -> == 2)
# ---------------------------------------------------------------------------

def _tier_metrics(*, psi=None, n_paired=60):
    return {
        "detector_id": "d",
        "slices": {
            "human-native": {
                "n": n_paired,
                "is_human_slice": True,
                "drift_signal_allowed": n_paired >= 50,
                "score_shift": {"ks_statistic": None, "psi": psi,
                                "ks_pvalue_holm_adjusted": None, "n_paired": n_paired},
                "flips": {"n": n_paired, "flips": 0, "flip_rate": 0.0,
                          "flip_rate_ci": [0.01, 0.5], "human_to_ai": 0,
                          "ai_to_human": 0, "to_abstain": 0, "from_abstain": 0,
                          "n_human_paired": n_paired, "human_to_ai_human": 0},
                "calibration": {"ece": None, "baseline_ece": None},
                "human_fpr": None,
            }
        },
        "overall": {"flips": None},
        "worst_slice_fpr": None,
        "holm": {"alpha_per_run": 0.05, "family": "per-slice KS tests", "adjusted_pvalues": {}},
    }


def probe_pr_evaluate_tiers():
    from textforensics.probe_runs import evaluate_tiers, RULE_DRIFT_STATISTIC
    rows = []
    for psi in (None, 0.1, 0.5, 1.0):
        for prev in ([], [{"rule": RULE_DRIFT_STATISTIC, "slice": "human-native"}]):
            rows.append(((psi, len(prev)),
                         outcome(evaluate_tiers, metrics=_tier_metrics(psi=psi),
                                 detector_version="0.1.0", previous_breaches=prev)))
    # below-floor paired denominator: no escalation either way
    rows.append((("floor",),
                 outcome(evaluate_tiers, metrics=_tier_metrics(psi=0.5, n_paired=49),
                         detector_version="0.1.0", previous_breaches=[])))
    return rows


# ---------------------------------------------------------------------------
# policy._claim_is_effective (NotEq_IsNot / Eq_Is enum identity)
# ---------------------------------------------------------------------------

def probe_policy_claim_effective():
    from textforensics.policy import _claim_is_effective, EvidenceTier
    from datetime import date
    rows = []
    for tier in (EvidenceTier.VALIDATED, EvidenceTier.READABLE, EvidenceTier.TOOL_BACKED):
        for valid_until in (None, "2999-01-01", "2000-01-01"):
            claim = _ledger_claim(tier_name=tier.name, valid_until=valid_until)
            rows.append(((tier.name, valid_until),
                         outcome(_claim_is_effective, claim, today=date(2026, 11, 11))))
    # evidence-ref label variants (EXECUTED vs others)
    from textforensics.policy import CapabilityClaim, EvidenceLabel, EvidenceRef
    for label in (EvidenceLabel.EXECUTED, EvidenceLabel.REPORTED, EvidenceLabel.CALCULATED, EvidenceLabel.PROPOSED):
        claim = CapabilityClaim(
            detector_id="a", capability="language", tier=EvidenceTier.VALIDATED,
            evidence=[EvidenceRef(label=label, tier=EvidenceTier.VALIDATED, artifact="runs/1.json")])
        rows.append((("label", label.name),
                     outcome(_claim_is_effective, claim, today=date(2026, 11, 11))))
    return rows

# ---------------------------------------------------------------------------
# calibration
# ---------------------------------------------------------------------------

def _hex64(seed):
    return f"{seed:064x}"


def _platt_curve(**over):
    from textforensics.calibration import CalibrationCurve
    kw = dict(method="platt", parameters={"A": 1.0, "B": 0.0},
              reference_dataset_hash=_hex64(1), reference_dataset_name="test",
              calibrated_at="2024-01-01T00:00:00Z", sample_count=200)
    kw.update(over)
    return CalibrationCurve(**kw)


def probe_cal_post_init():
    from textforensics.calibration import CalibrationCurve, CURVE_SCHEMA, LEGACY_CURVE_SCHEMA
    rows = []
    for method in ("platt", "temperature", "isotonic", "beta", "identity", "unknown", ""):
        for schema in (CURVE_SCHEMA, LEGACY_CURVE_SCHEMA, "wrong"):
            for semantics in ("probability", "logit", "legacy_raw_score", "bogus"):
                for direction in ("higher_means_ai", "lower_means_ai", "bogus"):
                    rows.append(
                        ((method, schema, semantics, direction),
                         outcome(CalibrationCurve, method=method, parameters={"A": 1.0, "B": 0.0},
                                 schema=schema, input_semantics=semantics,
                                 native_score_direction=direction)))
    return rows


def probe_cal_calibrate():
    rows = []
    for method, params in (
            ("platt", {"A": 1.0, "B": 0.0}),
            ("temperature", {"T": 2.0}),
            ("isotonic", {"x": [0.0, 0.5, 1.0], "y": [0.0, 0.5, 1.0]}),
            ("beta", {"a": 2.0, "b": 2.0}),
            ("identity", {})):
        for semantics in ("probability", "logit", "legacy_raw_score"):
            for direction in ("higher_means_ai", "lower_means_ai"):
                try:
                    curve = _platt_curve(method=method, parameters=params,
                                         input_semantics=semantics,
                                         native_score_direction=direction)
                except Exception as exc:  # noqa: BLE001
                    rows.append(((method, semantics, direction), ("raise", type(exc).__name__, str(exc))))
                    continue
                for score in (0.0, 0.25, 0.5, 0.75, 1.0, -1.0, 2.0):
                    rows.append(((method, semantics, direction, score),
                                 outcome(curve.calibrate, score)))
    return rows


def _scored_jsonl(path):
    import json
    rows = ([{"label": "human", "text": f"human observation {i}"} for i in range(4)]
            + [{"label": "ai", "text": f"ai sample {i}"} for i in range(4)])
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def _eval_with_proof(eval_path, status, overlap, diagnostic):
    from textforensics.benchmark import DisjointnessProof, dataset_sha256
    from textforensics.calibration import evaluate_threshold
    proof = DisjointnessProof(status=status, overlap_count=overlap,
                              training_count=8, evaluation_count=8,
                              training_hash=_hex64(1),
                              evaluation_hash=dataset_sha256(eval_path),
                              errors=())
    return evaluate_threshold(eval_path, 0.5, disjointness_proof=proof, diagnostic=diagnostic)


def probe_cal_evaluate_threshold():
    import tempfile
    from pathlib import Path
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        eval_path = Path(tmp) / "eval.jsonl"
        _scored_jsonl(eval_path)
        for status in ("verified", "unknown", "contaminated"):
            for overlap in (-1, 0, 1, 2):
                for diagnostic in (False, True):
                    rows.append(((status, overlap, diagnostic),
                                 outcome(_eval_with_proof, eval_path, status, overlap, diagnostic)))
        # Same-dataset hash match (no proof): disjointness_status is
        # "contaminated" via the calibration_dataset_hash branch. This is the
        # only way evaluate_threshold reaches the contaminated comparison
        # without raising first.
        from textforensics.benchmark import dataset_sha256
        from textforensics.calibration import evaluate_threshold
        # allow_same_dataset=True is REQUIRED to reach the contaminated
        # comparison: without it the hash match raises before line 1905.
        for diagnostic in (False, True):
            rows.append((("hash-match", -1, diagnostic),
                         outcome(evaluate_threshold, eval_path, 0.5,
                                 calibration_dataset_hash=dataset_sha256(eval_path),
                                 diagnostic=diagnostic, allow_same_dataset=True)))
    return rows


def probe_cal_from_dict():
    from textforensics.calibration import CalibrationCurve
    rows = []
    params_for = {"platt": {"A": 1.0, "B": 0.0}, "temperature": {"T": 2.0},
                  "isotonic": {"x": [0.0, 0.5, 1.0], "y": [0.0, 0.5, 1.0]},
                  "beta": {"a": 2.0, "b": 2.0}, "identity": {}}
    for schema in ("textforensics.calibration-curve/v3", "textforensics.calibration-curve/v2", "wrong"):
        for method, params in params_for.items():
            d = dict(_platt_curve(method=method, parameters=params).to_dict(),
                     schema=schema, method=method)
            rows.append(((schema, method), outcome(CalibrationCurve.from_dict, d)))
    return rows


def probe_cal_is_legacy():
    from textforensics.calibration import CURVE_SCHEMA, LEGACY_CURVE_SCHEMA
    rows = []
    for schema in (CURVE_SCHEMA, LEGACY_CURVE_SCHEMA):
        for method in ("platt", "temperature"):
            params = {"T": 2.0} if method == "temperature" else {"A": 1.0, "B": 0.0}
            curve = _platt_curve(method=method, parameters=params, schema=schema)
            rows.append(((schema, method), ("ok", repr(curve.is_legacy))))
    return rows


def probe_cal_migrate():
    from textforensics.calibration import migrate_legacy_temperature_curve
    rows = []
    for method in ("temperature", "platt"):
        for schema in ("textforensics.calibration-curve/v2", "textforensics.calibration-curve/v3"):
            params = {"T": 2.0} if method == "temperature" else {"A": 1.0, "B": 0.0}
            curve = _platt_curve(method=method, parameters=params, schema=schema)
            rows.append(((method, schema), outcome(migrate_legacy_temperature_curve, curve)))
    return rows


def probe_cal_validate_no_contamination():
    import tempfile
    from pathlib import Path
    from textforensics.calibration import validate_no_contamination
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        a = Path(tmp) / "a.jsonl"
        b = Path(tmp) / "b.jsonl"
        _scored_jsonl(a)
        _scored_jsonl(b)
        rows.append((("identical",), outcome(validate_no_contamination, a, a)))
        rows.append((("same-content",), outcome(validate_no_contamination, a, b)))
        c = Path(tmp) / "c.jsonl"
        _scored_jsonl(c)
        import json as _json
        c.write_text(c.read_text() + _json.dumps({"label": "human", "text": "extra row"}) + "\n")
        rows.append((("extra-row",), outcome(validate_no_contamination, a, c)))
    return rows


# ---------------------------------------------------------------------------
# benchmark
# ---------------------------------------------------------------------------

def probe_bm_post_init():
    from textforensics.benchmark import DisjointnessProof
    rows = []
    for status in ("verified", "unknown", "contaminated", "bogus"):
        for overlap in (-1, 0, 1, 2):
            for group in (-1, 0, 1, 2):
                rows.append(((status, overlap, group),
                             outcome(DisjointnessProof, status=status, overlap_count=overlap,
                                     group_overlap_count=group, training_count=8,
                                     evaluation_count=8, training_hash=_hex64(1),
                                     evaluation_hash=_hex64(2), errors=())))
    return rows


def _proof_rows(path, rows):
    import json
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def probe_bm_prove_disjointness():
    import tempfile
    from pathlib import Path
    from textforensics.benchmark import prove_disjointness
    rows = []
    human = [{"label": "human", "text": f"human sentence {i}."} for i in range(3)]
    ai = [{"label": "ai", "text": f"ai sentence {i}."} for i in range(3)]
    with tempfile.TemporaryDirectory() as tmp:
        train = Path(tmp) / "train.jsonl"
        ev = Path(tmp) / "eval.jsonl"
        _proof_rows(train, human + ai)
        for ev_rows, label in (
                ([{"label": "human", "text": "different human sentence."},
                  {"label": "ai", "text": "different ai sentence."}], "disjoint"),
                ([{"label": "human", "text": "human sentence 0."},
                  {"label": "ai", "text": "different ai sentence."}], "overlap"),
                ([], "empty-eval"),
                ([{"label": "human", "text": "human sentence 0."}], "train-only-human")):
            _proof_rows(ev, ev_rows)
            rows.append(((label,), outcome(prove_disjointness, train, ev)))
        _proof_rows(train, [])
        _proof_rows(ev, human)
        rows.append((("empty-train",), outcome(prove_disjointness, train, ev)))
    return rows


def probe_bm_jsonl():
    import tempfile
    from pathlib import Path
    from textforensics.benchmark import (
        benchmark_with_calibration_jsonl, calibrate_threshold_jsonl,
        dataset_sha256, DisjointnessProof, prove_disjointness)
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        cal = Path(tmp) / "cal.jsonl"
        ev = Path(tmp) / "eval.jsonl"
        _proof_rows(cal, [{"label": "human", "text": "human sentence one."},
                          {"label": "ai", "text": "ai sentence one."}])
        _proof_rows(ev, [{"label": "human", "text": "human sentence two."},
                         {"label": "ai", "text": "ai sentence two."}])
        artifact = calibrate_threshold_jsonl(cal, target_fpr=0.0)
        # verified proof from the real disjointness check
        proof = prove_disjointness(cal, ev)
        rows.append((("verified",),
                     outcome(benchmark_with_calibration_jsonl, ev, artifact,
                             disjointness_proof=proof)))
        # unknown / contaminated proofs with matching hashes
        for status, overlap in (("unknown", -1), ("contaminated", 1)):
            proof = DisjointnessProof(status=status, overlap_count=overlap,
                                      training_count=2, evaluation_count=2,
                                      training_hash=dataset_sha256(cal),
                                      evaluation_hash=dataset_sha256(ev),
                                      errors=())
            rows.append(((status,),
                         outcome(benchmark_with_calibration_jsonl, ev, artifact,
                                 disjointness_proof=proof)))
        # no proof at all (diagnostic mode)
        rows.append((("none",),
                     outcome(benchmark_with_calibration_jsonl, ev, artifact, diagnostic=True)))
    return rows

# ---------------------------------------------------------------------------
# evidence
# ---------------------------------------------------------------------------

def _ev_record(*, evaluated_at="2026-11-01T00:00:00Z", status="active", n_human=120, n_ai=120,
               detector_version="1"):
    from textforensics.evidence import (
        BenchmarkProvenance, EvidenceRecord, MetricEstimate, RunProvenance,
        SliceConditions, ValidationSlice)
    slice_ = ValidationSlice(
        slice_id="s1",
        conditions=SliceConditions(languages=("en",), domains=("general",),
                                   editing_regimes=("human_only",)),
        n_human=n_human, n_ai=n_ai,
        metrics={"auroc": MetricEstimate(value=0.8, n=n_human + n_ai,
                                         ci_lower=0.7, ci_upper=0.9,
                                         method="bootstrap")},
        threshold=0.5)
    return EvidenceRecord(
        evidence_id="ev-1", detector_id="det", detector_version=detector_version,
        detector_family="fam", evaluated_at_utc=evaluated_at,
        benchmark=BenchmarkProvenance(name="raid", version="1.0",
                                      fingerprint_sha256=_hex64(1), split="test",
                                      license="MIT", artifact_path="data/raid.jsonl",
                                      artifact_sha256=_hex64(2),
                                      contamination_controls=("disjoint_sample_ids",)),
        slices=(slice_,),
        provenance=RunProvenance(git_sha="abc1234", command="textforensics benchmark",
                                 environment_sha256=_hex64(3),
                                 executed_at_utc=evaluated_at,
                                 run_artifact_path="runs/1.json",
                                 run_artifact_sha256=_hex64(4)),
        status=status)


def _ev_slice(*, n_human=120, n_ai=120):
    from textforensics.evidence import MetricEstimate, SliceConditions, ValidationSlice
    return ValidationSlice(
        slice_id="s1",
        conditions=SliceConditions(languages=("en",), domains=("general",),
                                   editing_regimes=("human_only",)),
        n_human=n_human, n_ai=n_ai,
        metrics={"auroc": MetricEstimate(value=0.8, n=n_human + n_ai,
                                         ci_lower=0.7, ci_upper=0.9,
                                         method="bootstrap")},
        threshold=0.5)


def probe_ev_record_candidate():
    from datetime import datetime, UTC
    from textforensics.evidence import _record_candidate_for_dimension, SliceMatch
    rows = []
    now = datetime(2026, 11, 11, tzinfo=UTC)
    for dimension in ("language", "text_length", "domain_genre", "editing_revision",
                      "generator_scope", "human_population",
                      "human_false_positive_evidence", "temporal_version_stability"):
        for match_vals in (("match", "match", "match", "match"),
                           ("unknown", "unknown", "unknown", "unknown"),
                           ("mismatch", "mismatch", "mismatch", "mismatch"),
                           ("match", "mismatch", "unknown", "match")):
            match = SliceMatch(language=match_vals[0], length=match_vals[1],
                               domain=match_vals[2], editing=match_vals[3], applicable=True)
            for age, nh, na in (("2026-11-01T00:00:00Z", 120, 120),   # fresh + adequate
                                ("2026-09-01T00:00:00Z", 120, 120),   # stale-ish
                                ("2026-01-01T00:00:00Z", 120, 120),   # unknown fresh
                                ("2026-11-01T00:00:00Z", 10, 10)):    # partial sample
                record = _ev_record(evaluated_at=age, n_human=nh, n_ai=na)
                slice_ = _ev_slice(n_human=nh, n_ai=na)
                try:
                    cand = _record_candidate_for_dimension(
                        record=record, slice_=slice_, match=match, now=now,
                        max_age_days=30, dimension=dimension, fpr_ceiling=0.05)
                    if cand is None:
                        rows.append(((dimension, match_vals, age, nh), ("ok", None)))
                    else:
                        rows.append(((dimension, match_vals, age, nh),
                                     ("ok", cand.state, cand.reason)))
                except Exception as exc:  # noqa: BLE001
                    rows.append(((dimension, match_vals, age, nh),
                                 ("raise", type(exc).__name__, str(exc))))
    return rows


def probe_ev_check_eligibility():
    from datetime import datetime, UTC
    from textforensics.evidence import (
        DisjointnessProof, InferenceIdentity, check_record_eligibility)
    rows = []
    now = datetime(2026, 11, 11, tzinfo=UTC)
    for status in ("active", "retracted"):
        for age in ("2026-11-01T00:00:00Z", "2026-01-01T00:00:00Z"):
            record = _ev_record(evaluated_at=age, status=status)
            for regime in ("human_only", "raw"):
                identity = InferenceIdentity(
                    detector_id="det", detector_version="1", provider=None,
                    model=None, config_hash=None, native_score_semantics=None,
                    calibration_id=None, regime=regime)
                for dj_status, dj_overlap in (("verified", 0), ("unknown", 0),
                                              ("contaminated", 1), (None, None)):
                    dj = None if dj_status is None else DisjointnessProof(
                        status=dj_status, overlap_count=dj_overlap,
                        training_count=1000, evaluation_count=400,
                        training_hash=_hex64(9),
                        evaluation_hash=record.benchmark.fingerprint_sha256)
                    try:
                        v = check_record_eligibility(
                            record, identity=identity, disjointness=dj,
                            now=now, max_age_days=30)
                        rows.append(((status, age, regime, dj_status),
                                     ("ok", v.eligible, list(v.reasons),
                                      list(v.unbound_identity_fields))))
                    except Exception as exc:  # noqa: BLE001
                        rows.append(((status, age, regime, dj_status),
                                     ("raise", type(exc).__name__, str(exc))))
    # Wildcard detector_version: the record_version == "*" check.
    identity = InferenceIdentity(
        detector_id="det", detector_version="1", provider=None,
        model=None, config_hash=None, native_score_semantics=None,
        calibration_id=None, regime="human_only")
    record = _ev_record(detector_version="*")
    dj = DisjointnessProof(status="verified", overlap_count=0,
                           training_count=1000, evaluation_count=400,
                           training_hash=_hex64(9),
                           evaluation_hash=record.benchmark.fingerprint_sha256)
    try:
        v = check_record_eligibility(record, identity=identity, disjointness=dj,
                                     now=now, max_age_days=30)
        rows.append((("active", "2026-11-01T00:00:00Z", "human_only", "verified-*"),
                     ("ok", v.eligible, list(v.reasons),
                      list(v.unbound_identity_fields))))
    except Exception as exc:  # noqa: BLE001
        rows.append((("active", "2026-11-01T00:00:00Z", "human_only", "verified-*"),
                     ("raise", type(exc).__name__, str(exc))))
    # Zero-count proofs: training_count / evaluation_count == 0.
    for tcount, ecount in ((0, 400), (1000, 0)):
        record = _ev_record()
        dj = DisjointnessProof(status="verified", overlap_count=0,
                               training_count=tcount, evaluation_count=ecount,
                               training_hash=_hex64(9),
                               evaluation_hash=record.benchmark.fingerprint_sha256)
        try:
            v = check_record_eligibility(record, identity=identity, disjointness=dj,
                                         now=now, max_age_days=30)
            rows.append((("active", "2026-11-01T00:00:00Z", "human_only",
                          f"verified-{tcount}-{ecount}"),
                         ("ok", v.eligible, list(v.reasons),
                          list(v.unbound_identity_fields))))
        except Exception as exc:  # noqa: BLE001
            rows.append((("active", "2026-11-01T00:00:00Z", "human_only",
                          f"verified-{tcount}-{ecount}"),
                         ("raise", type(exc).__name__, str(exc))))
    return rows


def probe_ev_assess_coverage():
    import tempfile
    from pathlib import Path
    A = _v3()
    from textforensics.evidence import EvidenceRegistry
    rows = []
    import dataclasses
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        A._write_artifacts(root)
        for status in ("active", "retracted"):
            record = A._v2_record(status=status)
            registry = EvidenceRegistry([record])
            cov = A._v2_coverage(registry, **A._eligible_inputs(registry, root))
            rows.append(((status, "base"), list(cov.record_ids),
                         [(k, v.state) for k, v in sorted(cov.dimensions.items())]))
        # Out-of-scope metadata: language outside supported_languages and
        # word_count below min_words — exercises the metadata downgrade
        # branches (state == "out_of_scope").
        from textforensics.evidence import assess_detector_coverage
        record = A._v2_record(status="active")
        registry = EvidenceRegistry([record])
        base_inputs = A._eligible_inputs(registry, root)
        for tag, cond in (("lang-fr", dataclasses.replace(A._v2_conditions(), language="fr")),
                          ("words-10", A._v2_conditions(word_count=10))):
            # _v2_coverage hardcodes conditions, so call the function directly.
            cov = assess_detector_coverage(
                detector_id="a", detector_version="1", detector_family="fam1",
                supported_languages=("en",), min_words=80, max_words=1000,
                conditions=cond, registry=registry, now=A.NOW, **base_inputs)
            rows.append(((("active", tag), list(cov.record_ids),
                         [(k, v.state) for k, v in sorted(cov.dimensions.items())])))
    return rows


# ---------------------------------------------------------------------------
# validation (v3) — reuse the W2-A test module's builders
# ---------------------------------------------------------------------------

def _v3():
    import sys
    import test_audit_w2_worker_a as A
    return A


def probe_val_support_blockers():
    from textforensics.validation import _support_blockers
    A = _v3()
    rows = []
    rec = A.ValidationRecord.from_dict(A._v3_record_dict())
    for dimension in ("language", "human_false_positive_evidence", "temporal_version_stability"):
        for lcr in (None, 0, 1, 2, 3):
            kw = {} if lcr is None else {"longitudinal_clean_runs": lcr}
            rows.append(((dimension, lcr),
                         outcome(_support_blockers, rec, dimension=dimension,
                                 detector_version=A.V3_VERSION, now=A.NOW,
                                 fpr_ceiling=0.05, **kw)))
    return rows


def probe_val_derive_dimension():
    from textforensics.validation import _derive_evidence_dimension
    A = _v3()
    rows = []
    statuses = ("supported", "partial", "unknown", "stale", "contested")
    base_kw = dict(detector_id=A.V3_DETECTOR, detector_version=A.V3_VERSION,
                   now=A.NOW, fpr_ceiling=0.05, unobservable=False,
                   unobservable_reason="",
                   out_of_scope_reason="no matching record for language",
                   out_of_scope_observed={})
    for status in statuses:
        rec = A.ValidationRecord.from_dict(A._v3_record_dict(status=status))
        rows.append(((status, False),
                     outcome(_derive_evidence_dimension, "language", matching=(rec,),
                             detector_records=(rec,), **base_kw)))
    # mixed matching sets: contested among others
    recs = tuple(A.ValidationRecord.from_dict(A._v3_record_dict(status=s, record_id=f"evr-20261106-synth{s}-builtin-heuristic"))
                 for s in ("supported", "contested", "unknown"))
    rows.append((("mixed", False),
                 outcome(_derive_evidence_dimension, "language", matching=recs,
                         detector_records=recs, **base_kw)))
    # unobservable dimension with no matching records
    rows.append((("empty-unobs", True),
                 outcome(_derive_evidence_dimension, "language", matching=(),
                         detector_records=(), **{**base_kw, "unobservable": True,
                                                "unobservable_reason": "no slice"})))
    rows.append((("empty-oos", False),
                 outcome(_derive_evidence_dimension, "language", matching=(),
                         detector_records=recs, **base_kw)))
    return rows


def probe_val_derive_trust_map():
    A = _v3()
    rows = []
    for n_records, statuses in ((0, ()), (1, ("supported",)),
                                (2, ("supported", "supported")),
                                (3, ("supported", "partial", "unknown"))):
        recs = [A._v3_record_dict(status=s, record_id=f"evr-20261106-synth{i}-builtin-heuristic")
                for i, s in enumerate(statuses)]
        registry = A._v3_registry(*recs)
        cond = A._v3_conditions()
        tm = A._v3_derive(cond, registry)
        rows.append(((n_records, statuses), tm.overall,
                     [(d.dimension, d.state) for d in tm.dimensions]))
    return rows

# ---------------------------------------------------------------------------
# adversarial / semantic
# ---------------------------------------------------------------------------

def _adv_text(n_words=40, marker=""):
    words = ("The quick brown fox jumps over the lazy dog near the river bank "
             "while the old farmer watches the morning sun rise over the hills. ").split()
    body = " ".join((words * ((n_words // len(words)) + 1))[:n_words])
    return (marker + " " + body).strip() if marker else body


def probe_adv_analyze():
    from textforensics.adversarial import AdversarialDetector
    det = AdversarialDetector()
    rows = []
    for text, language in (
            (_adv_text(40), None),
            (_adv_text(8), None),                    # below MIN_WORDS (10)
            (_adv_text(120), None),
            ("As an AI language model, I cannot help with that request. " * 3, None),
            ("Delve into the multifaceted tapestry of human experience. " * 4, None),
            (_adv_text(40), "fr"),                  # non-English declaration
            ("", None)):
        try:
            rep = det.analyze(text, language=language)
            rows.append(((len(text.split()), language), rep.overall_risk,
                         rep.support_status, len(rep.findings)))
        except Exception as exc:  # noqa: BLE001
            rows.append(((len(text.split()), language),
                         ("raise", type(exc).__name__, str(exc))))
    return rows


def probe_adv_assess_risk():
    from textforensics.adversarial import AdversarialDetector, AdversarialFinding
    det = AdversarialDetector()
    rows = []
    def finding(severity, confidence, pattern="p1"):
        return AdversarialFinding(pattern_id=pattern, segment="full_text",
                                  evidence=0.5, severity=severity,
                                  confidence=confidence, location=(0, 10),
                                  description="synthetic")
    for findings in ([], [finding("low", 0.1)], [finding("medium", 0.5)],
                     [finding("high", 0.7)], [finding("critical", 0.9)],
                     [finding("low", 0.1), finding("high", 0.7)],
                     [finding("critical", 0.9), finding("critical", 0.9)],
                     [finding("medium", 0.5), finding("medium", 0.5),
                      finding("medium", 0.5)]):
        rows.append(((tuple((f.severity, f.confidence) for f in findings),),
                     outcome(det._assess_risk, findings)))
    return rows


def probe_sem_analyze():
    from textforensics.semantic import SemanticConsistencyChecker
    checker = SemanticConsistencyChecker()
    rows = []
    three = ("The city council approved the new budget on Tuesday. "
             "Local residents welcomed the decision with cautious optimism. "
             "The mayor said the funds would support road repairs and schools.")
    two = ("The city council approved the new budget on Tuesday. "
           "Local residents welcomed the decision with cautious optimism.")
    long_mixed = (three + " " + "Quantum computers exploit superposition to solve "
                  "certain problems exponentially faster than classical machines. " * 3)
    for text, language in ((three, None), (two, None), (long_mixed, None),
                           (three, "fr"), ("", None),
                           (" ".join(["word"] * 400), None)):
        try:
            rep = checker.analyze(text, language=language)
            rows.append(((len(text.split()), language), rep.risk_level,
                         rep.support_status, len(rep.findings)))
        except Exception as exc:  # noqa: BLE001
            rows.append(((len(text.split()), language),
                         ("raise", type(exc).__name__, str(exc))))
    return rows


def probe_sem_assess_risk():
    from textforensics.semantic import SemanticConsistencyChecker
    checker = SemanticConsistencyChecker()
    rows = []
    def finding(severity, confidence):
        return {"finding_id": "f1", "category": "style", "description": "synthetic",
                "evidence": 0.5, "severity": severity, "confidence": confidence,
                "segment_indices": (0, 1), "details": {}}
    for findings in ([], [finding("low", 0.1)], [finding("medium", 0.5)],
                     [finding("high", 0.7)], [finding("critical", 0.9)],
                     [finding("low", 0.1), finding("high", 0.7)],
                     [finding("critical", 0.9), finding("critical", 0.9)]):
        rows.append(((tuple((f["severity"], f["confidence"]) for f in findings),),
                     outcome(checker._assess_risk, findings)))
    return rows


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------

def probe_explain_explain():
    from textforensics.explain import CounterfactualExplainer
    rows = []
    def score_fn(text):
        # Additive: machine-generated sentence pushes AI (+0.4),
        # handwritten sentence pushes human (-0.3), neutral adds nothing.
        score = 0.5
        if "machine generated" in text:
            score += 0.4
        if "handwritten note" in text:
            score -= 0.3
        return score
    expl = CounterfactualExplainer(score_fn, detector_id="d", detector_version="1")
    texts = [
        "This is machine generated content. This is a handwritten note from a friend. The weather is fine today.",
        "The weather is fine today. This is machine generated content. This is a handwritten note from a friend.",
        "A single sentence only.",
    ]
    for text in texts:
        try:
            rep = expl.explain(text)
            rows.append(((len(text.split(".")),),
                         [(s.direction, round(s.delta, 6)) for s in rep.segment_attribution],
                         rep.completeness.selected, rep.completeness.attempted))
        except Exception as exc:  # noqa: BLE001
            rows.append(((len(text.split(".")),),
                         ("raise", type(exc).__name__, str(exc))))
    # abstaining score_fn (timestamp-free fields: created_at varies per call)
    expl2 = CounterfactualExplainer(lambda t: None, detector_id="d", detector_version="1")
    try:
        rep = expl2.explain(texts[0])
        rows.append((("abstain",), ("ok", rep.n_segments, rep.n_scored,
                                     rep.original_score, rep.verdict,
                                     rep.completeness.selected if rep.completeness else None,
                                     rep.completeness.attempted if rep.completeness else None)))
    except Exception as exc:  # noqa: BLE001
        rows.append((("abstain",), ("raise", type(exc).__name__, str(exc))))
    return rows


# ---------------------------------------------------------------------------
# probe_runs
# ---------------------------------------------------------------------------

def _pr_slice_inputs(n=10, flipped=0, direction="higher_means_ai", prev_verdicts=None):
    import sys
    import test_w2_worker_d as D
    from datetime import datetime, UTC
    prev, curr, labels, slices = [], [], {}, {}
    for i in range(n):
        item_id = f"h-{i:03d}"
        is_flipped = i < flipped
        prev_verdict = (prev_verdicts or {}).get(item_id, "human_like")
        prev.append(D._rec(item_id, score=0.3, verdict=prev_verdict))
        curr.append(D._rec(item_id, score=0.9 if is_flipped else 0.3,
                           verdict="ai_like" if is_flipped else "human_like",
                           direction=direction))
        labels[item_id] = 0
    current = {r["sample_id"]: r for r in curr}
    baseline = {r["sample_id"]: r for r in prev}
    return [r["sample_id"] for r in curr], current, baseline, labels


def probe_pr_slice_metrics():
    from datetime import datetime, UTC
    import textforensics.probe_metrics as primitives
    from textforensics.probe_runs import _slice_metrics
    rows = []
    now = datetime(2026, 11, 11, tzinfo=UTC)
    for n, flipped, direction, prev_verdicts in (
            (0, 0, "higher_means_ai", None),
            (10, 0, "higher_means_ai", None),
            (10, 2, "higher_means_ai", None),
            (10, 10, "higher_means_ai", None),
            (10, 2, "lower_means_ai", None),
            (300, 3, "higher_means_ai", None),
            # Previous-run verdicts that are NOT human_like: the flip loop's
            # `_verdict(previous[item]) == "human_like"` comparison.
            (10, 2, "higher_means_ai", {"h-000": "ai_like"}),
            (10, 2, "higher_means_ai", {"h-000": "abstain"}),
            (10, 2, "higher_means_ai", {"h-000": "ai_like", "h-001": "abstain"})):
        item_ids, current, baseline, labels = _pr_slice_inputs(
            n, flipped, direction, prev_verdicts)
        key = (n, flipped, direction, tuple(sorted((prev_verdicts or {}).items())))
        human_scores = [0.3] * n
        human_labels = [0] * n
        # previous must be a real dict: the flip loop (`item in previous`)
        # is only reached when a previous run exists. baseline and previous
        # are the same records here (previous run == baseline run).
        out = outcome(_slice_metrics, item_ids=item_ids, current=current,
                      baseline=baseline, previous=baseline, labels=labels,
                      primitives=primitives, is_human_slice=True,
                      is_attacked_slice=False, human_scores_all=human_scores,
                      human_labels_all=human_labels,
                      calibration_created_at=None, now=now, score_direction=direction)
        if out[0] == "ok":
            import ast as _ast
            m = _ast.literal_eval(out[1])
            rows.append((key,
                         {k: m[k] for k in ("n", "verdict_counts", "fpr", "tpr", "ece",
                                            "flips")
                          if k in m}))
        else:
            rows.append((key, out))
    return rows


def probe_pr_compute_run_metrics():
    import sys
    import test_w2_worker_d as D
    from datetime import datetime, UTC
    from textforensics.probe_runs import compute_run_metrics
    rows = []
    now = datetime(2026, 11, 11, tzinfo=UTC)
    for n, flipped in ((0, 0), (10, 0), (10, 2), (10, 10)):
        prev, curr, labels, slices = D._human_slice(n, flipped=flipped)
        out = outcome(compute_run_metrics, current_records=curr,
                      previous_records=prev, baseline_records=prev,
                      labels=labels, slices=slices, detector_id="d",
                      calibration_created_at=None, now=now)
        if out[0] == "ok":
            import ast as _ast
            m = _ast.literal_eval(out[1])
            rows.append(((n, flipped), sorted(m.keys()),
                         m.get("overall", {}).get("verdict_counts")
                         if isinstance(m.get("overall"), dict) else None))
        else:
            rows.append(((n, flipped), out))
    return rows


# ---------------------------------------------------------------------------
# _standalone_verify
# ---------------------------------------------------------------------------

def probe_sa_verify_bundle():
    import sys
    import test_standalone_verify as S
    from textforensics._standalone_verify import verify_bundle_bytes
    rows = []
    variants = []
    variants.append(("sorted", S.build_bundle()[0]))
    variants.append(("unsorted", S.build_bundle()[0]))
    # pack with unsorted names
    manifest = S.make_manifest({"b.txt": b"bee", "a.txt": b"aye"})
    variants.append(("names-unsorted", S.pack_bundle(
        {"b.txt": b"bee", "a.txt": b"aye"}, sort=False)))
    variants.append(("names-sorted", S.pack_bundle(
        {"b.txt": b"bee", "a.txt": b"aye"}, sort=True)))
    # compression variants
    variants.append(("deflate", S.pack_bundle({"a.txt": b"aye" * 100}, deflate={"a.txt"})))
    variants.append(("stored", S.pack_bundle({"a.txt": b"aye" * 100}, deflate=None)))
    # signature states: absent (default), failed (bad token), verified (real token via build_bundle)
    variants.append(("sig-bad-token", S.build_bundle(token_der=b"\x00\x01\x02")[0]))
    for name, data in variants:
        out = outcome(verify_bundle_bytes, data)
        if out[0] == "ok":
            import ast as _ast
            rep = _ast.literal_eval(out[1])
            rows.append(((name,),
                         rep["signature"],
                         [(c["id"], c["status"]) for c in rep["checks"]],
                         list(rep["gaps"])))
        else:
            rows.append(((name,), out))
    return rows


# ---------------------------------------------------------------------------
# semantic._compute_consistency_score (new probe, W2-F kill tests)
# ---------------------------------------------------------------------------
def _sem_segment(ttr=0.5, entropy=1.0, hapax=0.2, wc=10, index=0):
    from textforensics.semantic import SemanticSegment
    return SemanticSegment(index=index, text="x", word_count=wc, sentence_count=1,
                           avg_word_length=4.0, type_token_ratio=ttr, hapax_ratio=hapax,
                           pos_distribution={}, semantic_density=1.0, entropy=entropy)


def probe_sem_consistency_score():
    from textforensics.semantic import SemanticConsistencyChecker
    checker = SemanticConsistencyChecker()
    # value triples chosen so statistics.stdev lands exactly on the scale
    # boundaries: [0, s, 2s] -> stdev == s (ttr/hapax scale 0.05, entropy 0.3)
    rows = []
    cases = [
        ("empty", []),
        ("one", [_sem_segment()]),
        ("two", [_sem_segment(), _sem_segment()]),
        ("uniform3", [_sem_segment(index=i) for i in range(3)]),
        ("ttr-boundary", [_sem_segment(ttr=v) for v in (0.0, 0.05, 0.10)]),
        ("ttr-double", [_sem_segment(ttr=v) for v in (0.0, 0.10, 0.20)]),
        ("ttr-half", [_sem_segment(ttr=v) for v in (0.0, 0.025, 0.05)]),
        ("entropy-boundary", [_sem_segment(entropy=v) for v in (0.0, 0.30, 0.60)]),
        ("entropy-half", [_sem_segment(entropy=v) for v in (0.0, 0.15, 0.30)]),
        ("hapax-boundary", [_sem_segment(hapax=v) for v in (0.0, 0.05, 0.10)]),
        ("hapax-half", [_sem_segment(hapax=v) for v in (0.0, 0.025, 0.05)]),
        ("wc-boundary", [_sem_segment(wc=v) for v in (10, 20, 30)]),
        ("wc-half", [_sem_segment(wc=v) for v in (10, 15, 20)]),
        ("wc-double", [_sem_segment(wc=v) for v in (0, 20, 40)]),
        ("all-spread", [_sem_segment(ttr=v, entropy=2 * v, hapax=v, wc=int(100 * v))
                        for v in (0.0, 0.05, 0.10)]),
        ("uniform4", [_sem_segment(index=i) for i in range(4)]),
        ("ttr-boundary4", [_sem_segment(ttr=v) for v in (0.0, 0.05, 0.10, 0.15)]),
    ]
    for name, segs in cases:
        rows.append((name, outcome(checker._compute_consistency_score, segs)))
    return rows


# ---------------------------------------------------------------------------
# semantic MIN_SEGMENTS_FOR_ASSESSMENT floor (module-level constant)
# ---------------------------------------------------------------------------
def probe_sem_min_segments():
    from textforensics.semantic import SemanticConsistencyChecker
    checker = SemanticConsistencyChecker(segment_word_target=20)
    # 10-word sentences; 2 sentences per segment at target 20
    sent = "The quick brown fox jumps over the lazy dog today."
    rows = []
    for n_sent in (2, 4, 6, 8):
        text = " ".join([sent] * n_sent)
        try:
            rep = checker.analyze(text)
            rows.append((n_sent, rep.n_segments, rep.support_status,
                         rep.overall_consistency_score is None, rep.risk_level))
        except Exception as exc:  # noqa: BLE001
            rows.append((n_sent, ("raise", type(exc).__name__, str(exc))))
    return rows


# ---------------------------------------------------------------------------
# schema trust-map validators (new probes, W2-F kill tests)
# ---------------------------------------------------------------------------
def _schema_map(version="v3", dims=None, **overrides):
    from textforensics.trust import TRUST_DIMENSIONS
    if dims is None:
        dims = [{"dimension": d, "state": "supported", "reason": "ok"}
                for d in sorted(TRUST_DIMENSIONS)]
    m = {"schema": f"textforensics.trust-map/{version}",
         "dimensions": dims,
         "input_conditions": {"language": "en"},
         "evidence_registry": {},
         "generated_at_utc": "2026-01-01T00:00:00Z",
         "coverage": {"supported": len(dims), "partial": 0, "unknown": 0,
                      "out_of_scope": 0}}
    if version == "v3":
        m["coverage"]["stale"] = 0
    m.update(overrides)
    return m


def _schema_cov(m, **changes):
    import copy
    m = copy.deepcopy(m)
    m["coverage"].update(changes)
    return m


def probe_schema_dimensions():
    from textforensics.schema import validate_trust_map_dimensions
    from textforensics.trust import TRUST_DIMENSIONS
    import copy
    dims = sorted(TRUST_DIMENSIONS)
    base = _schema_map("v3")
    base2 = _schema_map("v2")
    cases = [
        ("valid-v3", base),
        ("valid-v2", base2),
        ("list-map", []),
        ("v1", _schema_map("v1")),
        ("v4", {"schema": "textforensics.trust-map/v4", "dimensions": []}),
        ("no-schema", {"dimensions": []}),
        ("dims-dict", _schema_map("v3", dims={"a": 1})),
        ("dim-string", _schema_map("v3", dims=["language"])),
        ("dim-no-name", _schema_map("v3", dims=[{"state": "supported"}])),
        ("dim-empty-name", _schema_map("v3", dims=[{"dimension": "", "state": "supported"}])),
        ("state-bogus", _schema_map("v3", dims=[{"dimension": dims[0], "state": "bogus"}] + [
            {"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]])),
        ("v2-stale-state", _schema_map("v2", dims=[{"dimension": dims[0], "state": "stale"}] + [
            {"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]])),
        ("v3-stale-state-ok", _schema_map("v3", dims=[{"dimension": dims[0], "state": "stale"}] + [
            {"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]])),
        ("dup2", _schema_map("v3", dims=[{"dimension": dims[0], "state": "supported"}] * 2 + [
            {"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]])),
        ("dup3", _schema_map("v3", dims=[{"dimension": dims[0], "state": "supported"}] * 3 + [
            {"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]])),
        ("unknown-dim", _schema_map("v3", dims=[{"dimension": "nope", "state": "supported"}] + [
            {"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]])),
        ("missing-dim", _schema_map("v3", dims=[
            {"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]])),
        ("two-invalid", _schema_map("v3", dims=[{"dimension": dims[0], "state": "bogus"},
                                                 {"dimension": dims[1], "state": "bogus"}] + [
            {"dimension": d, "state": "supported", "reason": "ok"} for d in dims[2:]])),
        ("empty-dims", _schema_map("v3", dims=[])),
    ]
    return [(name, outcome(validate_trust_map_dimensions, m)) for name, m in cases]


def probe_schema_completeness():
    from textforensics.schema import validate_trust_map_completeness
    from textforensics.trust import TRUST_DIMENSIONS
    import copy
    dims = sorted(TRUST_DIMENSIONS)
    base = _schema_map("v3")
    cases = [
        ("valid-v3", base),
        ("valid-v2", _schema_map("v2")),
        ("list-map", []),
        ("v1", _schema_map("v1")),
        ("reason-123", _schema_map("v3", dims=[{"dimension": dims[0], "state": "supported", "reason": 123}] + [
            {"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]])),
        ("reason-empty", _schema_map("v3", dims=[{"dimension": dims[0], "state": "supported", "reason": ""}] + [
            {"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]])),
        ("reason-missing", _schema_map("v3", dims=[{"dimension": dims[0], "state": "supported"}] + [
            {"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]])),
        ("two-bad-reasons", _schema_map("v3", dims=[{"dimension": dims[0], "state": "supported", "reason": ""},
                                                     {"dimension": dims[1], "state": "supported", "reason": 1}] + [
            {"dimension": d, "state": "supported", "reason": "ok"} for d in dims[2:]])),
        ("no-input-conditions", {k: v for k, v in base.items() if k != "input_conditions"}),
        ("input-conditions-list", _schema_map("v3", input_conditions=[])),
        ("no-evidence-registry", {k: v for k, v in base.items() if k != "evidence_registry"}),
        ("generated-none", _schema_map("v3", generated_at_utc=None)),
        ("generated-empty", _schema_map("v3", generated_at_utc="")),
        ("coverage-list", _schema_map("v3", coverage=[])),
        ("coverage-extra", _schema_cov(base, bogus=1)),
        ("coverage-missing", {k: v for k, v in base.items() if k != "coverage"}),
        ("coverage-missing-key", _schema_map("v3", coverage={"supported": len(dims), "partial": 0, "unknown": 0, "out_of_scope": 0})),
        ("coverage-bool", _schema_cov(base, supported=True)),
        ("coverage-str", _schema_cov(base, supported="x")),
        ("coverage-neg", _schema_cov(base, supported=-1)),
        ("coverage-zero", _schema_cov(base, supported=0)),
        ("coverage-wrong-count", _schema_cov(base, supported=len(dims) - 1, partial=1)),
        ("coverage-300", _schema_map("v3", dims=[{"dimension": dims[0], "state": "supported", "reason": "ok"}] * 300,
                                     coverage={"supported": 300, "partial": 0, "unknown": 0, "out_of_scope": 0, "stale": 0})),
        ("coverage-300-off", _schema_map("v3", dims=[{"dimension": dims[0], "state": "supported", "reason": "ok"}] * 300,
                                         coverage={"supported": 299, "partial": 0, "unknown": 0, "out_of_scope": 0, "stale": 0})),
    ]
    return [(name, outcome(validate_trust_map_completeness, m)) for name, m in cases]


def probe_schema_load():
    from textforensics.schema import load_schema
    rows = []
    rows.append(("maxsize", outcome(lambda: load_schema.cache_info().maxsize)))
    rows.append(("bogus-name", outcome(load_schema, "no-such-schema")))
    rows.append(("valid", outcome(lambda: sorted(load_schema("case-file").keys())[:3])))
    return rows


# ---------------------------------------------------------------------------
# verify.verify_benchmark (new probe, W2-F kill tests)
# ---------------------------------------------------------------------------
def _bm_result(tp=2, fn=1, fp=1, tn=1, evaluated=None, rates=None, fp_sha=None):
    if evaluated is None:
        try:
            evaluated = tp + fp + tn + fn
        except TypeError:
            evaluated = 5
    try:
        total = tp + fp + tn + fn
    except TypeError:
        total = 5
    def rate(num, den):
        try:
            return round(num / den, 4) if den else 0.0
        except TypeError:
            return 0.5
    try:
        acc, tpr = rate(tp + tn, total), rate(tp, tp + fn)
        fpr, spec = rate(fp, fp + tn), rate(tn, tn + fp)
        fnr, prec = rate(fn, fn + tp), rate(tp, tp + fp)
    except TypeError:
        acc = tpr = fpr = spec = fnr = prec = 0.5
    r = {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "evaluated": evaluated,
         "accuracy": acc, "true_positive_rate": tpr, "false_positive_rate": fpr,
         "specificity": spec, "false_negative_rate": fnr, "precision": prec,
         "dataset_sha256": fp_sha if fp_sha is not None else "a" * 64}
    if rates:
        r.update(rates)
    return r


def probe_verify_benchmark():
    from textforensics.verify import verify_benchmark
    cases = [
        ("valid-2211", _bm_result()),
        ("valid-300", _bm_result(tp=300, fn=0, fp=0, tn=0, evaluated=300)),
        ("thirds", _bm_result(tp=1, fn=2, fp=1, tn=2)),
        ("sixths", _bm_result(tp=1, fn=5, fp=1, tn=5)),
        ("sevenths", _bm_result(tp=1, fn=6, fp=2, tn=5)),
        ("all-zero", _bm_result(tp=0, fn=0, fp=0, tn=0, evaluated=0)),
        ("tp-fn-21", _bm_result(tp=2, fn=1, fp=0, tn=0)),
        ("tp-fp-11", _bm_result(tp=1, fn=0, fp=1, tn=0)),
        ("neg-count", _bm_result(tp=-1)),
        ("bool-count", _bm_result(tp=True)),
        ("str-count", _bm_result(tp="2")),
        ("frac-count", _bm_result(tp=1.5)),
        ("rate-neg", _bm_result(rates={"accuracy": -0.5})),
        ("rate-over", _bm_result(rates={"accuracy": 1.5})),
        ("rate-nan", _bm_result(rates={"accuracy": float("nan")})),
        ("rate-missing", {k: v for k, v in _bm_result().items() if k != "accuracy"}),
        ("total-mismatch", _bm_result(evaluated=4)),
        ("total-mismatch-big", _bm_result(tp=300, fn=0, fp=0, tn=0, evaluated=299)),
        ("diff-exact-001", _bm_result(tp=0, fn=0, fp=0, tn=0, evaluated=0,
                                      rates={"true_positive_rate": 0.001})),
        ("diff-01", _bm_result(tp=0, fn=0, fp=0, tn=0, evaluated=0,
                               rates={"true_positive_rate": 0.1})),
        ("diff-05", _bm_result(tp=0, fn=0, fp=0, tn=0, evaluated=0,
                               rates={"true_positive_rate": 0.5})),
        ("rate-mismatch", _bm_result(rates={"accuracy": 0.9})),
        ("not-dict", "not a dict"),
        ("hash-63", _bm_result(fp_sha="a" * 63)),
        ("hash-65", _bm_result(fp_sha="a" * 65)),
        ("hash-upper", _bm_result(fp_sha="A" * 64)),
        ("hash-nonhex", _bm_result(fp_sha="g" * 64)),
        ("hash-missing", {k: v for k, v in _bm_result().items() if k != "dataset_sha256"}),
    ]
    return [(name, outcome(verify_benchmark, m)) for name, m in cases]


# ---------------------------------------------------------------------------
# verify.verify_case_file (new probe, W2-F kill tests)
# ---------------------------------------------------------------------------
def _vc_case(text, **tamper):
    from textforensics.report import build_forensic_bundle
    from textforensics.casefile import seal_case_file
    import copy
    case = seal_case_file(build_forensic_bundle(text).to_dict())
    for path, value in tamper.items():
        obj = case
        keys = path.split(".")
        for k in keys[:-1]:
            obj = obj[k]
        obj[keys[-1]] = value
    return case


def probe_verify_case_file():
    from textforensics.verify import verify_case_file
    import copy
    ascii_text = "The city council approved the budget on Tuesday. " * 20
    nonascii_text = "Café naïve façade — the résumé was über. " * 20
    base = _vc_case(ascii_text)
    base_na = _vc_case(nonascii_text)
    tm = base["forensic_bundle"]["trust_map"]
    derived = tm["overall"]
    cases = [
        ("valid", base),
        ("valid-nonascii", base_na),
        ("overall-partial", _vc_case(ascii_text, **{"forensic_bundle.trust_map.overall": "partial"})),
        ("overall-unknown", _vc_case(ascii_text, **{"forensic_bundle.trust_map.overall": "unknown"})),
        ("overall-supported", _vc_case(ascii_text, **{"forensic_bundle.trust_map.overall": "supported"})),
        ("overall-same", _vc_case(ascii_text, **{"forensic_bundle.trust_map.overall": derived})),
        ("raw-0", _vc_case(ascii_text, **{"raw_text_included": 0})),
        ("raw-1", _vc_case(ascii_text, **{"raw_text_included": 1})),
        ("raw-true", _vc_case(ascii_text, **{"raw_text_included": True})),
        ("raw-none", _vc_case(ascii_text, **{"raw_text_included": None})),
        ("input-raw-0", _vc_case(ascii_text, **{"forensic_bundle.input.raw_text_included": 0})),
        ("input-raw-true", _vc_case(ascii_text, **{"forensic_bundle.input.raw_text_included": True})),
        ("not-dict", "x"),
        ("list-payload", []),
        ("seal-63", _vc_case(ascii_text, **{"case_sha256": "a" * 63})),
        ("seal-65", _vc_case(ascii_text, **{"case_sha256": "a" * 65})),
        ("seal-upper", _vc_case(ascii_text, **{"case_sha256": "A" * 64})),
        ("content-63", _vc_case(ascii_text, **{"forensic_bundle.content_sha256": "a" * 63})),
        ("content-65", _vc_case(ascii_text, **{"forensic_bundle.content_sha256": "a" * 65})),
        ("content-upper", _vc_case(ascii_text, **{"forensic_bundle.content_sha256": "A" * 64})),
        ("tm-v2", _vc_case(ascii_text, **{"forensic_bundle.trust_map.schema": "textforensics.trust-map/v2"})),
        ("tm-v1", _vc_case(ascii_text, **{"forensic_bundle.trust_map.schema": "textforensics.trust-map/v1"})),
        ("tm-bad-schema", _vc_case(ascii_text, **{"forensic_bundle.trust_map.schema": "textforensics.trust-map/v9"})),
        ("tm-dims-empty", _vc_case(ascii_text, **{"forensic_bundle.trust_map.dimensions": []})),
        ("tm-dim-string", _vc_case(ascii_text, **{"forensic_bundle.trust_map.dimensions": ["language"]})),
        ("tm-no-trust-map", {k: v for k, v in copy.deepcopy(base)["forensic_bundle"].items() if k != "trust_map"} and _vc_case(ascii_text)),
        ("bundle-not-dict", _vc_case(ascii_text, **{"forensic_bundle": "x"})),
        ("no-bundle", {k: v for k, v in base.items() if k != "forensic_bundle"}),
        ("bad-case-schema", _vc_case(ascii_text, **{"schema": "textforensics.case-file/v9"})),
        ("bad-bundle-schema", _vc_case(ascii_text, **{"forensic_bundle.schema": "textforensics.forensic-bundle/v9"})),
        ("dr-not-list", _vc_case(ascii_text, **{"forensic_bundle.detector_results": "x"})),
        ("dr-wrong-schema", _vc_case(ascii_text, **{"forensic_bundle.detector_results": [{"schema": "wrong", "detector_id": "d1", "score": 0.5, "verdict": "ai_like"}]})),
        ("dr-score-str", _vc_case(ascii_text, **{"forensic_bundle.detector_results": [{"schema": "textforensics.detector-result/v2", "detector_id": "d1", "score": "0.5", "verdict": "ai_like"}]})),
        ("dr-score-nan", _vc_case(ascii_text, **{"forensic_bundle.detector_results": [{"schema": "textforensics.detector-result/v2", "detector_id": "d1", "score": float("nan"), "verdict": "ai_like"}]})),
        ("dr-verdict-bad", _vc_case(ascii_text, **{"forensic_bundle.detector_results": [{"schema": "textforensics.detector-result/v2", "detector_id": "d1", "score": 0.5, "verdict": "maybe"}]})),
    ]
    # v2/v3-divergent map: 1 partial + 8 unknown -> v3 derives "mixed",
    # v2 derives "insufficient" (unknown >= 4 rule). Hand-sealed minimal case.
    import hashlib, json, math
    from textforensics.trust import TRUST_DIMENSIONS
    dims9 = sorted(TRUST_DIMENSIONS)
    v3dims = [{"dimension": dims9[0], "state": "partial", "reason": "ok"}] + [
        {"dimension": d, "state": "unknown", "reason": "ok"} for d in dims9[1:]]
    tm3 = _schema_map("v3", dims=v3dims)
    tm3["overall"] = "mixed"
    tm3["coverage"] = {"supported": 0, "partial": 1, "unknown": 9,
                       "out_of_scope": 0, "stale": 0}
    minimal = {"schema": "textforensics.case-file/v1", "raw_text_included": False,
               "forensic_bundle": {"schema": "textforensics.forensic-bundle/v2",
                                   "content_sha256": "a" * 64, "trust_map": tm3,
                                   "input": {"raw_text_included": False},
                                   "detector_results": []},
               "case_sha256": "x" * 64}
    def _sanitize(obj):
        if isinstance(obj, float):
            if not math.isfinite(obj):
                return "Infinity" if obj > 0 else "-Infinity" if obj < 0 else "NaN"
            return obj
        if isinstance(obj, dict):
            return {k: _sanitize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_sanitize(v) for v in obj]
        return obj
    stripped = _sanitize(copy.deepcopy(minimal))
    stripped.pop("case_sha256", None)
    stripped.pop("created_at_utc", None)
    minimal["case_sha256"] = hashlib.sha256(json.dumps(
        stripped, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False).encode("utf-8")).hexdigest()
    cases.append(("v3-partial-unknown", minimal))
    # fix the tm-no-trust-map case (built above as a placeholder)
    cases = [(n, c) for n, c in cases if n != "tm-no-trust-map"]
    no_tm = copy.deepcopy(base)
    del no_tm["forensic_bundle"]["trust_map"]
    cases.append(("tm-no-trust-map", no_tm))
    raw = copy.deepcopy(base)
    raw["raw_text"] = "forbidden"
    cases.append(("raw-text-key", raw))
    rows = []
    for name, payload in cases:
        try:
            out = verify_case_file(payload)
            rows.append((name, ("ok", out["valid"], out["seal_verified"],
                                out["trust_map_verified"], sorted(out["errors"]),
                                sorted(out["dimensions"].items()))))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    return rows


# ---------------------------------------------------------------------------
# mixed_origin.segment_covered_regimes (new probe, W2-F kill tests)
# ---------------------------------------------------------------------------
def _mo_record(**overrides):
    import test_audit_w2_worker_a as A
    return A._segment_record_dict(**overrides)


def _mo_resign(record):
    from textforensics.validation import compute_signature
    record["signature"] = compute_signature(record)
    return record


def _mo_set(record, path, value, resign=True):
    import copy
    record = copy.deepcopy(record)
    obj = record
    keys = path.split(".")
    for k in keys[:-1]:
        obj = obj[k]
    obj[keys[-1]] = value
    if resign:
        _mo_resign(record)
    return record


def _mo_registry(*records):
    # Raw-dict registry: segment_covered_regimes accepts any object with a
    # .records attribute of mappings (or to_dict() objects). Raw dicts let
    # the probe use values ValidationRecord.from_dict would reject
    # (e.g. contamination_flag "clean") while keeping a valid signature.
    from types import SimpleNamespace
    return SimpleNamespace(records=list(records))


def probe_mixed_origin_regimes():
    from textforensics.mixed_origin import segment_covered_regimes
    good = _mo_record(domain=("news", "essays"))
    rows = []
    cases = [
        ("valid", [good], {}),
        ("valid-wc80", [good], {"word_count": 80}),
        ("valid-wc79", [good], {"word_count": 79}),
        ("valid-wc81", [good], {"word_count": 81}),
        ("detector-zzz", [_mo_set(good, "detector_id", "zzz")], {}),
        ("detector-aaa", [_mo_set(good, "detector_id", "aaa")], {}),
        ("version-999", [_mo_set(good, "detector_version", "9.9.9")], {}),
        ("version-001", [_mo_set(good, "detector_version", "0.0.1")], {}),
        ("version-020", [_mo_record(detector_version="0.2.0", domain=("news", "essays"))], {}),
        ("status-stale", [_mo_record(status="stale", domain=("news", "essays"))], {}),
        ("status-partial", [_mo_record(status="partial", domain=("news", "essays"))], {}),
        ("split-fit", [_mo_record(split_role="fit", domain=("news", "essays"))], {}),
        ("split-threshold", [_mo_record(split_role="threshold", domain=("news", "essays"))], {}),
        ("contamination-yes", [_mo_record(contamination="yes", domain=("news", "essays"))], {}),
        ("contamination-clean", [_mo_record(contamination="clean", domain=("news", "essays"))], {}),
        ("n-human-99", [_mo_record(n_human=99, domain=("news", "essays"))], {}),
        ("n-human-100", [_mo_record(n_human=100, domain=("news", "essays"))], {}),
        ("n-human-true", [_mo_set(good, "data.n_human", True)], {}),
        ("n-human-str", [_mo_set(good, "data.n_human", "x")], {}),
        ("n-ai-99", [_mo_record(n_ai=99, domain=("news", "essays"))], {}),
        ("n-ai-100", [_mo_record(n_ai=100, domain=("news", "essays"))], {}),
        ("n-ai-true", [_mo_set(good, "data.n_ai", True)], {}),
        ("n-ai-str", [_mo_set(good, "data.n_ai", "x")], {}),
        ("bad-signature", [_mo_set(good, "data.n_human", 121, resign=False)], {}),
        ("regime-not-mapping", [_mo_set(good, "regime", ["x"])], {}),
        ("regime-raw", [_mo_record(editing_regime="raw", domain=("news", "essays"))], {}),
        ("regime-mixed", [_mo_record(editing_regime="mixed-origin", domain=("news", "essays"))], {}),
        ("slice-unknown", [_mo_record(fpr_slices=({"slice_id": "other", "value": 0.02, "ci": (0.0, 0.05), "worst_slice": True},), domain=("news", "essays"))], {}),
        ("bucket-list", [_mo_set(good, "regime.length_bucket", ["x"])], {"word_count": 80}),
        ("floor-true", [_mo_set(good, "regime.length_bucket.floor_words", True)], {"word_count": 80}),
        ("floor-str", [_mo_set(good, "regime.length_bucket.floor_words", "x")], {"word_count": 80}),
        ("floor-100-wc99", [_mo_set(good, "regime.length_bucket.floor_words", 100)], {"word_count": 99}),
        ("floor-100-wc100", [_mo_set(good, "regime.length_bucket.floor_words", 100)], {"word_count": 100}),
        ("max-100-wc100", [_mo_set(_mo_set(good, "regime.length_bucket.max_words", 100), "regime.length_bucket.floor_words", 80)], {"word_count": 100}),
        ("max-100-wc101", [_mo_set(_mo_set(good, "regime.length_bucket.max_words", 100), "regime.length_bucket.floor_words", 80)], {"word_count": 101}),
        ("max-100-wc99", [_mo_set(_mo_set(good, "regime.length_bucket.max_words", 100), "regime.length_bucket.floor_words", 80)], {"word_count": 99}),
        ("max-true", [_mo_set(good, "regime.length_bucket.max_words", True)], {"word_count": 80}),
        ("max-str", [_mo_set(good, "regime.length_bucket.max_words", "x")], {"word_count": 80}),
        ("max-none", [good], {"word_count": 500}),
        ("language-none", [_mo_set(good, "regime.language", None)], {}),
        ("domain-empty", [_mo_set(good, "regime.domain", [])], {}),
        ("language-none-domain-set", [_mo_set(good, "regime.language", None)], {}),
        ("fail-detector-then-good", [_mo_set(good, "detector_id", "zzz"), good], {}),
        ("fail-nhuman-then-good", [_mo_record(n_human=99, domain=("news",)), good], {}),
        ("fail-regime-then-good", [_mo_record(editing_regime="raw", domain=("news",)), good], {}),
        ("fail-slice-then-good", [_mo_record(fpr_slices=({"slice_id": "other", "value": 0.02, "ci": (0.0, 0.05)},), domain=("news",)), good], {}),
        ("two-good", [good, _mo_record(domain=("science",))], {}),
    ]
    for name, records, kwargs in cases:
        # sorted list: set repr order varies across processes (hash seed)
        try:
            rows.append((name, ("ok", sorted(segment_covered_regimes(_mo_registry(*records), **kwargs)))))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    return rows
