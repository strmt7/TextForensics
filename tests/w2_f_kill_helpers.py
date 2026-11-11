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
    # non-string / missing dimension names: the `and` in the dim filter
    # only includes dict dims with a string dimension.
    for name, dims in [
        ("dim-none", [{"dimension": None, "state": "supported"}]),
        ("dim-int", [{"dimension": 123, "state": "supported"}]),
        ("dim-missing", [{"state": "supported"}]),
        ("dim-mixed", [{"dimension": "language", "state": "supported"},
                       {"dimension": None, "state": "out_of_scope"},
                       {"dimension": 123, "state": "partial"}]),
        ("dim-nonstr-out-of-scope", [{"dimension": None, "state": "out_of_scope"}]),
    ]:
        rows.append(((name, dims), outcome(sa._recompute_trust_map_overall,
                                            {"dimensions": dims, "schema": "textforensics.trust-map/v3"})))
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


def _et_metrics(*, psi=None, n_paired=60, slice_n="default", drift_allowed=True,
                shift=None, flips="default", calibration=None, human_fpr=None,
                is_human=True, overall="default", drop_overall=False):
    """Flexible metrics dict for evaluate_tiers strengthening.

    ``shift``/``flips``/``calibration``/``human_fpr``/``overall`` accept a
    dict to use verbatim, None for the JSON null, or "default" for the
    base _tier_metrics value. ``flips="absent"`` drops the key entirely.
    """
    m = _tier_metrics(psi=psi, n_paired=n_paired)
    sl = m["slices"]["human-native"]
    if slice_n != "default":
        sl["n"] = slice_n
    sl["drift_signal_allowed"] = drift_allowed
    sl["is_human_slice"] = is_human
    if shift == "absent":
        sl.pop("score_shift", None)
    elif shift is not None:
        sl["score_shift"] = shift
    if flips == "absent":
        sl.pop("flips", None)
    elif flips is not None and flips != "default":
        sl["flips"] = flips
    elif flips is None:
        sl["flips"] = None
    if calibration is not None:
        sl["calibration"] = calibration
    if human_fpr is not None:
        sl["human_fpr"] = human_fpr
    if drop_overall:
        m.pop("overall", None)
    elif overall == "absent":
        m.pop("overall", None)
    elif overall is not None and overall != "default":
        m["overall"] = overall
    elif overall is None:
        m["overall"] = None
    return m


def _et_flips(*, n=60, flips=0, rate=0.0, ci=(0.01, 0.5), human_to_ai=0,
              ai_to_human=0, n_human_paired="default", human_to_ai_human="default",
              drop=()):
    d = {"n": n, "flips": flips, "flip_rate": rate,
         "flip_rate_ci": [ci[0], ci[1]], "human_to_ai": human_to_ai,
         "ai_to_human": ai_to_human, "to_abstain": 0, "from_abstain": 0}
    if n_human_paired != "default":
        d["n_human_paired"] = n_human_paired
    else:
        d["n_human_paired"] = n
    if human_to_ai_human != "default":
        d["human_to_ai_human"] = human_to_ai_human
    else:
        d["human_to_ai_human"] = 0
    for k in drop:
        d.pop(k, None)
    return d


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
    # --- drift / floor shapes -------------------------------------------
    extra = [
        ("drift-allowed-false", dict(psi=0.5, drift_allowed=False), {}),
        ("shift-absent", dict(psi=0.5, shift="absent"), {}),
        ("shift-npaired-none-n60", dict(psi=0.5, shift={}, slice_n=60), {}),
        ("shift-npaired-none-n49", dict(psi=0.5, shift={}, slice_n=49), {}),
        ("shift-npaired-none-n-none", dict(psi=0.5, shift={}, slice_n=None), {}),
        ("npaired-50", dict(psi=0.5, n_paired=50), {}),
        ("ks-breach", dict(psi=None, shift={"ks_statistic": 0.11, "psi": None,
             "ks_pvalue_holm_adjusted": 0.04, "ks_pvalue": 0.01, "n_paired": 60}), {}),
        ("ks-stat-below", dict(psi=None, shift={"ks_statistic": 0.09, "psi": None,
             "ks_pvalue_holm_adjusted": 0.04, "ks_pvalue": 0.01, "n_paired": 60}), {}),
        ("ks-p-above", dict(psi=None, shift={"ks_statistic": 0.11, "psi": None,
             "ks_pvalue_holm_adjusted": 0.05, "ks_pvalue": 0.01, "n_paired": 60}), {}),
        ("ks-p-none", dict(psi=None, shift={"ks_statistic": 0.11, "psi": None,
             "ks_pvalue_holm_adjusted": None, "ks_pvalue": 0.01, "n_paired": 60}), {}),
        ("psi-exact-0.2", dict(psi=0.2), {}),
        ("no-overall-key", dict(psi=0.5, drop_overall=True), {}),
        # --- flip tier-1 (human->AI) --------------------------------------
        ("t1-rate-0.06", dict(flips=_et_flips(n=60, flips=3, rate=0.06,
             human_to_ai=3, n_human_paired=50, human_to_ai_human=3)), {}),
        ("t1-rate-0.05", dict(flips=_et_flips(n=60, flips=3, rate=0.06,
             human_to_ai=3, n_human_paired=60, human_to_ai_human=3)), {}),
        ("t1-rate-0.04", dict(flips=_et_flips(n=60, flips=2, rate=0.06,
             human_to_ai=2, n_human_paired=50, human_to_ai_human=2)), {}),
        ("t1-n49", dict(flips=_et_flips(n=60, flips=10, rate=0.20,
             human_to_ai=10, n_human_paired=49, human_to_ai_human=10)), {}),
        ("t1-n0", dict(flips=_et_flips(n=0, flips=0, rate=0.0,
             human_to_ai=0, n_human_paired=0, human_to_ai_human=0)), {}),
        ("t1-legacy-0.10", dict(flips=_et_flips(n=60, flips=6, rate=0.10,
             human_to_ai=6, drop=("n_human_paired", "human_to_ai_human"))), {}),
        ("t1-legacy-0.05", dict(flips=_et_flips(n=60, flips=3, rate=0.05,
             human_to_ai=3, drop=("n_human_paired", "human_to_ai_human"))), {}),
        ("t1-legacy-0.0", dict(flips=_et_flips(n=60, flips=0, rate=0.0,
             human_to_ai=0, drop=("n_human_paired", "human_to_ai_human"))), {}),
        ("t1-one-key-nhp", dict(flips=_et_flips(n=60, flips=3, rate=0.06,
             human_to_ai=3, n_human_paired=50, drop=("human_to_ai_human",))), {}),
        ("t1-one-key-htah", dict(flips=_et_flips(n=60, flips=3, rate=0.06,
             human_to_ai=3, human_to_ai_human=3, drop=("n_human_paired",))), {}),
        ("t1-flips-none", dict(flips=None), {}),
        ("t1-flips-absent", dict(flips="absent"), {}),
        ("t1-flips-n-none", dict(flips=_et_flips(n=None, flips=0, rate=0.0)), {}),
        ("t1-nhp-none", dict(flips=_et_flips(n=60, flips=0, rate=0.0,
             n_human_paired=None, human_to_ai_human=None)), {}),
        ("t1-htah-none", dict(flips=_et_flips(n=60, flips=0, rate=0.0,
             n_human_paired=60, human_to_ai_human=None)), {}),
        ("t1-human-to-ai-none", dict(flips=_et_flips(n=60, flips=0, rate=0.0,
             human_to_ai=None, drop=("n_human_paired", "human_to_ai_human"))), {}),
        ("t1-nonhuman-slice", dict(is_human=False, flips=_et_flips(
             n=60, flips=12, rate=0.20, human_to_ai=12,
             n_human_paired=50, human_to_ai_human=12)), {}),
        # --- flip tier-2 ---------------------------------------------------
        ("t2-rate-0.02-ci0.01", dict(flips=_et_flips(n=60, flips=2, rate=0.02)), {}),
        ("t2-rate-0.01", dict(flips=_et_flips(n=60, flips=1, rate=0.01)), {}),
        ("t2-rate-0.02-ci0", dict(flips=_et_flips(n=60, flips=2, rate=0.02,
             ci=(0.0, 0.5))), {}),
        ("t2-rate-0.02-n49", dict(flips=_et_flips(n=49, flips=2, rate=0.02)), {}),
        ("t2-rate-0.02-n50", dict(flips=_et_flips(n=50, flips=2, rate=0.02)), {}),
        ("t2-rate-none", dict(flips=_et_flips(n=60, flips=0, rate=None)), {}),
        # --- overall flips -------------------------------------------------
        ("overall-t2", dict(overall={"flips": {"flip_rate": 0.02,
             "flip_rate_ci": [0.01, 0.5], "flips": 2, "n": 60}}), {}),
        ("overall-rate-0.01", dict(overall={"flips": {"flip_rate": 0.01,
             "flip_rate_ci": [0.01, 0.5], "flips": 1, "n": 60}}), {}),
        ("overall-ci0", dict(overall={"flips": {"flip_rate": 0.02,
             "flip_rate_ci": [0.0, 0.5], "flips": 2, "n": 60}}), {}),
        ("overall-n49", dict(overall={"flips": {"flip_rate": 0.02,
             "flip_rate_ci": [0.01, 0.5], "flips": 2, "n": 49}}), {}),
        ("overall-rate-none", dict(overall={"flips": {"flip_rate": None,
             "flip_rate_ci": [0.01, 0.5], "flips": 0, "n": 60}}), {}),
        ("overall-n-none", dict(overall={"flips": {"flip_rate": 0.02,
             "flip_rate_ci": [0.01, 0.5], "flips": 2, "n": None}}), {}),
        ("overall-absent", dict(overall="absent"), {}),
        # --- ECE ------------------------------------------------------------
        ("ece-up-0.06", dict(calibration={"ece": 0.10, "baseline_ece": 0.04,
             "n_calibrated_paired": 60}), {}),
        ("ece-up-0.05", dict(calibration={"ece": 0.10, "baseline_ece": 0.05,
             "n_calibrated_paired": 60}), {}),
        ("ece-up-0.04", dict(calibration={"ece": 0.09, "baseline_ece": 0.05,
             "n_calibrated_paired": 60}), {}),
        ("ece-n49", dict(calibration={"ece": 0.10, "baseline_ece": 0.04,
             "n_calibrated_paired": 49}), {}),
        ("ece-n-none", dict(calibration={"ece": 0.10, "baseline_ece": 0.04,
             "n_calibrated_paired": None}), {}),
        ("ece-none", dict(calibration={"ece": None, "baseline_ece": 0.04,
             "n_calibrated_paired": 60}), {}),
        ("ece-base-none", dict(calibration={"ece": 0.10, "baseline_ece": None,
             "n_calibrated_paired": 60}), {}),
        ("ece-down", dict(calibration={"ece": 0.02, "baseline_ece": 0.10,
             "n_calibrated_paired": 60}), {}),
        # --- FPR cap ---------------------------------------------------------
        ("fpr-cap-breach", dict(human_fpr={"fpr_claim_allowed": True, "fpr": 0.06,
             "fpr_ci": [0.06, 0.10], "n_human": 120, "false_positives": 7}), {}),
        ("fpr-cap-exact", dict(human_fpr={"fpr_claim_allowed": True, "fpr": 0.05,
             "fpr_ci": [0.05, 0.10], "n_human": 120, "false_positives": 6}), {}),
        ("fpr-cap-below", dict(human_fpr={"fpr_claim_allowed": True, "fpr": 0.04,
             "fpr_ci": [0.04, 0.10], "n_human": 120, "false_positives": 5}), {}),
        ("fpr-not-allowed", dict(human_fpr={"fpr_claim_allowed": False, "fpr": 0.06,
             "fpr_ci": [0.06, 0.10], "n_human": 120, "false_positives": 7}), {}),
        # --- version change ---------------------------------------------------
        ("ver-10d", dict(), dict(previous_detector_version="0.0.9",
             previous_run_at="2026-11-01T00:00:00", run_at="2026-11-11T00:00:00")),
        ("ver-7d", dict(), dict(previous_detector_version="0.0.9",
             previous_run_at="2026-11-04T00:00:00", run_at="2026-11-11T00:00:00")),
        ("ver-6d", dict(), dict(previous_detector_version="0.0.9",
             previous_run_at="2026-11-05T00:00:00", run_at="2026-11-11T00:00:00")),
        ("ver-no-run-at", dict(), dict(previous_detector_version="0.0.9",
             previous_run_at=None, run_at="2026-11-11T00:00:00")),
        ("ver-same", dict(), dict(previous_detector_version="0.1.0",
             previous_run_at="2026-11-01T00:00:00", run_at="2026-11-11T00:00:00")),
        ("ver-prev-none", dict(), dict(previous_detector_version=None,
             previous_run_at="2026-11-01T00:00:00", run_at="2026-11-11T00:00:00")),
        # --- provider diff ------------------------------------------------------
        ("prov-diff-10d", dict(), dict(previous_provider_metadata={"a": 1},
             provider_metadata={"a": 2}, previous_run_at="2026-11-01T00:00:00",
             run_at="2026-11-11T00:00:00")),
        ("prov-diff-7d", dict(), dict(previous_provider_metadata={"a": 1},
             provider_metadata={"a": 2}, previous_run_at="2026-11-04T00:00:00",
             run_at="2026-11-11T00:00:00")),
        ("prov-diff-key", dict(), dict(previous_provider_metadata={"a": 1},
             provider_metadata={"a": 1, "b": 2}, previous_run_at="2026-11-01T00:00:00",
             run_at="2026-11-11T00:00:00")),
        ("prov-nodiff", dict(), dict(previous_provider_metadata={"a": 1},
             provider_metadata={"a": 1}, previous_run_at="2026-11-01T00:00:00",
             run_at="2026-11-11T00:00:00")),
        ("prov-prev-none", dict(), dict(previous_provider_metadata=None,
             provider_metadata={"a": 1}, previous_run_at="2026-11-01T00:00:00",
             run_at="2026-11-11T00:00:00")),
        ("prov-meta-none", dict(), dict(previous_provider_metadata={"a": 1},
             provider_metadata=None, previous_run_at="2026-11-01T00:00:00",
             run_at="2026-11-11T00:00:00")),
        ("prov-no-run-at", dict(), dict(previous_provider_metadata={"a": 1},
             provider_metadata={"a": 2}, previous_run_at=None,
             run_at="2026-11-11T00:00:00")),
    ]
    for key, mk, ck in extra:
        rows.append(((key,),
                     outcome(evaluate_tiers, metrics=_et_metrics(**mk),
                             detector_version="0.1.0", previous_breaches=[], **ck)))
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
        # --- missing files (hash OSError excepts) -------------------------
        rows.append((("missing-train",),
                     outcome(prove_disjointness, Path(tmp) / "nope.jsonl", ev)))
        rows.append((("missing-eval",),
                     outcome(prove_disjointness, train, Path(tmp) / "nope.jsonl")))
        rows.append((("missing-both",),
                     outcome(prove_disjointness, Path(tmp) / "nope1.jsonl",
                             Path(tmp) / "nope2.jsonl")))
        # --- bad lines (samples Exception excepts; strict True/False) -----
        import json
        _proof_rows(train, human + ai)
        bad_train = Path(tmp) / "bad-train.jsonl"
        bad_train.write_text('{"label": "human", "text": "Good one."}\nNOT JSON\n',
                             encoding="utf-8")
        bad_ev = Path(tmp) / "bad-eval.jsonl"
        bad_ev.write_text('{"label": "human", "text": "Good one."}\nNOT JSON\n',
                          encoding="utf-8")
        _proof_rows(ev, human + ai)
        rows.append((("bad-train-strict",),
                     outcome(prove_disjointness, bad_train, ev)))
        rows.append((("bad-eval-strict",),
                     outcome(prove_disjointness, train, bad_ev)))
        rows.append((("bad-train-lenient",),
                     outcome(prove_disjointness, bad_train, ev, strict=False)))
        rows.append((("bad-eval-lenient",),
                     outcome(prove_disjointness, train, bad_ev, strict=False)))
        rows.append((("bad-both-lenient",),
                     outcome(prove_disjointness, bad_train, bad_ev, strict=False)))
        # --- group overlap (same source id, different text) --------------
        _proof_rows(train, [{"label": "human", "text": "train text one.",
                            "source_document_id": "doc-shared"},
                           {"label": "ai", "text": "train text two."}])
        _proof_rows(ev, [{"label": "human", "text": "eval text one.",
                          "source_document_id": "doc-shared"},
                         {"label": "ai", "text": "eval text two."}])
        rows.append((("group-overlap",), outcome(prove_disjointness, train, ev)))
        # --- group overlap via normalized text (case/whitespace variant) --
        _proof_rows(train, [{"label": "human", "text": "  Hello   WORLD. "}])
        _proof_rows(ev, [{"label": "human", "text": "hello world."}])
        rows.append((("group-normalized-overlap",),
                     outcome(prove_disjointness, train, ev)))
        # Scrub the temp-dir path out of error messages (non-deterministic).
        tmp_s = str(tmp)
        rows = [(k, _scrub_value(v, tmp_s)) for k, v in rows]
    return rows


def _scrub_value(value, tmp_s):
    if isinstance(value, tuple):
        return tuple(_scrub_value(v, tmp_s) for v in value)
    if isinstance(value, str):
        return value.replace(tmp_s, "TMP")
    return value


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
        # --- hash-mismatch proofs (both orderings) -------------------------
        ev_sha = dataset_sha256(ev)
        cal_sha = artifact["calibration_dataset_sha256"]
        for tag, ehash, thash in (
                ("eval-hash-lo", "0" * 64, dataset_sha256(cal)),
                ("eval-hash-hi", "f" * 64, dataset_sha256(cal)),
                ("train-hash-lo", ev_sha, "0" * 64),
                ("train-hash-hi", ev_sha, "f" * 64),
                ("eval-hash-none", None, dataset_sha256(cal)),
                ("train-hash-none", ev_sha, None)):
            proof = DisjointnessProof(status="verified", overlap_count=0,
                                      training_count=2, evaluation_count=2,
                                      training_hash=thash,
                                      evaluation_hash=ehash,
                                      errors=())
            rows.append(((tag,),
                         outcome(benchmark_with_calibration_jsonl, ev, artifact,
                                 disjointness_proof=proof)))
        # --- allow_same_dataset: same file / different file / no proof -----
        rows.append((("same-file-allowed",),
                     outcome(benchmark_with_calibration_jsonl, cal, artifact,
                             allow_same_dataset=True)))
        same_proof = DisjointnessProof(status="verified", overlap_count=0,
                                       training_count=2, evaluation_count=2,
                                       training_hash=dataset_sha256(cal),
                                       evaluation_hash=dataset_sha256(cal),
                                       errors=())
        rows.append((("same-file-allowed-proof",),
                     outcome(benchmark_with_calibration_jsonl, cal, artifact,
                             allow_same_dataset=True, disjointness_proof=same_proof)))
        rows.append((("diff-file-allowed-noproof",),
                     outcome(benchmark_with_calibration_jsonl, ev, artifact,
                             allow_same_dataset=True)))
        rows.append((("same-file-not-allowed",),
                     outcome(benchmark_with_calibration_jsonl, cal, artifact)))
        # --- contaminated / unknown proofs without diagnostic (raise) ------
        for status, overlap in (("contaminated", 1), ("unknown", -1)):
            proof = DisjointnessProof(status=status, overlap_count=overlap,
                                      training_count=2, evaluation_count=2,
                                      training_hash=dataset_sha256(cal),
                                      evaluation_hash=dataset_sha256(ev),
                                      errors=("test error",))
            rows.append(((f"{status}-nodq",),
                         outcome(benchmark_with_calibration_jsonl, ev, artifact,
                                 disjointness_proof=proof)))
            rows.append(((f"{status}-dq",),
                         outcome(benchmark_with_calibration_jsonl, ev, artifact,
                                 disjointness_proof=proof, diagnostic=True)))
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


def _ev_slice(*, n_human=120, n_ai=120, cond_over=None, fpr="default"):
    from textforensics.evidence import MetricEstimate, SliceConditions, ValidationSlice
    cond_kw = dict(languages=("en",), domains=("general",),
                   editing_regimes=("human_only",))
    if cond_over:
        cond_kw.update(cond_over)
    if fpr == "default":
        metrics = {"auroc": MetricEstimate(value=0.8, n=n_human + n_ai,
                                           ci_lower=0.7, ci_upper=0.9,
                                           method="bootstrap")}
    elif fpr is None:
        metrics = {}
    else:
        metrics = {"fpr": fpr}
    return ValidationSlice(
        slice_id="s1",
        conditions=SliceConditions(**cond_kw),
        n_human=n_human, n_ai=n_ai,
        metrics=metrics,
        threshold=0.5)


def _ev_fpr(*, value=0.02, has_ci=True, ci_upper=0.03, ci_lower=0.01, n=120):
    """An fpr metric. MetricEstimate requires both CI bounds or neither,
    so has_ci=False means both bounds None; a lone ci_upper is
    unconstructible (and AndWithOr:35/36 are equivalent for that reason)."""
    from textforensics.evidence import MetricEstimate
    if has_ci:
        return MetricEstimate(value=value, n=n, ci_lower=ci_lower,
                              ci_upper=ci_upper, method="wilson")
    return MetricEstimate(value=value, n=n, ci_lower=None, ci_upper=None,
                          method="wilson")


def probe_ev_record_candidate():
    from datetime import datetime, UTC
    from textforensics.evidence import _record_candidate_for_dimension, SliceMatch
    rows = []
    now = datetime(2026, 11, 11, tzinfo=UTC)

    def _run(dimension, match, record, slice_, key):
        try:
            cand = _record_candidate_for_dimension(
                record=record, slice_=slice_, match=match, now=now,
                max_age_days=30, dimension=dimension, fpr_ceiling=0.05)
            if cand is None:
                rows.append((key, ("ok", None)))
            else:
                rows.append((key, ("ok", cand.state, cand.reason,
                                   cand.observed.get("age_days"))))
        except Exception as exc:  # noqa: BLE001
            rows.append((key, ("raise", type(exc).__name__, str(exc))))

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
                _run(dimension, match, record, slice_,
                     (dimension, match_vals, age, nh))
    # --- fresh == "partial" (age 31..60 days) + fractional ages -----------
    for age, nh, na in (("2026-10-01T00:00:00Z", 120, 120),   # 41d -> partial
                        ("2026-10-01T00:00:00Z", 10, 10),    # partial + partial
                        ("2026-11-10T10:40:48Z", 120, 120),  # 0.555d -> round() grid
                        ("2026-10-12T00:00:00Z", 120, 120)): # 30d exactly
        for dimension in ("language", "text_length", "domain_genre",
                          "editing_revision", "generator_scope",
                          "human_population", "human_false_positive_evidence",
                          "temporal_version_stability"):
            match = SliceMatch(language="match", length="match", domain="match",
                               editing="match", applicable=True)
            record = _ev_record(evaluated_at=age, n_human=nh, n_ai=na)
            slice_ = _ev_slice(n_human=nh, n_ai=na)
            _run(dimension, match, record, slice_,
                 (dimension, ("match",) * 4, age, nh))
    # --- generator scope / population shapes ------------------------------
    for scope, gens, pops in (
            ("representative", ("g1", "g2", "g3"), ("p1", "p2")),
            ("multi", ("g1", "g2", "g3"), ("p1",)),
            ("multi", ("g1", "g2"), ("p1", "p2")),
            ("multi", ("g1",), ("representative",)),
            ("single", ("g1",), ("p1",)),
            ("single", (), ()),
            ("unknown", (), ("p1",)),
            ("unknown", ("g1",), ())):
        for age in ("2026-11-01T00:00:00Z", "2026-01-01T00:00:00Z"):
            match = SliceMatch(language="match", length="match", domain="match",
                               editing="match", applicable=True)
            record = _ev_record(evaluated_at=age)
            slice_ = _ev_slice(cond_over={"generators": gens,
                                          "generator_scope": scope,
                                          "human_populations": pops})
            for dimension in ("generator_scope", "human_population"):
                _run(dimension, match, record, slice_,
                     (dimension, (scope, gens, pops), age, 120))
    # --- single-field mismatch (reaches the guarded mismatch lines) ------
    for match_vals in (("mismatch", "match", "match", "match"),
                       ("match", "mismatch", "match", "match"),
                       ("match", "match", "mismatch", "match"),
                       ("match", "match", "match", "mismatch"),
                       ("match", "match", "unknown", "match"),
                       ("match", "match", "match", "unknown")):
        match = SliceMatch(language=match_vals[0], length=match_vals[1],
                           domain=match_vals[2], editing=match_vals[3],
                           applicable=True)
        for dimension in ("language", "text_length", "domain_genre",
                          "editing_revision", "generator_scope",
                          "human_population", "human_false_positive_evidence",
                          "temporal_version_stability"):
            record = _ev_record()
            slice_ = _ev_slice()
            _run(dimension, match, record, slice_,
                 (dimension, match_vals, "2026-11-01T00:00:00Z", 120))
    # --- out-of-vocabulary match values + dimensions ----------------------
    for field, val in (("language", "zzz"), ("language", "aaa"),
                       ("length", "zzz"), ("length", "aaa"),
                       ("domain", "zzz"), ("domain", "aaa"),
                       ("editing", "zzz"), ("editing", "aaa")):
        vals = {"language": "match", "length": "match", "domain": "match",
                "editing": "match"}
        vals[field] = val
        match = SliceMatch(language=vals["language"], length=vals["length"],
                           domain=vals["domain"], editing=vals["editing"],
                           applicable=True)
        for dimension in ("language", "text_length", "domain_genre",
                          "editing_revision", "generator_scope",
                          "human_population", "human_false_positive_evidence",
                          "temporal_version_stability"):
            record = _ev_record()
            slice_ = _ev_slice()
            _run(dimension, match, record, slice_,
                 (dimension, (field, val), "2026-11-01T00:00:00Z", 120))
    for dimension in ("zzz", "aaa", "LANGUAGE", ""):
        match = SliceMatch(language="match", length="match", domain="match",
                           editing="match", applicable=True)
        record = _ev_record()
        slice_ = _ev_slice()
        _run(dimension, match, record, slice_,
             (dimension, ("match",) * 4, "2026-11-01T00:00:00Z", 120))
    # --- human-false-positive section: fpr metric shapes ------------------
    for nh, fpr in (
            (120, _ev_fpr(n=120)),
            (99, _ev_fpr(n=99)),
            (100, _ev_fpr(n=100)),
            (101, _ev_fpr(n=101)),
            (120, _ev_fpr(ci_upper=0.05, n=120)),
            (120, _ev_fpr(ci_upper=0.07, n=120)),
            (120, _ev_fpr(has_ci=False, n=120)),
            (120, None)):
        for age in ("2026-11-01T00:00:00Z", "2026-10-01T00:00:00Z",
                    "2026-01-01T00:00:00Z"):
            match = SliceMatch(language="match", length="match", domain="match",
                               editing="match", applicable=True)
            record = _ev_record(evaluated_at=age, n_human=nh, n_ai=120)
            slice_ = _ev_slice(n_human=nh, n_ai=120, fpr=fpr)
            _run("human_false_positive_evidence", match, record, slice_,
                 ("human_false_positive_evidence",
                  (nh, getattr(fpr, "ci_upper", None),
                   getattr(fpr, "has_ci", None)), age, nh))
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
    # --- identity / proof shape boundaries --------------------------------
    base_record = _ev_record()
    base_dj = DisjointnessProof(status="verified", overlap_count=0,
                                training_count=1000, evaluation_count=400,
                                training_hash=_hex64(9),
                                evaluation_hash=base_record.benchmark.fingerprint_sha256)

    def _ident(**over):
        kw = dict(detector_id="det", detector_version="1", provider=None,
                  model=None, config_hash=None, native_score_semantics=None,
                  calibration_id=None, regime="human_only")
        kw.update(over)
        return InferenceIdentity(**kw)

    def _dj(**over):
        kw = dict(status="verified", overlap_count=0, training_count=1000,
                  evaluation_count=400, training_hash=_hex64(9),
                  evaluation_hash=base_record.benchmark.fingerprint_sha256)
        kw.update(over)
        return DisjointnessProof(**kw)

    def _check(key, record, ident, dj, **kw):
        try:
            v = check_record_eligibility(record, identity=ident, disjointness=dj,
                                         now=now, max_age_days=30, **kw)
            rows.append((key, ("ok", v.eligible, list(v.reasons),
                               list(v.unbound_identity_fields))))
        except Exception as exc:  # noqa: BLE001
            rows.append((key, ("raise", type(exc).__name__, str(exc))))

    _check(("id-aaa",), base_record, _ident(detector_id="aaa"), base_dj)
    _check(("id-zzz",), base_record, _ident(detector_id="zzz"), base_dj)
    _check(("ver-0.9",), base_record, _ident(detector_version="0.9"), base_dj)
    _check(("ver-2",), base_record, _ident(detector_version="2"), base_dj)
    _check(("rec-ver-bang",), _ev_record(detector_version="!"), _ident(), base_dj)
    _check(("rec-ver-0.9",), _ev_record(detector_version="0.9"), _ident(), base_dj)
    _check(("overlap-1",), base_record, _ident(), _dj(overlap_count=1))
    _check(("train-1",), base_record, _ident(), _dj(training_count=1))
    _check(("eval-1",), base_record, _ident(), _dj(evaluation_count=1))
    _check(("train-1-eval-1",), base_record, _ident(),
           _dj(training_count=1, evaluation_count=1))
    _check(("eval-hash-diff-lo",), base_record, _ident(),
           _dj(evaluation_hash="0" * 64))
    _check(("eval-hash-diff-hi",), base_record, _ident(),
           _dj(evaluation_hash="f" * 64))
    _check(("eval-hash-none",), base_record, _ident(),
           _dj(evaluation_hash=None))
    _check(("hashes-equal",), base_record, _ident(),
           _dj(training_hash=base_record.benchmark.fingerprint_sha256))
    _check(("age-30",), _ev_record(evaluated_at="2026-10-12T00:00:00Z"),
           _ident(), base_dj)
    _check(("age-31",), _ev_record(evaluated_at="2026-10-11T00:00:00Z"),
           _ident(), base_dj)
    for nh, na in ((99, 120), (100, 120), (101, 120), (120, 99), (120, 100),
                   (120, 101), (99, 99)):
        _check((f"samples-{nh}-{na}",), _ev_record(n_human=nh, n_ai=na),
               _ident(), base_dj)
    _check(("artifact-ok",), base_record, _ident(), base_dj,
           artifact_verification={"ev-1": True})
    _check(("artifact-fail",), base_record, _ident(), base_dj,
           artifact_verification={"ev-1": False})
    _check(("artifact-missing-row",), base_record, _ident(), base_dj,
           artifact_verification={"other": True})
    _check(("artifact-none",), base_record, _ident(), base_dj,
           artifact_verification=None)
    _check(("artifact-bad-shape",), base_record, _ident(), base_dj,
           artifact_verification="not-a-mapping")
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
                         [(k, v.state) for k, v in sorted(cov.dimensions.items())],
                         list(cov.limitations)))
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
                         [(k, v.state) for k, v in sorted(cov.dimensions.items())],
                         list(cov.limitations))))
        # --- empty registry / multi-record continue-vs-break --------------
        cov = A._v2_coverage(EvidenceRegistry([]),
                             **A._eligible_inputs(EvidenceRegistry([record]), root))
        rows.append((("empty-registry",), list(cov.record_ids),
                     [(k, v.state) for k, v in sorted(cov.dimensions.items())],
                     list(cov.limitations)))
        retracted = A._v2_record(status="retracted")
        retracted2 = A._v2_record(status="retracted", split="heldout")
        active = A._v2_record(status="active")
        # Second record needs a distinct evidence_id: split="heldout" is an
        # approved held-out split, so it stays eligible.
        active2 = A._v2_record(status="active", split="heldout")
        thin2 = A._v2_record(n_human=10, n_ai=10, split="heldout")
        for tag, recs in (("retracted-then-active", [retracted, active2]),
                          ("active-then-retracted", [active, retracted2]),
                          ("thin-then-adequate", [A._v2_record(n_human=10, n_ai=10), active2]),
                          ("adequate-then-thin", [active, thin2])):
            registry = EvidenceRegistry(recs)
            cov = A._v2_coverage(registry, **A._eligible_inputs(registry, root))
            rows.append(((tag,), list(cov.record_ids),
                         [(k, v.state) for k, v in sorted(cov.dimensions.items())],
                         list(cov.limitations)))
        # --- max_age_days / fpr_ceiling boundaries -------------------------
        for tag, kw in (("max-age-0", dict(max_age_days=0)),
                        ("max-age-1", dict(max_age_days=1)),
                        ("max-age-2", dict(max_age_days=2)),
                        ("fpr-ceiling-0", dict(fpr_ceiling=0.0)),
                        ("fpr-ceiling-1", dict(fpr_ceiling=1.0)),
                        ("fpr-ceiling-1.5", dict(fpr_ceiling=1.5)),
                        ("fpr-ceiling-neg", dict(fpr_ceiling=-0.1))):
            try:
                cov = A._v2_coverage(registry, **A._eligible_inputs(registry, root), **kw)
                rows.append(((tag,), list(cov.record_ids),
                             [(k, v.state) for k, v in sorted(cov.dimensions.items())],
                             list(cov.limitations)))
            except Exception as exc:  # noqa: BLE001
                rows.append(((tag,), ("raise", type(exc).__name__, str(exc))))
        # --- unbound identity fields (limitations message) -----------------
        from textforensics.evidence import InferenceIdentity
        bound_identity = InferenceIdentity(
            detector_id="a", detector_version="1", provider="prov", model="m",
            config_hash=_hex64(5), native_score_semantics="probability",
            calibration_id=None, regime="human_only")
        cov = A._v2_coverage(registry, **{**A._eligible_inputs(registry, root),
                                          "identity": bound_identity})
        rows.append((("unbound-identity",), list(cov.record_ids),
                     [(k, v.state) for k, v in sorted(cov.dimensions.items())],
                     list(cov.limitations)))
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
            (_adv_text(9), None),                    # MIN_WORDS - 1
            (_adv_text(10), None),                   # MIN_WORDS exactly
            (_adv_text(11), None),                   # MIN_WORDS + 1
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
    # summary(): text_sha256 prefix is [:16] + "..."
    for text in (_adv_text(40), _adv_text(10)):
        rep = det.analyze(text)
        s = rep.summary()
        rows.append((("summary", len(text.split())),
                     (s["text_sha256"], s["overall_risk"], s["total_findings"],
                      s["patterns_checked"])))
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
    # summary(): text_sha256 prefix is [:16] + "..."
    for text in (three, two):
        rep = checker.analyze(text)
        s = rep.summary()
        rows.append((("summary", len(text.split())),
                     (s["text_sha256"], s["risk_level"], s["total_findings"],
                      s["support_status"])))
    # segment_word_target boundary: one-word sentences, 200 vs 201 words.
    # target 100 -> 200 words = 2 segments, 201 words = 3 segments.
    # target 101 -> 201 words = 2 segments; target 99 -> 200 words = 3.
    from textforensics.semantic import analyze_semantic_consistency
    for n in (199, 200, 201, 202):
        text = " ".join(f"Word{i}." for i in range(n))
        try:
            rep = analyze_semantic_consistency(text)
            rows.append((("target-boundary", n), rep.support_status,
                         rep.overall_consistency_score, len(rep.findings)))
        except Exception as exc:  # noqa: BLE001
            rows.append((("target-boundary", n),
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


def _pr_slice_inputs2(*, n_human=10, n_ai=0, n_none=0, flipped=0,
                       direction="higher_means_ai", prev_verdicts=None,
                       current_verdicts=None, cal=None, cal_id=None,
                       baseline_cal=None, baseline_cal_id=None, scores=None,
                       baseline_scores=None):
    """Slice inputs with mixed labels / verdicts / calibrated probs.

    ``cal``/``cal_id`` apply to current records (scalar or per-item list);
    ``baseline_cal``/``baseline_cal_id`` likewise for baseline records.
    ``scores``/``baseline_scores`` are per-item score lists (None = no score).
    """
    import sys
    import test_w2_worker_d as D
    total = n_human + n_ai + n_none
    item_ids, current, baseline, labels = [], {}, {}, {}
    for i in range(total):
        item_id = f"h-{i:03d}"
        label = 0 if i < n_human else (1 if i < n_human + n_ai else None)
        is_flipped = i < flipped
        prev_verdict = (prev_verdicts or {}).get(item_id, "human_like")
        curr_verdict = (current_verdicts or {}).get(
            item_id, "ai_like" if is_flipped else "human_like")
        score = 0.9 if is_flipped else 0.3
        if scores is not None:
            score = scores[i]
        bscore = 0.3
        if baseline_scores is not None:
            bscore = baseline_scores[i]
        c = cal[i] if isinstance(cal, list) else cal
        cid = cal_id[i] if isinstance(cal_id, list) else cal_id
        bc = baseline_cal[i] if isinstance(baseline_cal, list) else baseline_cal
        bcid = (baseline_cal_id[i] if isinstance(baseline_cal_id, list)
                else baseline_cal_id)
        prev = D._rec(item_id, score=bscore, verdict=prev_verdict,
                      cal=bc, cal_id=bcid, direction=direction)
        curr = D._rec(item_id, score=score, verdict=curr_verdict,
                      cal=c, cal_id=cid, direction=direction)
        item_ids.append(item_id)
        current[item_id] = curr
        baseline[item_id] = prev
        labels[item_id] = label
    return item_ids, current, baseline, labels


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
        rows.append((key, _sm_row(out)))
    # --- mixed labels / verdicts / calibration / boundaries ----------------
    variants = [
        # (key, builder-kwargs, call-kwargs)
        ("ai-mixed", dict(n_human=6, n_ai=4, flipped=2), {}),
        ("ai-only", dict(n_human=0, n_ai=10, flipped=0), {}),
        ("none-labels", dict(n_human=5, n_ai=3, n_none=2, flipped=1), {}),
        ("n1-human", dict(n_human=1, n_ai=0, flipped=0), {}),
        ("n50", dict(n_human=50, n_ai=0, flipped=5), {}),
        ("n51", dict(n_human=51, n_ai=0, flipped=5), {}),
        ("n100-human", dict(n_human=100, n_ai=0, flipped=5), {}),
        ("n99-human", dict(n_human=99, n_ai=0, flipped=5), {}),
        ("n101-human", dict(n_human=101, n_ai=0, flipped=5), {}),
        ("n300-cal-all", dict(n_human=300, n_ai=0, flipped=3, cal=0.3,
                              baseline_cal=0.3), {}),
        ("cal-partial", dict(n_human=10, n_ai=0, flipped=2,
                             cal=[0.3] * 5 + [None] * 5,
                             baseline_cal=[0.3] * 5 + [None] * 5), {}),
        ("cal-all", dict(n_human=10, n_ai=0, flipped=2, cal=0.3,
                         baseline_cal=0.3), {}),
        ("cal-baseline-only", dict(n_human=10, n_ai=0, flipped=2,
                                   baseline_cal=0.3), {}),
        ("cal-current-only", dict(n_human=10, n_ai=0, flipped=2, cal=0.3), {}),
        ("cal-ids-same", dict(n_human=10, n_ai=0, flipped=2, cal=0.3,
                              cal_id="cal-1", baseline_cal=0.3,
                              baseline_cal_id="cal-1"), {}),
        ("cal-ids-diff", dict(n_human=10, n_ai=0, flipped=2, cal=0.3,
                              cal_id="cal-2", baseline_cal=0.3,
                              baseline_cal_id="cal-1"), {}),
        ("cal-ids-baseline-only", dict(n_human=10, n_ai=0, flipped=2,
                                       baseline_cal_id="cal-1"), {}),
        ("cal-ids-current-only", dict(n_human=10, n_ai=0, flipped=2,
                                      cal_id="cal-1"), {}),
        ("cal-ages", dict(n_human=10, n_ai=0, flipped=2, cal=0.3,
                          cal_id=["cal-1", "cal-2"] * 5,
                          baseline_cal=0.3, baseline_cal_id="cal-1"),
         dict(calibration_created_at={"cal-1": "2026-11-01T00:00:00",
                                      "cal-2": "2026-11-10T00:00:00"})),
        ("cal-ages-unknown-id", dict(n_human=10, n_ai=0, flipped=2, cal=0.3,
                                     cal_id="cal-9", baseline_cal=0.3),
         dict(calibration_created_at={"cal-1": "2026-11-01T00:00:00"})),
        ("cal-ages-none-id", dict(n_human=10, n_ai=0, flipped=2, cal=0.3,
                                  baseline_cal=0.3),
         dict(calibration_created_at={"cal-1": "2026-11-01T00:00:00"})),
        ("abstain-current", dict(n_human=10, n_ai=0, flipped=2,
                                 current_verdicts={"h-002": "abstain",
                                                   "h-003": "abstain"}), {}),
        ("abstain-all-current", dict(n_human=10, n_ai=0, flipped=0,
                                     current_verdicts={f"h-{i:03d}": "abstain"
                                                       for i in range(10)}), {}),
        ("no-score-current", dict(n_human=10, n_ai=0, flipped=2,
                                  scores=[None] * 10), {}),
        ("some-no-score", dict(n_human=10, n_ai=0, flipped=2,
                               scores=[0.3] * 5 + [None] * 5), {}),
        ("no-baseline", dict(n_human=10, n_ai=0, flipped=2),
         dict(no_baseline=True)),
        ("no-previous", dict(n_human=10, n_ai=0, flipped=2),
         dict(no_previous=True)),
        ("nonhuman-slice", dict(n_human=0, n_ai=10, flipped=0),
         dict(is_human_slice=False)),
        ("attacked", dict(n_human=0, n_ai=10, flipped=0),
         dict(is_attacked_slice=True, human_scores_all=[0.3] * 10,
              human_labels_all=[0] * 10)),
        ("attacked-lower", dict(n_human=0, n_ai=10, flipped=0),
         dict(is_attacked_slice=True, human_scores_all=[0.3] * 10,
              human_labels_all=[0] * 10, score_direction="lower_means_ai")),
        ("attacked-unknown-dir", dict(n_human=0, n_ai=10, flipped=0),
         dict(is_attacked_slice=True, human_scores_all=[0.3] * 10,
              human_labels_all=[0] * 10, score_direction="unknown")),
        ("attacked-na-dir", dict(n_human=0, n_ai=10, flipped=0),
         dict(is_attacked_slice=True, human_scores_all=[0.3] * 10,
              human_labels_all=[0] * 10, score_direction="not_applicable")),
        ("attacked-no-human-ref", dict(n_human=0, n_ai=10, flipped=0),
         dict(is_attacked_slice=True, human_scores_all=[],
              human_labels_all=[])),
        ("attacked-no-machine", dict(n_human=10, n_ai=0, flipped=0),
         dict(is_attacked_slice=True, human_scores_all=[0.3] * 10,
              human_labels_all=[0] * 10)),
        ("attacked-machine-no-score", dict(n_human=0, n_ai=10, flipped=0,
                                           scores=[None] * 10),
         dict(is_attacked_slice=True, human_scores_all=[0.3] * 10,
              human_labels_all=[0] * 10)),
        ("attacked-mixed-scores", dict(n_human=0, n_ai=10, flipped=0,
                                       scores=[0.9, 0.8, 0.7, 0.6, 0.5,
                                               0.4, 0.3, 0.2, 0.1, 0.05]),
         dict(is_attacked_slice=True,
              human_scores_all=[0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4,
                                0.45, 0.5],
              human_labels_all=[0] * 10)),
    ]
    for key, bkw, ckw in variants:
        item_ids, current, baseline, labels = _pr_slice_inputs2(**bkw)
        n = len(item_ids)
        human_scores = [0.3] * n
        human_labels = [0] * n
        kw = dict(item_ids=item_ids, current=current,
                  baseline=None if ckw.get("no_baseline") else baseline,
                  previous=None if ckw.get("no_previous") else baseline,
                  labels=labels, primitives=primitives,
                  is_human_slice=ckw.get("is_human_slice", True),
                  is_attacked_slice=ckw.get("is_attacked_slice", False),
                  human_scores_all=ckw.get("human_scores_all", human_scores),
                  human_labels_all=ckw.get("human_labels_all", human_labels),
                  calibration_created_at=ckw.get("calibration_created_at"),
                  now=now,
                  score_direction=ckw.get("score_direction", "higher_means_ai"))
        out = outcome(_slice_metrics, **kw)
        rows.append(((key,), _sm_row(out)))
    return rows


def _sm_row(out):
    """Record the FULL _slice_metrics result (was: only n + flips)."""
    if out[0] != "ok":
        return out
    import ast as _ast
    return ("ok", _ast.literal_eval(out[1]))


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


# ---------------------------------------------------------------------------
# report.build_forensic_bundle (new probe, W2-F kill tests)
# ---------------------------------------------------------------------------
class _MockRegistry:
    """Minimal EvidenceRegistry stand-in for build_forensic_bundle."""
    def __init__(self, verified=True, errors=()):
        self.verified = verified
        self.errors = list(errors)
        self.roots = []
        self.records = []
        self.registry_id = "mock-registry"

    def verify_artifacts(self, root="."):
        from types import SimpleNamespace
        self.roots.append(root)
        return SimpleNamespace(verified=self.verified, errors=list(self.errors))

    def summary(self):
        return {"registry_id": "mock-registry", "record_count": 0}

    def records_for(self, *args, **kwargs):
        return list(getattr(self, "_records_for", []))


def _report_summary(bundle):
    d = bundle.to_dict()
    d.pop("generated_at_utc", None)
    tm = dict(d.get("trust_map") or {})
    tm.pop("generated_at_utc", None)
    results = []
    for row in d.get("detector_results") or []:
        results.append({k: v for k, v in row.items() if k != "runtime_ms"})
        results[-1]["_has_runtime_ms"] = "runtime_ms" in row
    failures = []
    for row in d.get("detector_failures") or []:
        failures.append({k: v for k, v in row.items() if k != "runtime_ms"})
        failures[-1]["_has_runtime_ms"] = "runtime_ms" in row
    robustness = []
    for row in (d.get("robustness") or {}).get("detectors") or []:
        r = dict(row)
        r["failures"] = [{k: v for k, v in f.items() if k != "runtime_ms"}
                         for f in row.get("failures") or []]
        r["_failure_has_runtime_ms"] = [("runtime_ms" in f) for f in row.get("failures") or []]
        robustness.append(r)
    return {"schema": d.get("schema"), "content_sha256": d.get("content_sha256"),
            "detector_results": results, "detector_failures": failures,
            "robustness": robustness,
            "trust_overall": tm.get("overall"),
            "trust_dims": [(x.get("dimension"), x.get("state")) for x in tm.get("dimensions") or []],
            "trust_dim_limitations": [(x.get("dimension"), x.get("limitations"))
                                      for x in tm.get("dimensions") or []],
            "trust_coverage": tm.get("coverage"),
            "limitations": d.get("limitations"),
            "skipped": (d.get("provenance") or {}).get("skipped_detectors"),
            "legacy": d.get("legacy"),
            "evidence_registry": d.get("evidence_registry")}


def _records_registry():
    import test_audit_w2_worker_a as A
    reg = _MockRegistry(True, [])
    reg._records_for = [A._v2_record()]
    reg.records = reg._records_for
    return reg


def probe_report_bundle():
    from textforensics.report import build_forensic_bundle
    from textforensics.detectors import BuiltinHeuristicDetector
    from textforensics.benchmark import DisjointnessProof
    from types import SimpleNamespace
    text = ("The city council approved the new budget on Tuesday. "
            "Local residents welcomed the decision with cautious optimism. " * 8)
    det = [BuiltinHeuristicDetector()]
    proof = DisjointnessProof(status="verified", overlap_count=0, training_count=10,
                              evaluation_count=10, training_hash="a" * 64,
                              evaluation_hash="b" * 64, group_overlap_count=0)

    def failing_detector():
        d = SimpleNamespace(detector_id="fake/failing", detector_version="1",
                            detector_family="fake", execution="local")
        def detect(t):
            raise RuntimeError("boom")
        d.detect = detect
        return d

    def remote_detector():
        d = SimpleNamespace(detector_id="fake/remote", detector_version="1",
                            detector_family="fake", execution="remote")
        d.detect = lambda t: None
        return d

    rows = []
    cases = [
        ("default", {}, None),
        ("deterministic", {"deterministic": True}, None),
        ("deterministic-fixed-ts", {"deterministic": True, "fixed_timestamp": "2026-01-01T00:00:00+00:00"}, None),
        ("legacy", {"include_legacy": True}, None),
        ("text-int", {"text": 123}, None),
        ("text-empty", {"text": ""}, None),
        ("text-spaces", {"text": "   "}, None),
        ("both-registry", {"registry": _MockRegistry(), "registry_path": "x.json"}, None),
        ("verify-no-registry", {"verify_evidence": True}, None),
        ("verify-ok", {"verify_evidence": True, "registry": _MockRegistry(True, [])}, "roots"),
        ("verify-fail-1", {"verify_evidence": True, "registry": _MockRegistry(False, ["bad artifact"])}, "roots"),
        ("verify-fail-6", {"verify_evidence": True, "registry": _MockRegistry(False, [f"err{i}" for i in range(6)])}, "roots"),
        ("verify-root", {"verify_evidence": True, "registry": _MockRegistry(True, []), "evidence_root": "/tmp/ev"}, "roots"),
        ("disjointness", {"disjointness": proof}, None),
        ("failing-detector", {"detectors": det + [failing_detector()]}, None),
        ("failing-det-det", {"detectors": det + [failing_detector()], "deterministic": True}, None),
        ("skipped-remote", {"detectors": det + [remote_detector()]}, None),
        ("no-detectors", {"detectors": []}, None),
        ("registry-records", {"registry": _records_registry()}, None),
        ("registry-records-disjointness", {"registry": _records_registry(), "disjointness": proof}, None),
    ]
    for name, kwargs, extra in cases:
        text_arg = kwargs.pop("text", text)
        try:
            bundle = build_forensic_bundle(text_arg, **kwargs)
            rows.append((name, ("ok", _report_summary(bundle),
                                kwargs.get("registry").roots if extra == "roots" else None)))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    return rows


# ---------------------------------------------------------------------------
# probe_metrics supplementary functions (new probe, W2-F kill tests)
# ---------------------------------------------------------------------------
def probe_pm_extra():
    import math
    from textforensics.probe_metrics import (
        psi, coverage_shortfall_pp, require_integer, wilson_ci,
        holm_adjusted, set_coverage, reject_nonfinite_value,
        require_finite_number)
    rows = []
    # psi: identical -> 0; shifted; empty bins (smoothing); bin edges
    for name, fn in [
        ("psi-identical", lambda: psi([0.1, 0.2, 0.3, 0.4], [0.1, 0.2, 0.3, 0.4])),
        ("psi-shifted", lambda: psi([0.1, 0.2, 0.3, 0.4], [0.5, 0.6, 0.7, 0.8])),
        ("psi-empty-bins", lambda: psi([0.1] * 10, [0.9] * 10)),
        ("psi-bins1", lambda: psi([0.1, 0.9], [0.2, 0.8], bins=1)),
        ("psi-bins2", lambda: psi([0.1, 0.2, 0.8, 0.9], [0.15, 0.25, 0.75, 0.85], bins=2)),
        ("psi-bins0", lambda: psi([0.1, 0.2], [0.1, 0.2], bins=0)),
        ("psi-empty", lambda: psi([], [0.1])),
        ("psi-nan", lambda: psi([0.1, float("nan")], [0.1, 0.2])),
        ("psi-cut-edge", lambda: psi([0.0, 0.25, 0.5, 0.75, 1.0], [0.25, 0.25, 0.5, 0.75, 1.0], bins=4)),
        ("wilson-0-10", lambda: wilson_ci(0, 10)),
        ("wilson-10-10", lambda: wilson_ci(10, 10)),
        ("wilson-5-10", lambda: wilson_ci(5, 10)),
        ("wilson-1-100", lambda: wilson_ci(1, 100)),
        ("wilson-0-1", lambda: wilson_ci(0, 1)),
        ("wilson-k-gt-n", lambda: wilson_ci(11, 10)),
        ("wilson-n-0", lambda: wilson_ci(0, 0)),
        ("wilson-z-0", lambda: wilson_ci(1, 10, z=0.0)),
        ("wilson-z-neg", lambda: wilson_ci(1, 10, z=-1.0)),
        ("wilson-z-2", lambda: wilson_ci(5, 10, z=2.0)),
        ("shortfall-0", lambda: coverage_shortfall_pp(0.9, 0.9)),
        ("shortfall-5pp", lambda: coverage_shortfall_pp(0.85, 0.9)),
        ("shortfall-neg", lambda: coverage_shortfall_pp(0.95, 0.9)),
        ("shortfall-100", lambda: coverage_shortfall_pp(0.0, 1.0)),
        ("shortfall-emp-over", lambda: coverage_shortfall_pp(1.1, 0.9)),
        ("shortfall-nom-under", lambda: coverage_shortfall_pp(0.9, -0.1)),
        ("shortfall-nan", lambda: coverage_shortfall_pp(float("nan"), 0.9)),
        ("holm-single", lambda: holm_adjusted([0.03])),
        ("holm-sorted", lambda: holm_adjusted([0.01, 0.02, 0.03, 0.04])),
        ("holm-unsorted", lambda: holm_adjusted([0.04, 0.01, 0.03, 0.02])),
        ("holm-cap", lambda: holm_adjusted([0.5, 0.6, 0.7])),
        ("holm-running-max", lambda: holm_adjusted([0.01, 0.9, 0.02])),
        ("holm-empty", lambda: holm_adjusted([])),
        ("holm-over-1", lambda: holm_adjusted([1.5])),
        ("holm-5-2", lambda: holm_adjusted([0.01, 0.02, 0.03, 0.04, 0.05])),
        ("setcov-all", lambda: set_coverage([{0}, {1}, {0, 1}], [0, 1, 1])),
        ("setcov-none", lambda: set_coverage([{1}, {0}], [0, 1])),
        ("setcov-half", lambda: set_coverage([{0}, {0}], [0, 1])),
        ("setcov-mismatch", lambda: set_coverage([{0}], [0, 1])),
        ("setcov-empty", lambda: set_coverage([], [])),
        ("setcov-bool-label", lambda: set_coverage([{0}], [True])),
        ("setcov-str-label", lambda: set_coverage([{0}], ["0"])),
        ("setcov-300", lambda: set_coverage([{0}] * 300, [0] * 300)),
        ("reqint-5", lambda: require_integer(5, "n")),
        ("reqint-0-min0", lambda: require_integer(0, "n", minimum=0)),
        ("reqint-neg-min0", lambda: require_integer(-1, "n", minimum=0)),
        ("reqint-10-max10", lambda: require_integer(10, "n", maximum=10)),
        ("reqint-11-max10", lambda: require_integer(11, "n", maximum=10)),
        ("reqint-9-max10", lambda: require_integer(9, "n", maximum=10)),
        ("reqint-bool", lambda: require_integer(True, "n")),
        ("reqint-float", lambda: require_integer(5.0, "n")),
        ("reqint-str", lambda: require_integer("5", "n")),
        ("reqfin-1", lambda: require_finite_number(1, "x")),
        ("reqfin-nan", lambda: require_finite_number(float("nan"), "x")),
        ("reqfin-inf", lambda: require_finite_number(float("inf"), "x")),
        ("reqfin-bool", lambda: require_finite_number(True, "x")),
        ("reqfin-str", lambda: require_finite_number("1", "x")),
        ("reject-none", lambda: reject_nonfinite_value(None)),
        ("reject-nan", lambda: reject_nonfinite_value(float("nan"))),
        ("reject-inf", lambda: reject_nonfinite_value(float("inf"))),
        ("reject-nested", lambda: reject_nonfinite_value({"a": [1.0, float("nan")]})),
        ("reject-nested-ok", lambda: reject_nonfinite_value({"a": [1.0, 2.0]})),
        ("reject-set-nan", lambda: reject_nonfinite_value({float("nan")})),
    ]:
        rows.append((name, outcome(fn)))
    return rows


# ---------------------------------------------------------------------------
# _standalone_verify._trust_map_check_errors (new probe, W2-F kill tests)
# ---------------------------------------------------------------------------
def probe_sa_trust_map_errors():
    import sys
    from textforensics._standalone_verify import _trust_map_check_errors
    from textforensics.trust import TRUST_DIMENSIONS
    import copy, json
    dims = sorted(TRUST_DIMENSIONS)
    base = _schema_map("v3")
    base["overall"] = "mixed"
    # derive the correct overall for the base map (all supported -> strong)
    base["overall"] = "strong"
    base2 = _schema_map("v2")
    base2["overall"] = "strong"
    cases = [
        ("valid-v3", base, "textforensics.forensic-bundle/v2"),
        ("valid-v2", base2, "textforensics.forensic-bundle/v2"),
        ("valid-v2-bundle-v1", base2, "textforensics.forensic-bundle/v1"),
        ("not-dict", [], "textforensics.forensic-bundle/v2"),
        ("v4-schema", _schema_map("v3", **{"schema": "textforensics.trust-map/v4"}), "textforensics.forensic-bundle/v2"),
        ("v1-map", _schema_map("v1"), "textforensics.forensic-bundle/v1"),
        ("overall-mismatch", _schema_map("v3", **{"overall": "mixed"}), "textforensics.forensic-bundle/v2"),
        ("overall-distinct", _schema_map("v3", **{"overall": "".join(["s", "t", "r", "o", "n", "g"])}), "textforensics.forensic-bundle/v2"),
        ("overall-partial", _schema_map("v3", **{"overall": "partial"}), "textforensics.forensic-bundle/v2"),
        ("missing-dim", _schema_map("v3", dims=[{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]]), "textforensics.forensic-bundle/v2"),
        ("unknown-dim", _schema_map("v3", dims=[{"dimension": "nope", "state": "supported", "reason": "ok"}] + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]]), "textforensics.forensic-bundle/v2"),
        ("dup2", _schema_map("v3", dims=[{"dimension": dims[0], "state": "supported", "reason": "ok"}] * 2 + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]]), "textforensics.forensic-bundle/v2"),
        ("dup3", _schema_map("v3", dims=[{"dimension": dims[0], "state": "supported", "reason": "ok"}] * 3 + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]]), "textforensics.forensic-bundle/v2"),
        ("two-bad-dims", _schema_map("v3", dims=[{"dimension": dims[0], "state": "bogus", "reason": "ok"}, {"dimension": dims[1], "state": "bogus", "reason": "ok"}] + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[2:]]), "textforensics.forensic-bundle/v2"),
        ("reason-123", _schema_map("v3", dims=[{"dimension": dims[0], "state": "supported", "reason": 123}] + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]]), "textforensics.forensic-bundle/v2"),
        ("reason-empty", _schema_map("v3", dims=[{"dimension": dims[0], "state": "supported", "reason": ""}] + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]]), "textforensics.forensic-bundle/v2"),
        ("name-non-str", _schema_map("v3", dims=[{"dimension": 123, "state": "supported", "reason": "ok"}] + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]]), "textforensics.forensic-bundle/v2"),
        ("name-empty", _schema_map("v3", dims=[{"dimension": "", "state": "supported", "reason": "ok"}] + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]]), "textforensics.forensic-bundle/v2"),
        ("generated-none", _schema_map("v3", generated_at_utc=None), "textforensics.forensic-bundle/v2"),
        ("coverage-bool", _schema_cov(base, supported=True), "textforensics.forensic-bundle/v2"),
        ("coverage-neg", _schema_cov(base, supported=-1), "textforensics.forensic-bundle/v2"),
        ("coverage-mismatch", _schema_cov(base, supported=len(dims) - 1, partial=1), "textforensics.forensic-bundle/v2"),
        ("coverage-mismatch-up", _schema_cov(base, supported=len(dims) + 1), "textforensics.forensic-bundle/v2"),
        ("pair-bad", base, "textforensics.forensic-bundle/v9"),
        ("empty-dims", _schema_map("v3", dims=[]), "textforensics.forensic-bundle/v2"),
        ("dims-not-list", _schema_map("v3", dims={"a": 1}), "textforensics.forensic-bundle/v2"),
        ("partial-unknown-mix", _schema_map("v3", dims=[{"dimension": dims[0], "state": "partial", "reason": "ok"}] + [{"dimension": d, "state": "unknown", "reason": "ok"} for d in dims[1:]], **{"overall": "mixed", "coverage": {"supported": 0, "partial": 1, "unknown": 9, "out_of_scope": 0, "stale": 0}}), "textforensics.forensic-bundle/v2"),
    ]
    # fix the coverage cases to carry the right overall (all-supported -> strong)
    fixed = []
    for name, m, bundle_schema in cases:
        if name.startswith("coverage-"):
            m = copy.deepcopy(m)
            m["overall"] = "strong"
        fixed.append((name, m, bundle_schema))
    return [(name, outcome(_trust_map_check_errors, m, b)) for name, m, b in fixed]


# ---------------------------------------------------------------------------
# calibration.run_calibration_evaluation (new probe, W2-F kill tests)
# ---------------------------------------------------------------------------
def probe_cal_pipeline():
    import tempfile, json
    from pathlib import Path
    from textforensics.calibration import run_calibration_evaluation
    rows = []

    def write(path, texts):
        rows = ([{"label": "human", "text": t} for t in texts[:4]]
                + [{"label": "ai", "text": t} for t in texts[4:]])
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        cal = tmp / "cal.jsonl"
        ev = tmp / "ev.jsonl"
        same = tmp / "same.jsonl"
        bad = tmp / "bad.jsonl"
        write(cal, [f"cal human sentence {i}." for i in range(4)] + [f"cal ai sentence {i}." for i in range(4)])
        write(ev, [f"ev human sentence {i}." for i in range(4)] + [f"ev ai sentence {i}." for i in range(4)])
        write(same, [f"same human sentence {i}." for i in range(4)])
        bad.write_text('{"label": "human", "text": "ok."}\nNOT JSON\n{"label": "ai", "text": "ok2."}\n', encoding="utf-8")
        for name, c, e, kwargs in [
            ("disjoint", cal, ev, {}),
            ("disjoint-diag", cal, ev, {"diagnostic": True}),
            ("same-file", cal, cal, {}),
            ("same-file-diag", cal, cal, {"diagnostic": True}),
            ("bad-cal", bad, ev, {}),
            ("bad-cal-diag", bad, ev, {"diagnostic": True}),
            ("bad-cal-nostrict", bad, ev, {"strict": False}),
            ("bad-eval", cal, bad, {}),
            ("bad-eval-diag", cal, bad, {"diagnostic": True}),
            ("missing", cal, tmp / "nope.jsonl", {}),
            ("missing-diag", cal, tmp / "nope.jsonl", {"diagnostic": True}),
        ]:
            try:
                out = run_calibration_evaluation(c, e, **kwargs)
                er = out["evaluation_result"]
                rows.append((name, ("ok", er.get("evaluation_mode"),
                                    er.get("contamination_detected"),
                                    er.get("overlap_count"),
                                    out["validation"].get("valid"),
                                    out["validation"].get("contamination_detected"))))
            except Exception as exc:  # noqa: BLE001
                rows.append((name, ("raise", type(exc).__name__,
                                    str(exc).replace(str(tmp), "TMP"))))
    return rows


# ---------------------------------------------------------------------------
# calibration.store / getters (new probe, W2-F kill tests)
# ---------------------------------------------------------------------------
def _cal_identity(**over):
    from textforensics.calibration import InferenceIdentity
    import test_calibration as T
    kw = dict(detector_id="det1", detector_version="1.0", provider="local",
              model="builtin-heuristic-0.1.0", config_hash=T.hex64(5),
              native_score_semantics="probability_higher_means_ai",
              regime="unedited", calibration_id="cal1")
    kw.update(over)
    return InferenceIdentity(**kw)


def probe_cal_store():
    import tempfile
    from textforensics.calibration import CalibrationManager
    import test_calibration as T
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        mgr = CalibrationManager(tmp)
        ident = _cal_identity()
        # valid store with identity
        try:
            art = mgr.store(detector_id="det1", detector_version="1.0",
                            curve=T.platt_curve(), calibration_id="cal1",
                            created_at="2024-01-01T00:00:00+00:00", identity=ident,
                            **T.eligible_artifact_kwargs())
            rows.append(("store-identity", ("ok", art.artifact_id, art.calibration_id)))
        except Exception as exc:  # noqa: BLE001
            rows.append(("store-identity", ("raise", type(exc).__name__, str(exc))))
        # identity mismatches (each field, either side of the value)
        for name, over in [
            ("id-aaa", {"detector_id": "aaa"}),
            ("id-zzz", {"detector_id": "zzz"}),
            ("ver-099", {"detector_version": "0.9.9"}),
            ("ver-200", {"detector_version": "2.0.0"}),
            ("cal-aaa", {"calibration_id": "aaa"}),
            ("cal-zzz", {"calibration_id": "zzz"}),
        ]:
            try:
                mgr.store(detector_id="det1", detector_version="1.0",
                          curve=T.platt_curve(), calibration_id="cal1",
                          created_at="2024-01-01T00:00:00+00:00",
                          identity=_cal_identity(**over), **T.eligible_artifact_kwargs())
                rows.append((f"store-{name}", ("ok", "stored")))
            except Exception as exc:  # noqa: BLE001
                rows.append((f"store-{name}", ("raise", type(exc).__name__, str(exc))))
        # calibration_id None vs set (identity carries cal1)
        try:
            art = mgr.store(detector_id="det1", detector_version="1.0",
                            curve=T.platt_curve(), created_at="2024-01-01T00:00:00+00:00",
                            identity=ident, **T.eligible_artifact_kwargs())
            rows.append(("store-cal-none", ("ok", art.calibration_id)))
        except Exception as exc:  # noqa: BLE001
            rows.append(("store-cal-none", ("raise", type(exc).__name__, str(exc))))
        # explicit identity-field mismatches (provider/model/config/semantics/regime)
        for name, field, value in [
            ("prov-aaa", "provider", "aaa"), ("prov-zzz", "provider", "zzz"),
            ("model-aaa", "model", "aaa"), ("model-zzz", "model", "zzz"),
            ("semantics-aaa", "native_score_semantics", "aaa"),
            ("semantics-zzz", "native_score_semantics", "zzz"),
            ("regime-aaa", "regime", "aaa"), ("regime-zzz", "regime", "zzz"),
        ]:
            try:
                mgr.store(detector_id="det1", detector_version="1.0",
                          curve=T.platt_curve(), calibration_id="cal1",
                          created_at="2024-01-01T00:00:00+00:00", identity=ident,
                          **{**T.eligible_artifact_kwargs(), field: value})
                rows.append((f"store-{name}", ("ok", "stored")))
            except Exception as exc:  # noqa: BLE001
                rows.append((f"store-{name}", ("raise", type(exc).__name__, str(exc))))
        # getters on the stored artifact
        for name, fn in [
            ("score-match", lambda: mgr.get_calibrated_score("det1", 0.7, identity=ident)),
            ("score-id-zzz", lambda: mgr.get_calibrated_score("zzz", 0.7, identity=ident)),
            ("score-id-aaa", lambda: mgr.get_calibrated_score("aaa", 0.7, identity=ident)),
            ("score-id-distinct", lambda: mgr.get_calibrated_score("".join(["d", "e", "t", "1"]), 0.7, identity=ident)),
            ("score-no-identity", lambda: mgr.get_calibrated_score("det1", 0.7)),
            ("result-match", lambda: mgr.get_calibrated_result("det1", 0.7, identity=ident)),
            ("result-id-zzz", lambda: mgr.get_calibrated_result("zzz", 0.7, identity=ident)),
            ("result-unvalidated", lambda: mgr.get_calibrated_score("det1", 0.7, identity=ident, allow_unvalidated=True)),
            ("score-for-identity", lambda: mgr.get_calibrated_score_for_identity(ident, 0.7)),
            ("score-for-identity-zzz", lambda: mgr.get_calibrated_score_for_identity(_cal_identity(detector_id="zzz"), 0.7)),
            ("result-for-identity", lambda: mgr.get_calibrated_result_for_identity(ident, 0.7)),
        ]:
            rows.append((name, outcome(fn)))
    return rows


# ---------------------------------------------------------------------------
# calibration InferenceIdentity / content hash / EvaluationResult (new probe)
# ---------------------------------------------------------------------------
def probe_cal_identity():
    import dataclasses
    from textforensics.calibration import InferenceIdentity, EvaluationResult
    import test_calibration as T
    rows = []
    # from_dict as a classmethod (called on the class, not an instance)
    rows.append(("from-dict-class", outcome(InferenceIdentity.from_dict, {
        "detector_id": "det1", "detector_version": "1.0", "provider": "local",
        "model": "m", "config_hash": T.hex64(5),
        "native_score_semantics": "probability_higher_means_ai",
        "regime": "unedited", "calibration_id": "cal1"})))
    rows.append(("from-dict-nonmapping", outcome(InferenceIdentity.from_dict, ["x"])))
    ident = _cal_identity()
    # frozen: assignment must raise
    def _assign():
        ident.provider = "other"
        return ident.provider
    rows.append(("frozen-assign", outcome(_assign)))
    rows.append(("slots-no-dict", outcome(lambda: hasattr(ident, "__dict__"))))
    # EvaluationResult default overlap_count
    rows.append(("evalresult-default", outcome(lambda: EvaluationResult(
        threshold=0.5, tp=4, fp=0, tn=4, fn=0, accuracy=1.0, fpr=0.0,
        fnr=0.0, tpr=1.0, specificity=1.0, precision=1.0, evaluated=8,
        test_dataset_hash="a" * 64, calibration_dataset_hash="b" * 64).overlap_count)))
    # content hash: valid, then tampered stored hash (either side + distinct object)
    art = T.eligible_artifact()
    rows.append(("hash-valid", outcome(art.check_content_hash)))
    computed = art.compute_content_hash()
    rows.append(("hash-computed", ("ok", computed == art.content_hash)))
    for name, value in [("stored-less", "0" * 64), ("stored-greater", "f" * 64),
                        ("stored-distinct", "".join(computed))]:
        tampered = dataclasses.replace(art)
        object.__setattr__(tampered, "content_hash", value)
        rows.append((f"hash-{name}", outcome(tampered.check_content_hash)))
    # _content_payload: all identity fields None vs some set
    art_no_ident = dataclasses.replace(art)
    for _f in ("provider", "model", "config_hash", "native_score_semantics", "regime"):
        object.__setattr__(art_no_ident, _f, None)
    rows.append(("payload-all-none", outcome(lambda: sorted(art_no_ident._content_payload().keys()))))
    rows.append(("payload-some-set", outcome(lambda: sorted(art._content_payload().keys()))))
    rows.append(("payload-missing-field", outcome(lambda: "provider" in art_no_ident._content_payload())))
    # _identity_issues: missing fields, direction in/out of set, semantics mismatch
    rows.append(("issues-complete", outcome(art._identity_issues)))
    rows.append(("issues-missing", outcome(art_no_ident._identity_issues)))
    def _with_semantics(value):
        a = dataclasses.replace(art)
        object.__setattr__(a, "native_score_semantics", value)
        return a._identity_issues()
    rows.append(("issues-semantics-before", outcome(_with_semantics, "aaa")))
    rows.append(("issues-semantics-after", outcome(_with_semantics, "zzz")))
    rows.append(("issues-semantics-equal", outcome(_with_semantics, "probability_higher_means_ai")))
    return rows


# ---------------------------------------------------------------------------
# explain.summary / to_dict (new probe, W2-F kill tests)
# ---------------------------------------------------------------------------
def _explain_report():
    from textforensics.explain import CounterfactualExplainer
    # additive score_fn: pushes_ai / pushes_human / neutral segments
    def score_fn(text):
        total = 0.0
        for word in text.split():
            if word in ("ai", "machine", "robot"):
                total += 0.5
            elif word in ("human", "person", "hand"):
                total -= 0.5
        return total
    expl = CounterfactualExplainer(score_fn, detector_id="d", detector_version="1")
    long_ai = ("ai machine robot " * 12).strip()
    long_human = ("human person hand " * 12).strip()
    neutral = ("the quick brown fox jumps over the lazy dog " * 3).strip()
    text = long_ai + ". " + long_human + ". " + neutral + "."
    return expl.explain(text)


def _scrub_report(d):
    import copy
    d = copy.deepcopy(d)
    d.pop("created_at", None)
    return d


def probe_explain_summary():
    import dataclasses
    rows = []
    rep = _explain_report()
    for name, fn in [
        ("summary-default", lambda: rep.summary()),
        ("summary-raw", lambda: rep.summary(include_raw_text=True)),
        ("dict-default", lambda: rep.to_dict()),
        ("dict-raw", lambda: rep.to_dict(include_raw_text=True)),
    ]:
        rows.append((name, outcome(lambda fn=fn: _scrub_report(fn()))))
    # completeness=None report (direct dataclass construction)
    rep2 = dataclasses.replace(rep, completeness=None)
    for name, fn in [
        ("summary-nocomp", lambda: rep2.summary()),
        ("summary-nocomp-raw", lambda: rep2.summary(include_raw_text=True)),
        ("dict-nocomp", lambda: rep2.to_dict()),
        ("dict-nocomp-raw", lambda: rep2.to_dict(include_raw_text=True)),
    ]:
        rows.append((name, outcome(lambda fn=fn: _scrub_report(fn()))))
    # 4-segment report: 2 ai-driving + 1 human-driving + 1 neutral
    from textforensics.explain import CounterfactualExplainer as _CE
    expl4 = _CE(lambda t: sum(0.5 if w in ("ai", "machine", "robot") else -0.5 if w in ("human", "person", "hand") else 0.0 for w in t.split()), detector_id="d", detector_version="1")
    text4 = ("ai machine robot " * 12).strip() + ". " + ("ai robot machine " * 12).strip() + ". " + ("human person hand " * 12).strip() + ". " + ("the quick brown fox jumps over the lazy dog " * 3).strip() + "."
    rep4 = expl4.explain(text4)
    for name, fn in [
        ("summary-4seg", lambda: rep4.summary()),
        ("summary-4seg-raw", lambda: rep4.summary(include_raw_text=True)),
        ("dict-4seg", lambda: rep4.to_dict()),
        ("dict-4seg-raw", lambda: rep4.to_dict(include_raw_text=True)),
    ]:
        rows.append((name, outcome(lambda fn=fn: _scrub_report(fn()))))
    # empty-attribution report (all-neutral text -> no top entries)
    from textforensics.explain import CounterfactualExplainer
    expl = CounterfactualExplainer(lambda t: 0.0, detector_id="d", detector_version="1")
    rep3 = expl.explain("the quick brown fox jumps over the lazy dog. " * 3)
    for name, fn in [
        ("summary-neutral", lambda: rep3.summary()),
        ("summary-neutral-raw", lambda: rep3.summary(include_raw_text=True)),
        ("dict-neutral", lambda: rep3.to_dict()),
    ]:
        rows.append((name, outcome(lambda fn=fn: _scrub_report(fn()))))
    return rows


# ---------------------------------------------------------------------------
# benchmark._sample_and_group_hashes / check_disjointness (new probes)
# ---------------------------------------------------------------------------
def probe_bm_sample_hashes():
    import tempfile, json
    from pathlib import Path
    from textforensics.benchmark import _sample_and_group_hashes
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        files = {
            "valid": [{"label": "human", "text": "Alpha sentence."},
                      {"label": "ai", "text": "Beta sentence."},
                      {"label": "human", "text": "Gamma sentence.", "source_document_id": "doc1"},
                      {"label": "ai", "text": "Delta sentence.", "document_id": "doc1"},
                      {"label": "human", "text": "Epsilon sentence.", "group_id": "g7"},
                      {"label": "ai", "text": "Zeta sentence.", "source_id": "s9"}],
            "nonascii": [{"label": "human", "text": "Café naïve façade."},
                         {"label": "ai", "text": "Über résumé."}],
            "nontext": [{"label": "human", "text": 123},
                        {"label": "ai", "text": ["a", "b"]}],
            "empty": [],
        }
        for name, data in files.items():
            p = tmp / f"{name}.jsonl"
            p.write_text("".join(json.dumps(r) + "\n" for r in data), encoding="utf-8")
            rows.append((name, outcome(_sample_and_group_hashes, p)))
        # malformed lines (strict True/False), non-dict rows, blank lines
        bad = tmp / "bad.jsonl"
        bad.write_text('{"label": "human", "text": "Good one."}\nNOT JSON\n[1, 2]\n{"label": "ai", "text": "After bad."}\n\n', encoding="utf-8")
        rows.append(("bad-strict", outcome(_sample_and_group_hashes, bad, strict=True)))
        rows.append(("bad-lenient", outcome(_sample_and_group_hashes, bad, strict=False)))
        missing = tmp / "nope.jsonl"
        try:
            _sample_and_group_hashes(missing)
            rows.append(("missing", ("ok", "no-raise")))
        except Exception as exc:  # noqa: BLE001
            rows.append(("missing", ("raise", type(exc).__name__,
                                     str(exc).replace(str(tmp), "TMP"))))
        # group-id precedence: first non-empty group field wins
        prec = tmp / "prec.jsonl"
        prec.write_text(json.dumps({"label": "human", "text": "T.", "source_document_id": " ", "document_id": "d2"}) + "\n", encoding="utf-8")
        rows.append(("group-precedence", outcome(_sample_and_group_hashes, prec)))
        # same text, different case/whitespace -> same group hash
        norm = tmp / "norm.jsonl"
        norm.write_text(json.dumps({"label": "human", "text": "  Hello   WORLD. "}) + "\n" + json.dumps({"label": "ai", "text": "hello world."}) + "\n", encoding="utf-8")
        rows.append(("group-normalized", outcome(_sample_and_group_hashes, norm)))
        # --- strict default (no strict arg) on a bad file ------------------
        rows.append((("bad-default-strict", outcome(_sample_and_group_hashes, bad))))
        # --- blank line in the middle (continue vs break) ------------------
        mid_blank = tmp / "midblank.jsonl"
        mid_blank.write_text('{"label": "human", "text": "First."}\n\n{"label": "ai", "text": "Second."}\n',
                             encoding="utf-8")
        rows.append((("blank-middle", outcome(_sample_and_group_hashes, mid_blank))))
        # --- dict text (sort_keys) + non-ASCII dict text (ensure_ascii) ---
        dicttext = tmp / "dicttext.jsonl"
        dicttext.write_text(json.dumps({"label": "human", "text": {"b": 1, "a": 2}}) + "\n"
                            + json.dumps({"label": "ai", "text": {"k": "café", "a": "x"}}) + "\n",
                            encoding="utf-8")
        rows.append((("dict-text", outcome(_sample_and_group_hashes, dicttext))))
        # --- two group fields set (break vs continue in the field loop) ---
        two_groups = tmp / "twogroups.jsonl"
        two_groups.write_text(json.dumps({"label": "human", "text": "T1.",
                                          "source_document_id": "d1",
                                          "document_id": "d2"}) + "\n"
                              + json.dumps({"label": "ai", "text": "T2.",
                                            "group_id": "g1", "source_id": "s1"}) + "\n",
                              encoding="utf-8")
        rows.append((("two-group-fields", outcome(_sample_and_group_hashes, two_groups))))
    return rows


def probe_bm_check_disjointness():
    import tempfile
    from pathlib import Path
    from textforensics.benchmark import check_disjointness, fingerprint_dataset
    import test_benchmark as TB
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        a = tmp / "a.jsonl"
        b = tmp / "b.jsonl"
        empty = tmp / "empty.jsonl"
        TB.write_dataset(a)
        TB.write_dataset(b, human_suffix=" eval", ai_suffix=" eval")
        empty.write_text("", encoding="utf-8")
        fp_a = fingerprint_dataset(a, "A")
        fp_b = fingerprint_dataset(b, "B")
        fp_e = fingerprint_dataset(empty, "E")
        for name, p1, f1, p2, f2, kwargs in [
            ("disjoint", a, fp_a, b, fp_b, {}),
            ("self", a, fp_a, a, fp_a, {}),
            ("empty-vs-a", empty, fp_e, a, fp_a, {}),
            ("a-vs-empty", a, fp_a, empty, fp_e, {}),
            ("empty-vs-empty", empty, fp_e, empty, fp_e, {}),
            ("missing", tmp / "nope.jsonl", fp_a, b, fp_b, {}),
            ("missing2", a, fp_a, tmp / "nope.jsonl", fp_b, {}),
        ]:
            try:
                out = check_disjointness(p1, f1, p2, f2, **kwargs)
                rows.append((name, ("ok", out["disjoint"], out["shared_samples"],
                                    sorted(out["shared_hashes"]), out["verified"],
                                    sorted(e.replace(str(tmp), "TMP") for e in out["errors"]),
                                    sorted(w.replace(str(tmp), "TMP") for w in out["warnings"]),
                                    out["proof"]["status"], out["proof"]["overlap_count"],
                                    out["proof"]["training_count"],
                                    out["proof"]["evaluation_count"],
                                    out["proof"]["group_overlap_count"])))
            except Exception as exc:  # noqa: BLE001
                rows.append((name, ("raise", type(exc).__name__,
                                    str(exc).replace(str(tmp), "TMP"))))
    return rows


# ---------------------------------------------------------------------------
# observatory._normalize_observation / _validate_score_range /
# _validate_snapshot_schema / _observation_from_prediction (new probe)
# ---------------------------------------------------------------------------
def _obs_corpus():
    from textforensics.observatory import DriftObservatory
    corpus = {"schema": "textforensics.drift-corpus/v1",
              "samples": [{"id": "s1", "text": "synthetic probe sentence one."},
                          {"id": "s2", "text": "synthetic probe sentence two."}]}
    return DriftObservatory(corpus=corpus)


def _obs_valid(obs, **over):
    base = {"sample_id": "s1", "detector_id": "d", "detector_version": "0.1.0",
            "detector_family": "f", "execution": "local", "score": 0.1,
            "score_semantics": "lower means more machine-like",
            "verdict": "ai_like", "threshold": 0.2,
            "native_score_direction": "lower_means_ai", "score_range": [-5.0, 5.0],
            "observed_at": "2026-01-01T00:00:00+00:00"}
    base.update(over)
    return base


def _scrub_path(value, tmp):
    if isinstance(value, tuple) and len(value) == 3 and value[0] == "raise":
        return (value[0], value[1], value[2].replace(tmp, "TMP"))
    return value


def _scrub_time(value):
    import re
    if isinstance(value, str):
        return re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+00:00|Z)?", "TIME", value)
    if isinstance(value, dict):
        return {k: _scrub_time(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_time(v) for v in value]
    return value


def probe_obs_normalize():
    from textforensics.observatory import _validate_score_range, DRIFT_SNAPSHOT_SCHEMA
    obs = _obs_corpus()
    real_sha = obs.samples["s1"].text_sha256
    rows = []
    cases = [
        ("valid", _obs_valid(obs)),
        ("no-observed-at", {k: v for k, v in _obs_valid(obs).items() if k != "observed_at"}),
        ("observed-at-set", _obs_valid(obs, observed_at="2025-06-01T12:00:00+00:00")),
        ("sha-before", _obs_valid(obs, text_sha256="0" * 64)),
        ("sha-after", _obs_valid(obs, text_sha256="f" * 64)),
        ("sha-distinct", _obs_valid(obs, text_sha256="".join(real_sha))),
        ("sha-badhex", _obs_valid(obs, text_sha256="g" * 64)),
        ("sha-short", _obs_valid(obs, text_sha256="a" * 63)),
        ("score-neg", _obs_valid(obs, score=-0.5)),
        ("score-mid", _obs_valid(obs, score=0.5)),
        ("score-over", _obs_valid(obs, score=1.5)),
        ("reliability-neg", _obs_valid(obs, reliability=-0.5)),
        ("reliability-mid", _obs_valid(obs, reliability=0.5)),
        ("reliability-over", _obs_valid(obs, reliability=1.5)),
        ("calibrated-neg", _obs_valid(obs, calibrated_ai_probability=-0.5, calibration_id="c1")),
        ("calibrated-mid", _obs_valid(obs, calibrated_ai_probability=0.5, calibration_id="c1")),
        ("calibrated-over", _obs_valid(obs, calibrated_ai_probability=1.5, calibration_id="c1")),
        ("calibrated-no-id", _obs_valid(obs, calibrated_ai_probability=0.5)),
        ("calibration-id-only", _obs_valid(obs, calibration_id="c1")),
        ("lang-unsupported", _obs_valid(obs, supported_languages=["xx"])),
        ("lang-empty", _obs_valid(obs, supported_languages=[""])),
        ("lang-mixed-empty", _obs_valid(obs, supported_languages=["en", ""])),
        ("lang-ok", _obs_valid(obs, supported_languages=["en", "fr"])),
        ("lang-not-list", _obs_valid(obs, supported_languages="en")),
        ("score-range-eq", _obs_valid(obs, score_range=[0.0, 0.0])),
        ("score-range-lo", _obs_valid(obs, score_range=[0.0, 1.0])),
        ("score-range-hi", _obs_valid(obs, score_range=[-1.0, 0.0])),
        ("score-range-none", _obs_valid(obs, score_range=None)),
        ("not-mapping", "x"),
        ("unknown-sample", _obs_valid(obs, sample_id="s9")),
    ]
    for name, ob in cases:
        try:
            rows.append((name, ("ok", _scrub_time(obs._normalize_observation(ob)))))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    # _validate_score_range
    for name, value in [
        ("range-none", None), ("range-ok", [0.0, 1.0]), ("range-len1", [0.0]),
        ("range-len3", [0.0, 0.5, 1.0]), ("range-not-list", "x"),
        ("range-lo-none", [None, 1.0]), ("range-hi-none", [0.0, None]),
        ("range-eq", [1.0, 1.0]), ("range-eq-distinct", [float("1.0"), float("1.0")]),
        ("range-reversed", [1.0, 0.0]), ("range-bool", [True, 1.0]),
        ("range-str", ["0", "1"]), ("range-nan", [float("nan"), 1.0]),
    ]:
        rows.append((name, outcome(_validate_score_range, value)))
    # _validate_snapshot_schema
    for name, snap in [
        ("snap-valid", {"schema": DRIFT_SNAPSHOT_SCHEMA, "records": [], "failures": []}),
        ("snap-records", {"schema": DRIFT_SNAPSHOT_SCHEMA,
                          "records": [{"native_score_direction": "higher_means_ai",
                                       "score_range": [0.0, 1.0]}], "failures": []}),
        ("snap-no-direction", {"schema": DRIFT_SNAPSHOT_SCHEMA,
                               "records": [{"score_range": [0.0, 1.0]}], "failures": []}),
        ("snap-no-range", {"schema": DRIFT_SNAPSHOT_SCHEMA,
                           "records": [{"native_score_direction": "lower_means_ai"}], "failures": []}),
        ("snap-bad-schema", {"schema": "textforensics.drift-snapshot/v9", "records": []}),
        ("snap-old-schema", {"schema": "textforensics.drift-snapshot/v1", "records": []}),
        ("snap-records-not-list", {"schema": DRIFT_SNAPSHOT_SCHEMA, "records": "x"}),
        ("snap-record-not-obj", {"schema": DRIFT_SNAPSHOT_SCHEMA, "records": ["x"]}),
        ("snap-bad-direction", {"schema": DRIFT_SNAPSHOT_SCHEMA,
                                "records": [{"native_score_direction": "sideways"}]}),
        ("snap-bad-range", {"schema": DRIFT_SNAPSHOT_SCHEMA,
                            "records": [{"score_range": [1.0, 0.0]}]}),
    ]:
        rows.append((name, outcome(obs._validate_snapshot_schema, snap)))
    # _observation_from_prediction (score_range set vs None)
    from textforensics.detectors import DetectorPrediction
    sample = obs.samples["s1"]
    from types import SimpleNamespace
    det = SimpleNamespace(detector_id="d", detector_version="0.1.0", detector_family="f")
    for name, score_range, direction in [
        ("pred-range", [-5.0, 5.0], "lower_means_ai"),
        ("pred-no-range", None, "lower_means_ai"),
        ("pred-no-direction", [-5.0, 5.0], None),
    ]:
        pred = DetectorPrediction(schema="textforensics.detector-result/v2",
                                  detector_id="d", detector_version="0.1.0",
                                  detector_family="f", execution="local",
                                  score=0.1, score_semantics="s", verdict="ai_like",
                                  threshold=0.2)
        object.__setattr__(pred, "native_score_direction", direction)
        object.__setattr__(pred, "score_range", score_range)
        rows.append((name, outcome(lambda p=pred: _scrub_time(obs._observation_from_prediction(sample, det, p)))))
    return rows


# ---------------------------------------------------------------------------
# model_card from_dict helpers / to_json / to_markdown / load (new probe)
# ---------------------------------------------------------------------------
def _mc_full_card():
    import test_model_card as T
    return T.TestModelCardLoad()._full_card()


def probe_mc_from_dict():
    import copy, tempfile
    from pathlib import Path
    from textforensics.model_card import (
        ModelCard, _evaluation_dataset_from_dict, _metric_from_dict,
        _quantitative_analysis_from_dict, _training_data_from_dict,
        _mc_int, _mc_number, _mc_opt_number, load_model_card)
    card = _mc_full_card()
    d = card.to_dict()
    eval_d = d["evaluation_data"]
    metric_d = d["quantitative_analysis"]["metrics"][0]
    quant_d = d["quantitative_analysis"]
    train_d = d["training_data"]
    rows = []
    # _evaluation_dataset_from_dict: split ratios
    for name, ratios in [
        ("eval-valid", {"train": 0.8, "test": 0.2}),
        ("eval-bool", {"train": True, "test": 0.2}),
        ("eval-str", {"train": "0.8", "test": 0.2}),
        ("eval-neg", {"train": -0.5, "test": 1.5}),
        ("eval-zero", {"train": 0.0, "test": 1.0}),
        ("eval-one", {"train": 1.0, "test": 0.0}),
        ("eval-over", {"train": 1.5, "test": -0.5}),
        ("eval-sum-1e-6", {"train": 0.8 + 1e-6, "test": 0.2}),
        ("eval-sum-2e-6", {"train": 0.8 + 2e-6, "test": 0.2}),
        ("eval-sum-low", {"train": 0.8, "test": 0.1}),
        ("eval-sum-empty", {}),
        ("eval-sum-3way", {"train": 0.7, "val": 0.2, "test": 0.1}),
    ]:
        m = copy.deepcopy(eval_d)
        m["split_ratios"] = ratios
        rows.append((name, outcome(_evaluation_dataset_from_dict, m)))
    # _metric_from_dict: CI shapes
    for name, over in [
        ("metric-valid", {}),
        ("metric-ci-len1", {"confidence_interval": [0.9]}),
        ("metric-ci-len3", {"confidence_interval": [0.9, 0.95, 0.99]}),
        ("metric-ci-bool", {"confidence_interval": [True, 0.95]}),
        ("metric-ci-str", {"confidence_interval": ["0.9", 0.95]}),
        ("metric-ci-reversed", {"confidence_interval": [0.97, 0.93]}),
        ("metric-ci-eq", {"confidence_interval": [0.95, 0.95]}),
        ("metric-ci-none", {"confidence_interval": None}),
        ("metric-split-set", {"split": "train"}),
        ("metric-split-missing", {"split": None}),
    ]:
        m = copy.deepcopy(metric_d)
        if "split" in over and over["split"] is None:
            m.pop("split", None)
        else:
            m.update(over)
        rows.append((name, outcome(_metric_from_dict, m)))
    # _quantitative_analysis_from_dict: confusion values
    for name, cm in [
        ("quant-valid", {"tp": 90, "fp": 5, "tn": 95, "fn": 10}),
        ("quant-zero", {"tp": 0, "fp": 0, "tn": 0, "fn": 0}),
        ("quant-neg", {"tp": -1, "fp": 5, "tn": 95, "fn": 10}),
        ("quant-bool", {"tp": True, "fp": 5, "tn": 95, "fn": 10}),
        ("quant-none", None),
    ]:
        m = copy.deepcopy(quant_d)
        m["confusion_matrix"] = cm
        rows.append((name, outcome(_quantitative_analysis_from_dict, m)))
    # _training_data_from_dict: total_size + optional lists
    for name, over in [
        ("train-valid", {}),
        ("train-size-0", {"total_size": 0}),
        ("train-size-neg", {"total_size": -1}),
        ("train-no-aug", {"augmentation_techniques": None}),
        ("train-no-biases", {"known_biases": None}),
        ("train-no-both", {"augmentation_techniques": None, "known_biases": None}),
    ]:
        m = copy.deepcopy(train_d)
        m.update(over)
        rows.append((name, outcome(_training_data_from_dict, m)))
    # _mc_int / _mc_number / _mc_opt_number
    for name, fn in [
        ("mc-int-ok", lambda: _mc_int({"size": 5}, "size", "w")),
        ("mc-int-bool", lambda: _mc_int({"size": True}, "size", "w")),
        ("mc-int-str", lambda: _mc_int({"size": "5"}, "size", "w")),
        ("mc-int-float", lambda: _mc_int({"size": 5.0}, "size", "w")),
        ("mc-int-neg", lambda: _mc_int({"size": -1}, "size", "w", minimum=0)),
        ("mc-num-ok", lambda: _mc_number({"v": 0.5}, "v", "w")),
        ("mc-num-bool", lambda: _mc_number({"v": True}, "v", "w")),
        ("mc-num-str", lambda: _mc_number({"v": "x"}, "v", "w")),
        ("mc-num-nan-str", lambda: _mc_number({"v": "nan"}, "v", "w")),
        ("mc-opt-ok", lambda: _mc_opt_number({"v": 0.5}, "v", "w")),
        ("mc-opt-none", lambda: _mc_opt_number({"v": None}, "v", "w")),
        ("mc-opt-bool", lambda: _mc_opt_number({"v": True}, "v", "w")),
        ("mc-opt-str", lambda: _mc_opt_number({"v": "x"}, "v", "w")),
    ]:
        rows.append((name, outcome(fn)))
    # from_dict schema_version
    for name, ver in [("fromdict-100", "1.0.0"), ("fromdict-090", "0.9.0"),
                      ("fromdict-200", "2.0.0"), ("fromdict-missing", None)]:
        m = copy.deepcopy(d)
        if ver is None:
            m.pop("schema_version", None)
        else:
            m["schema_version"] = ver
        rows.append((name, outcome(ModelCard.from_dict, m)))
    # to_json: indent + non-ASCII
    rows.append(("json-indent2", outcome(card.to_json, 2)))
    rows.append(("json-indent3", outcome(card.to_json, 3)))
    rows.append(("json-indent1", outcome(card.to_json, 1)))
    import dataclasses
    card_na = dataclasses.replace(card.model_details, name="Café Détecteur")
    card2 = dataclasses.replace(card, model_details=card_na)
    rows.append(("json-nonascii", outcome(card2.to_json)))
    # to_markdown: full vs stripped sections
    rows.append(("md-full", outcome(card.to_markdown)))
    card_nom = dataclasses.replace(card, metrics=[], ethical_considerations=[],
                                   caveats_and_recommendations=[],
                                   eu_ai_act_transparency_notes={})
    rows.append(("md-stripped", outcome(card_nom.to_markdown)))
    card_noci = dataclasses.replace(card, metrics=[
        dataclasses.replace(card.metrics[0], confidence_interval=None)])
    rows.append(("md-no-ci", outcome(card_noci.to_markdown)))
    # load: missing file (scrub the tmp path from the error message)
    with tempfile.TemporaryDirectory() as tmp:
        rows.append(("load-missing", _scrub_path(outcome(load_model_card, Path(tmp) / "nope.json"), tmp)))
        p = Path(tmp) / "card.json"
        p.write_text(card.to_json(), encoding="utf-8")
        rows.append(("load-valid", outcome(lambda: load_model_card(p).model_details.name)))
        bad = Path(tmp) / "bad.json"
        bad.write_text("not json {", encoding="utf-8")
        rows.append(("load-badjson", _scrub_path(outcome(load_model_card, bad), tmp)))
        nan = Path(tmp) / "nan.json"
        nan.write_text('{"schema_version": "1.0.0", "x": NaN}', encoding="utf-8")
        rows.append(("load-nan", _scrub_path(outcome(load_model_card, nan), tmp)))
    return rows


# ---------------------------------------------------------------------------
# evidence._verification_row_ok / _record_candidate / _worst_fpr_dimension /
# records_for / InferenceIdentity+DisjointnessProof / coverage_for_predictions
# (new probes)
# ---------------------------------------------------------------------------
def probe_ev_row_ok():
    from textforensics.evidence import RegistryVerification, _verification_row_ok
    ver = RegistryVerification(verified=True, errors=(),
                               records={"ev1": {"ok": True},
                                        "ev2": {"ok": False, "errors": ["bad sha"]},
                                        "ev3": {"ok": False},
                                        "ev4": True,
                                        "ev5": False,
                                        "ev6": "not-a-row",
                                        "ev7": {"ok": True, "errors": ["ignored"]}},
                               checked_at_utc="2026-01-01T00:00:00+00:00")
    rows = []
    for name, av, eid in [
        ("none", None, "ev1"),
        ("unsupported-int", 42, "ev1"),
        ("unsupported-list", [], "ev1"),
        ("ver-ok", ver, "ev1"),
        ("ver-fail-errors", ver, "ev2"),
        ("ver-fail-noerr", ver, "ev3"),
        ("ver-bool-true", ver, "ev4"),
        ("ver-bool-false", ver, "ev5"),
        ("ver-malformed", ver, "ev6"),
        ("ver-ok-errors", ver, "ev7"),
        ("ver-missing", ver, "ev9"),
        ("map-ok", {"ev1": True}, "ev1"),
        ("map-false", {"ev1": False}, "ev1"),
        ("map-dict-ok", {"ev1": {"ok": True}}, "ev1"),
        ("map-dict-fail", {"ev1": {"ok": False, "errors": ["e1", "e2"]}}, "ev1"),
        ("map-dict-nook", {"ev1": {"errors": ["e1"]}}, "ev1"),
        ("map-missing", {"ev1": True}, "ev9"),
        ("map-malformed", {"ev1": 3}, "ev1"),
    ]:
        rows.append((name, outcome(_verification_row_ok, av, eid)))
    return rows


def probe_ev_record_candidate2():
    from datetime import datetime, UTC
    from textforensics.evidence import _record_candidate, SliceMatch
    now = datetime(2026, 11, 11, tzinfo=UTC)
    rows = []
    match_all = SliceMatch(language="match", length="match", domain="match",
                           editing="match", applicable=True)
    match_mix = SliceMatch(language="match", length="mismatch", domain="unknown",
                           editing="match", applicable=True)
    for name, dim, match, eligible, reasons in [
        ("supported-default", "language", match_all, None, ()),
        ("supported-eligible", "language", match_all, True, ()),
        ("supported-ineligible", "language", match_all, False, ("stale",)),
        ("supported-ineligible-2reasons", "language", match_all, False, ("stale", "no-proof")),
        ("partial-ineligible", "language", match_mix, False, ("stale",)),
        ("unknown-ineligible", "human_false_positive_evidence", match_mix, False, ("stale",)),
        ("text-length-ineligible", "text_length", match_all, False, ("stale",)),
    ]:
        record = _ev_record(evaluated_at="2026-11-01T00:00:00Z", n_human=120, n_ai=120)
        slice_ = _ev_slice(n_human=120, n_ai=120)
        kwargs = dict(record=record, slice_=slice_, match=match, now=now,
                      max_age_days=30, dimension=dim, fpr_ceiling=0.05)
        if eligible is not None:
            kwargs["eligible"] = eligible
            kwargs["ineligibility_reasons"] = reasons
        try:
            cand = _record_candidate(**kwargs)
            if cand is None:
                rows.append((name, ("ok", None)))
            else:
                rows.append((name, ("ok", cand.state, cand.reason, cand.limitations)))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    # candidate None + ineligible (dimension with no candidate: out-of-scope slice)
    record = _ev_record(evaluated_at="2026-11-01T00:00:00Z", n_human=120, n_ai=120)
    slice_ = _ev_slice(n_human=120, n_ai=120)
    nomatch = SliceMatch(language="mismatch", length="mismatch", domain="mismatch",
                         editing="mismatch", applicable=False)
    try:
        cand = _record_candidate(record=record, slice_=slice_, match=nomatch, now=now,
                                 max_age_days=30, dimension="language", fpr_ceiling=0.05,
                                 eligible=False, ineligibility_reasons=("stale",))
        rows.append(("none-ineligible", ("ok", None if cand is None else cand.state)))
    except Exception as exc:  # noqa: BLE001
        rows.append(("none-ineligible", ("raise", type(exc).__name__, str(exc))))
    return rows


def probe_ev_worst_fpr():
    from types import SimpleNamespace
    from textforensics.evidence import (
        DimensionCoverage, MetricEstimate, _worst_fpr_dimension)
    import test_audit_w2_worker_a as A
    rec = A._v2_record()
    slice_ = rec.slices[0]
    rows = []
    def _dim(state):
        return DimensionCoverage(dimension="human_false_positive_evidence",
                                 state=state, reason="base reason",
                                 evidence_refs=("ev-a-1-test",), observed={})
    def _fpr(upper, has_ci=True):
        if upper is None:
            return MetricEstimate(value=0.02, n=200, ci_lower=None, ci_upper=None)
        return MetricEstimate(value=0.02, n=200, ci_lower=0.01, ci_upper=upper)
    import dataclasses
    slice2 = dataclasses.replace(slice_, slice_id="s2")
    cases = [
        ("supported-one-below", _dim("supported"), [(rec, slice_, _fpr(0.03))], 0.05),
        ("supported-one-eq-ceiling", _dim("supported"), [(rec, slice_, _fpr(0.05))], 0.05),
        ("supported-one-above", _dim("supported"), [(rec, slice_, _fpr(0.06))], 0.05),
        ("supported-two-worst-second", _dim("supported"),
         [(rec, slice_, _fpr(0.02)), (rec, slice2, _fpr(0.04))], 0.05),
        ("supported-two-worst-first", _dim("supported"),
         [(rec, slice_, _fpr(0.04)), (rec, slice2, _fpr(0.02))], 0.05),
        ("supported-no-ci", _dim("supported"), [(rec, slice_, _fpr(None))], 0.05),
        ("supported-no-ci-flag", _dim("supported"),
         [(rec, slice_, SimpleNamespace(has_ci=False, ci_upper=0.04))], 0.05),
        ("supported-ci-upper-none", _dim("supported"),
         [(rec, slice_, SimpleNamespace(has_ci=True, ci_upper=None))], 0.05),
        ("supported-none-fpr", _dim("supported"), [(rec, slice_, None)], 0.05),
        ("supported-empty", _dim("supported"), [], 0.05),
        ("partial-one-above", _dim("partial"), [(rec, slice_, _fpr(0.09))], 0.05),
        ("unknown-one-above", _dim("unknown"), [(rec, slice_, _fpr(0.09))], 0.05),
        ("partial-empty", _dim("partial"), [], 0.05),
        ("supported-missing-plus-ok", _dim("supported"),
         [(rec, slice_, _fpr(0.02)), (rec, slice2, None)], 0.05),
    ]
    for name, dim, pairs, ceiling in cases:
        try:
            out = _worst_fpr_dimension(dim, pairs, fpr_ceiling=ceiling)
            rows.append((name, ("ok", out.state, out.reason,
                                sorted(out.observed.items(), key=lambda kv: str(kv[0])))))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    return rows


def probe_ev_records_for():
    import test_audit_w2_worker_a as A
    from textforensics.evidence import EvidenceRegistry
    recs = [
        A._v2_record(detector_id="zzz", detector_version="2"),
        A._v2_record(detector_id="aaa", detector_version="1"),
        A._v2_record(detector_id="aaa", detector_version="2"),
        A._v2_record(detector_id="aaa", detector_version="*"),
        A._v2_record(detector_id="mmm", detector_version="1"),
    ]
    reg = EvidenceRegistry(recs)
    rows = []
    for name, did, ver in [
        ("aaa-unversioned", "aaa", None),
        ("aaa-v1", "aaa", "1"),
        ("aaa-v2", "aaa", "2"),
        ("aaa-vstar", "aaa", "*"),
        ("aaa-v9", "aaa", "9"),
        ("zzz-unversioned", "zzz", None),
        ("missing", "qqq", None),
        ("aaa-v1-distinct", "aaa", "".join("1")),
    ]:
        try:
            sel = reg.records_for(did, ver) if ver is not None else reg.records_for(did)
            rows.append((name, ("ok", [r.evidence_id for r in sel])))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    rows.append(("empty-id", outcome(reg.records_for, "")))
    rows.append(("ids", outcome(lambda: reg.detector_ids())))
    return rows


def probe_ev_identity_proof():
    from textforensics.evidence import DisjointnessProof, InferenceIdentity
    rows = []
    # from_dict on the class (RemoveDecorator mutant)
    rows.append(("ident-fromdict-class", outcome(InferenceIdentity.from_dict,
                                                 {"detector_id": "d", "detector_version": "1"})))
    rows.append(("proof-fromdict-class", outcome(DisjointnessProof.from_dict,
                                                 {"status": "verified", "overlap_count": 0,
                                                  "training_count": 10, "evaluation_count": 10,
                                                  "training_hash": "a" * 64,
                                                  "evaluation_hash": "b" * 64})))
    rows.append(("ident-fromdict-nonmap", outcome(InferenceIdentity.from_dict, ["x"])))
    rows.append(("proof-fromdict-nonmap", outcome(DisjointnessProof.from_dict, "x")))
    # frozen / slots
    ident = InferenceIdentity(detector_id="d", detector_version="1")
    rows.append(("ident-frozen", outcome(lambda: setattr(ident, "detector_id", "e"))))
    rows.append(("ident-slots", ("ok", hasattr(ident, "__dict__"))))
    proof = DisjointnessProof(status="unknown", overlap_count=0, training_count=0,
                              evaluation_count=0, training_hash=None, evaluation_hash=None)
    rows.append(("proof-frozen", outcome(lambda: setattr(proof, "status", "verified"))))
    rows.append(("proof-slots", ("ok", hasattr(proof, "__dict__"))))
    # __post_init__ validation
    for name, fn in [
        ("ident-empty-id", lambda: InferenceIdentity(detector_id="", detector_version="1")),
        ("ident-empty-ver", lambda: InferenceIdentity(detector_id="d", detector_version="")),
        ("ident-empty-provider", lambda: InferenceIdentity(detector_id="d", detector_version="1", provider="")),
        ("ident-provider-set", lambda: InferenceIdentity(detector_id="d", detector_version="1", provider="p")),
        ("proof-bad-status", lambda: DisjointnessProof(status="maybe", overlap_count=0,
                                                        training_count=0, evaluation_count=0,
                                                        training_hash=None, evaluation_hash=None)),
        ("proof-neg-overlap", lambda: DisjointnessProof(status="unknown", overlap_count=-1,
                                                         training_count=0, evaluation_count=0,
                                                         training_hash=None, evaluation_hash=None)),
        ("proof-neg-training", lambda: DisjointnessProof(status="unknown", overlap_count=0,
                                                          training_count=-1, evaluation_count=0,
                                                          training_hash=None, evaluation_hash=None)),
        ("proof-empty-hash", lambda: DisjointnessProof(status="unknown", overlap_count=0,
                                                       training_count=0, evaluation_count=0,
                                                       training_hash="", evaluation_hash=None)),
        ("proof-hash-set", lambda: DisjointnessProof(status="unknown", overlap_count=0,
                                                     training_count=0, evaluation_count=0,
                                                     training_hash="a" * 64, evaluation_hash=None)),
    ]:
        rows.append((name, outcome(fn)))
    return rows


def probe_ev_coverage_preds():
    import test_audit_w2_worker_a as A
    from types import SimpleNamespace
    from textforensics.evidence import EvidenceRegistry, coverage_for_predictions
    rec = A._v2_record()
    reg = EvidenceRegistry([rec])
    cond = A._v2_conditions()
    rows = []
    def _pred(**over):
        base = dict(detector_id="a", detector_version="1", detector_family="fam1",
                    supported_length={"min_words": 100, "max_words": 1000},
                    min_words=None, max_words=None)
        base.update(over)
        return SimpleNamespace(**base)
    def _summarize(covs):
        out = []
        for cov in covs:
            out.append((cov.detector_id,
                        tuple((dim, dc.state) for dim, dc in sorted(cov.dimensions.items()))))
        return out
    cases = [
        ("one-supported-length", [_pred()]),
        ("one-no-supported-length", [_pred(supported_length=None)]),
        ("one-supported-length-list", [_pred(supported_length=[100, 1000])]),
        ("one-supported-length-str", [_pred(supported_length="100-1000")]),
        ("one-empty-supported-length", [_pred(supported_length={})]),
        ("two-preds", [_pred(), _pred(detector_id="b")]),
        ("no-preds", []),
        ("min-only", [_pred(supported_length={"min_words": 100})]),
        ("max-only", [_pred(supported_length={"max_words": 1000})]),
        ("narrow-500-600", [_pred(supported_length={"min_words": 500, "max_words": 600})]),
        ("narrow-attrs", [_pred(supported_length=None, min_words=500, max_words=600)]),
        ("narrow-list", [_pred(supported_length=[500, 600], min_words=500, max_words=600)]),
    ]
    for name, preds in cases:
        try:
            covs = coverage_for_predictions(preds, cond, registry=reg)
            rows.append((name, ("ok", _summarize(covs))))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    return rows


# ---------------------------------------------------------------------------
# result_codec encode/decode/_validate (new probe)
# ---------------------------------------------------------------------------
def probe_rc_codec():
    import copy, json
    from unittest import mock
    import test_result_codec as T
    from textforensics.result_codec import CodecConfig, ResultCodec
    import textforensics.result_codec as rc
    _validate = ResultCodec()._validate
    rows = []
    bundle = copy.deepcopy(T.MINIMAL_BUNDLE)
    # encode: canonical vs non-canonical, sort_keys, ensure_ascii
    codec = ResultCodec()
    rows.append(("encode-canonical", outcome(codec.encode, bundle, "forensic-bundle")))
    codec_nc = ResultCodec(CodecConfig(canonical_json=False))
    rows.append(("encode-noncanonical", outcome(codec_nc.encode, bundle, "forensic-bundle")))
    rows.append(("encode-ascii-canonical", outcome(codec.encode, {"b": 1, "a": "café"},
                                                   "forensic-bundle", validate=False)))
    rows.append(("encode-ascii-noncanonical", outcome(codec_nc.encode, {"b": 1, "a": "café"},
                                                      "forensic-bundle", validate=False)))
    rows.append(("encode-keys-out-of-order", outcome(codec.encode, {"z": 1, "a": 2, "m": 3},
                                                     "forensic-bundle", validate=False)))
    rows.append(("encode-inf", outcome(codec.encode, {"x": float("inf")},
                                       "forensic-bundle", validate=False)))
    rows.append(("encode-nan", outcome(codec.encode, {"x": float("nan")},
                                       "forensic-bundle", validate=False)))
    # decode: validate override (config False, explicit True, invalid payload)
    codec_nv = ResultCodec(CodecConfig(validate_on_decode=False))
    bad = copy.deepcopy(bundle)
    del bad["content_sha256"]  # required property: fails validation when validated
    rows.append(("decode-validate-override", outcome(codec_nv.decode,
                                                     json.dumps(bad), "forensic-bundle",
                                                     validate=True)))
    rows.append(("decode-validate-off", outcome(codec_nv.decode,
                                                json.dumps(bad), "forensic-bundle")))
    rows.append(("decode-validate-on", outcome(codec.decode,
                                              json.dumps(bad), "forensic-bundle")))
    # decode: version comparisons under strict_version
    codec_strict = ResultCodec(CodecConfig(strict_version=True))
    v3 = copy.deepcopy(bundle)
    v3["schema"] = "textforensics.forensic-bundle/v3"
    rows.append(("decode-version-greater", outcome(codec_strict.decode,
                                                   json.dumps(v3), "forensic-bundle")))
    rows.append(("decode-version-equal", outcome(codec_strict.decode,
                                                json.dumps(bundle), "forensic-bundle")))
    noschema = copy.deepcopy(bundle)
    del noschema["schema"]
    rows.append(("decode-version-none", outcome(codec_strict.decode,
                                               json.dumps(noschema), "forensic-bundle")))
    v1 = copy.deepcopy(bundle)
    v1["schema"] = "textforensics.forensic-bundle/v1"
    rows.append(("decode-version-lower", outcome(codec_strict.decode,
                                                json.dumps(v1), "forensic-bundle")))
    # decode: nonfinite literal + non-object + invalid JSON
    rows.append(("decode-infinity", outcome(codec.decode,
                                            b'{"x": Infinity}', "forensic-bundle")))
    rows.append(("decode-nan-literal", outcome(codec.decode,
                                               b'{"x": NaN}', "forensic-bundle")))
    rows.append(("decode-list", outcome(codec.decode, b'[1, 2]', "forensic-bundle")))
    rows.append(("decode-bad-json", outcome(codec.decode, b'{oops', "forensic-bundle")))
    rows.append(("decode-str-input", outcome(codec.decode,
                                             json.dumps(bundle), "forensic-bundle")))
    # _validate: RuntimeError / ValueError from the schema validator
    with mock.patch.object(rc, "validate", side_effect=RuntimeError("boom")):
        rows.append(("validate-runtimeerror", outcome(_validate, bundle, "forensic-bundle")))
    with mock.patch.object(rc, "validate", side_effect=ValueError("bad schema")):
        rows.append(("validate-valueerror", outcome(_validate, bundle, "forensic-bundle")))
    rows.append(("validate-valid", outcome(_validate, bundle, "forensic-bundle")))
    rows.append(("validate-nonfinite", outcome(_validate, {"x": float("inf")}, "forensic-bundle")))
    return rows


# ---------------------------------------------------------------------------
# validation._common_support_blockers / _fpr_blockers / worst_fpr_upper
# (new probe)
# ---------------------------------------------------------------------------
def probe_val_common_blockers():
    import dataclasses
    from types import SimpleNamespace
    from textforensics.validation import (
        _common_support_blockers, _fpr_blockers, worst_fpr_upper)
    A = _v3()
    rows = []
    def _rec(**kw):
        return A.ValidationRecord.from_dict(A._v3_record_dict(**kw))
    # _common_support_blockers: status / samples / split_role / contamination / signature
    for name, kw in [
        ("clean", {}),
        ("status-unknown", {"status": "unknown"}),
        ("status-stale", {"status": "stale"}),
        ("status-partial", {"status": "partial"}),
        ("status-contested", {"status": "contested"}),
        ("n-human-99", {"n_human": 99}),
        ("n-human-100", {"n_human": 100}),
        ("n-human-101", {"n_human": 101}),
        ("n-ai-99", {"n_ai": 99}),
        ("n-ai-100", {"n_ai": 100}),
        ("split-fit", {"split_role": "fit"}),
        ("split-threshold", {"split_role": "threshold"}),
        ("contamination-yes", {"contamination": "yes"}),
        ("contamination-unknown", {"contamination": "unknown"}),
    ]:
        rows.append((name, outcome(_common_support_blockers, _rec(**kw),
                                   detector_version=A.V3_VERSION, now=A.NOW)))
    # split_role values rejected by from_dict ("train"/"validation") via
    # object.__setattr__ on the frozen data object (bypasses validation)
    for name, role in [("split-train", "train"), ("split-validation", "validation")]:
        rec = _rec()
        object.__setattr__(rec.data, "split_role", role)
        rows.append((name, outcome(_common_support_blockers, rec,
                                   detector_version=A.V3_VERSION, now=A.NOW)))
    # tampered signature (change n_human after sealing)
    tampered = A._v3_record_dict()
    tampered["data"]["n_human"] = 121
    rows.append(("bad-signature", outcome(_common_support_blockers,
                                          A.ValidationRecord.from_dict(tampered),
                                          detector_version=A.V3_VERSION, now=A.NOW)))
    # worst_fpr_upper / _fpr_blockers via fpr_slices
    def _fpr_rec(slices):
        return A.ValidationRecord.from_dict(A._v3_record_dict(fpr_slices=slices))
    fpr_cases = [
        ("fpr-one-below", [{"slice_id": "s1", "value": 0.02, "ci": (0.0, 0.03)}]),
        ("fpr-one-eq", [{"slice_id": "s1", "value": 0.02, "ci": (0.0, 0.05)}]),
        ("fpr-one-above", [{"slice_id": "s1", "value": 0.02, "ci": (0.0, 0.06)}]),
        ("fpr-two-worst", [{"slice_id": "s1", "value": 0.02, "ci": (0.0, 0.03)},
                           {"slice_id": "s2", "value": 0.02, "ci": (0.0, 0.04)}]),
        ("fpr-no-ci", [{"slice_id": "s1", "value": 0.02, "ci": None}]),
        ("fpr-mixed", [{"slice_id": "s1", "value": 0.02, "ci": (0.0, 0.03)},
                       {"slice_id": "s2", "value": 0.02, "ci": None}]),
    ]
    for name, slices in fpr_cases:
        rec = _fpr_rec(slices)
        rows.append((name + "-worst", outcome(worst_fpr_upper, rec)))
        rows.append((name + "-blockers", outcome(_fpr_blockers, rec, 0.05)))
    # inconsistent has_ci / ci_upper shapes via duck-typed metrics
    base = _fpr_rec([{"slice_id": "s1", "value": 0.02, "ci": (0.0, 0.03)}])
    for name, fpr in [
        ("duck-ci-true-upper-none", SimpleNamespace(has_ci=True, ci_upper=None)),
        ("duck-ci-false-upper-set", SimpleNamespace(has_ci=False, ci_upper=0.04)),
    ]:
        # duck-typed metric (bypasses the MetricEstimate __post_init__ that
        # forbids inconsistent has_ci / ci_upper shapes)
        duck_metric = SimpleNamespace(slice_id="s1", fpr_native=fpr)
        rec2 = dataclasses.replace(base, metrics=(duck_metric,))
        rows.append((name + "-worst", outcome(worst_fpr_upper, rec2)))
        rows.append((name + "-blockers", outcome(_fpr_blockers, rec2, 0.05)))
    return rows


# ---------------------------------------------------------------------------
# policy._coerce_today / _resolver_verifies / register /
# ledger_to_trust_dimension (new probe)
# ---------------------------------------------------------------------------
def probe_policy_helpers():
    from datetime import date, datetime, timezone, timedelta
    import test_trust as TT
    from textforensics.policy import (
        CapabilityClaim, CapabilityLedger, EvidenceLabel, EvidenceRef,
        EvidenceTier, _coerce_today, _resolver_verifies,
        ledger_to_trust_dimension)
    rows = []
    # _coerce_today
    for name, value in [
        ("today-none", None),
        ("today-date", date(2026, 1, 15)),
        ("today-naive", datetime(2026, 1, 15, 12, 30)),
        ("today-aware-utc", datetime(2026, 1, 15, 12, 30, tzinfo=timezone.utc)),
        ("today-aware-plus5", datetime(2026, 1, 1, 2, 0, tzinfo=timezone(timedelta(hours=5)))),
        ("today-aware-minus5", datetime(2026, 1, 1, 2, 0, tzinfo=timezone(timedelta(hours=-5)))),
        ("today-aware-plus5-midnight", datetime(2026, 1, 1, 0, 30, tzinfo=timezone(timedelta(hours=5)))),
    ]:
        rows.append((name, outcome(_coerce_today, value)))
    # _resolver_verifies
    ref = EvidenceRef(label=EvidenceLabel.EXECUTED, tier=EvidenceTier.VALIDATED,
                      artifact="runs/1.json")
    def _raising(artifact):
        raise RuntimeError("resolver boom")
    class _RaisingMap(dict):
        def get(self, key, default=None):
            raise RuntimeError("map boom")
    for name, resolver in [
        ("resolver-none", None),
        ("resolver-map-hit", {"runs/1.json": True}),
        ("resolver-map-miss", {"other.json": True}),
        ("resolver-map-false", {"runs/1.json": False}),
        ("resolver-call-true", lambda a: True),
        ("resolver-call-false", lambda a: False),
        ("resolver-call-raises", _raising),
        ("resolver-map-raises", _RaisingMap({"runs/1.json": True})),
    ]:
        rows.append((name, outcome(_resolver_verifies, resolver, ref)))
    # register: valid vs invalid claims
    valid = TT._ledger_claim()
    no_evidence = CapabilityClaim(detector_id="a", capability="language",
                                  tier=EvidenceTier.READABLE, evidence=[])
    validated_no_exec = CapabilityClaim(
        detector_id="a", capability="language", tier=EvidenceTier.VALIDATED,
        evidence=[EvidenceRef(label=EvidenceLabel.REPORTED, tier=EvidenceTier.VALIDATED,
                              artifact="runs/1.json")])
    expired = TT._ledger_claim(valid_until="2020-01-01")
    for name, claim in [("register-valid", valid), ("register-no-evidence", no_evidence),
                        ("register-validated-no-exec", validated_no_exec),
                        ("register-expired", expired)]:
        ledger = CapabilityLedger()
        rows.append((name, outcome(lambda c=claim, l=ledger: (l.register(c), len(l.claims().get("a", []))))))
    # ledger_to_trust_dimension: valid_until limitation present/absent
    for name, claim in [
        ("ltd-no-expiry", TT._ledger_claim()),
        ("ltd-with-expiry", TT._ledger_claim(valid_until="2027-01-01")),
        ("ltd-expired", TT._ledger_claim(valid_until="2020-01-01")),
    ]:
        ledger = TT._ledger_with(claim)
        try:
            dim = ledger_to_trust_dimension(ledger, "a", "language",
                                            today=date(2026, 11, 11))
            rows.append((name, ("ok", dim.state, dim.reason, dim.limitations)))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    ledger_empty = CapabilityLedger()
    rows.append(("ltd-no-claims", outcome(lambda: ledger_to_trust_dimension(
        ledger_empty, "a", "language", today=date(2026, 11, 11)).state)))
    return rows


# ---------------------------------------------------------------------------
# trust.build_trust_map (new probe)
# ---------------------------------------------------------------------------
def probe_trust_build():
    from textforensics.trust import build_trust_map
    from textforensics.evidence import InputConditions
    from textforensics.detectors import DetectorPrediction
    rows = []
    def _cond(wc):
        return InputConditions(schema="textforensics.input-conditions/v1", language="en",
                               language_confidence="declared", script="latin",
                               word_count=wc, char_count=1000, length_band="medium",
                               domain_genre="general", domain_confidence="declared",
                               editing_regime="human_only", generator=None,
                               human_population="unknown")
    pred = DetectorPrediction(schema="textforensics.detector-result/v2",
                              detector_id="detector", detector_version="1",
                              detector_family="family", execution="local",
                              score=0.8, score_semantics="test", verdict="ai_like",
                              threshold=0.5)
    def _summarize(tm):
        return (tm.overall, tuple((d.dimension, d.state) for d in tm.dimensions))
    for name, wc, cond in [
        ("no-cond-200", 200, None),
        ("no-cond-0", 0, None),
        ("no-cond-neg", -1, None),
        ("no-cond-bool", True, None),
        ("no-cond-str", "100", None),
        ("no-cond-float", 100.5, None),
        ("cond-match", 200, _cond(200)),
        ("cond-lower", 200, _cond(100)),
        ("cond-higher", 200, _cond(300)),
        ("cond-equal-distinct", 1000, _cond(int("1000"))),
        ("cond-equal-distinct-low", 200, _cond(int("200"))),
    ]:
        try:
            tm = build_trust_map([pred], word_count=wc,
                                 conditions=cond) if cond is not None else build_trust_map([pred], word_count=wc)
            rows.append((name, ("ok", _summarize(tm))))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    return rows


# ---------------------------------------------------------------------------
# casefile._replay_trust_map / _validate_portable_bundle (new probe)
# ---------------------------------------------------------------------------
def probe_cf_replay():
    import copy
    import test_result_codec as T
    from textforensics.casefile import _replay_trust_map, _validate_portable_bundle
    rows = []
    base = copy.deepcopy(T.MINIMAL_BUNDLE)
    # v3 trust map with a single dimension (dimension-set errors) and no
    # evidence_refs -> inner replay: not_rederived, no errors.
    v3_one = {"schema": "textforensics.trust-map/v3", "overall": "strong",
              "dimensions": [{"dimension": "language", "state": "supported",
                              "reason": "ok", "evidence_refs": []}],
              "limitations": [], "generated_at_utc": "2024-01-01T00:00:00+00:00"}
    v3_full = {"schema": "textforensics.trust-map/v3", "overall": "unknown",
               "dimensions": [{"dimension": d, "state": "unknown", "reason": "ok",
                               "evidence_refs": []}
                              for d in ("language", "text_length", "domain_genre",
                                        "editing_revision", "generator_scope",
                                        "human_population",
                                        "human_false_positive_evidence",
                                        "temporal_version_stability")],
               "limitations": [], "generated_at_utc": "2024-01-01T00:00:00+00:00"}
    for name, bundle in [
        ("v3-one-dim", {**base, "trust_map": v3_one}),
        ("v3-full", {**base, "trust_map": v3_full}),
        ("v2-map", base),
        ("no-input-conditions", {k: v for k, v in {**base, "trust_map": v3_one}.items()
                                 if k != "input_conditions"}),
        ("input-conditions-str", {**base, "trust_map": v3_one,
                                  "input_conditions": "not-a-mapping"}),
        ("no-trust-map", {k: v for k, v in base.items() if k != "trust_map"}),
    ]:
        rows.append((name, outcome(_replay_trust_map, bundle, None)))
    # _validate_portable_bundle: pair errors are a single-element list,
    # so pair_errors[0] == pair_errors[-1] (see report).
    for name, bundle in [
        ("validate-v2-v3", {**base, "trust_map": v3_one}),
        ("validate-v2-v2", base),
        ("validate-v1-v3", {**base, "schema": "textforensics.forensic-bundle/v1",
                            "trust_map": v3_one}),
        ("validate-v1-v1", {**base, "schema": "textforensics.forensic-bundle/v1",
                            "trust_map": {"schema": "textforensics.trust-map/v1"}}),
        ("validate-no-tm-schema", {**base, "trust_map": {"overall": "strong"}}),
        ("validate-bad-bundle-schema", {**base, "schema": "textforensics.forensic-bundle/v9"}),
    ]:
        rows.append((name, outcome(_validate_portable_bundle, bundle)))
    return rows


# ---------------------------------------------------------------------------
# probe_runs._score / _series_from_records / build_run_manifest (new probe)
# ---------------------------------------------------------------------------
def probe_pr_score_series():
    from textforensics.probe_runs import (
        _score, _series_from_records, build_run_manifest)
    rows = []
    # _score
    for name, rec in [
        ("score-05", {"score": 0.5}),
        ("score-0", {"score": 0}),
        ("score-none", {"score": None}),
        ("score-missing", {}),
        ("score-bool", {"score": True}),
        ("score-str", {"score": "0.5"}),
        ("score-nan", {"score": float("nan")}),
        ("score-inf", {"score": float("inf")}),
        ("score-list", {"score": [0.5]}),
    ]:
        rows.append((name, outcome(_score, rec)))
    # _series_from_records
    def _rec(sid, score):
        return {"sample_id": sid, "score": score, "verdict": "ai_like",
                "native_score_direction": "higher_means_ai",
                "score_range": [0.0, 1.0]}
    for name, records in [
        ("series-one", [_rec("s1", 0.5)]),
        ("series-two", [_rec("s1", 0.5), _rec("s2", 0.7)]),
        ("series-empty", []),
        ("series-int-id", [_rec(123, 0.5)]),
        ("series-empty-id", [_rec("", 0.5)]),
        ("series-none-id", [_rec(None, 0.5)]),
        ("series-no-score", [_rec("s1", None)]),
        ("series-bool-score", [_rec("s1", True)]),
    ]:
        rows.append((name, outcome(_series_from_records, records)))
    # build_run_manifest: provider_metadata / code_sha or-branches
    kw = dict(scope="full", corpus_version="1.0.0",
              corpus_fingerprint="a" * 64, corpus_manifest_sha256="b" * 64,
              detector_id="d", detector_version="1", metrics={},
              alerts=[], breaches=[], baseline_run_id=None, is_baseline=True,
              previous_run_id=None)
    for name, over in [
        ("manifest-default", {}),
        ("manifest-provider-set", {"provider_metadata": {"a": 1}}),
        ("manifest-provider-none", {"provider_metadata": None}),
        ("manifest-code-set", {"code_sha": "abc1234"}),
        ("manifest-code-none", {"code_sha": None}),
        ("manifest-run-id", {"run_id": "run-1", "run_at_utc": "2026-01-01T00:00:00+00:00"}),
    ]:
        try:
            m = build_run_manifest(**{**kw, **over})
            rows.append((name, ("ok", m["provider_metadata"], m["code_sha"],
                                m["run_id"] if "run_id" in over else "auto",
                                m["run_at_utc"] if "run_at_utc" in over else "auto")))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    return rows


# ---------------------------------------------------------------------------
# benchmark.DisjointnessProof from_dict / frozen / slots (new probe)
# ---------------------------------------------------------------------------
def probe_bm_proof_dict():
    from textforensics.benchmark import DisjointnessProof
    rows = []
    base = {"status": "verified", "overlap_count": 0, "training_count": 10,
            "evaluation_count": 10, "training_hash": "a" * 64,
            "evaluation_hash": "b" * 64}
    for name, over in [
        ("fromdict-no-group", {}),
        ("fromdict-group-0", {"group_overlap_count": 0}),
        ("fromdict-group-3", {"group_overlap_count": 3}),
        ("fromdict-group-neg1", {"group_overlap_count": -1}),
        ("fromdict-no-errors", {}),
        ("fromdict-errors", {"errors": ["e1", "e2"]}),
        ("fromdict-non-dict", None),
    ]:
        if over is None:
            rows.append((name, outcome(DisjointnessProof.from_dict, ["x"])))
            continue
        d = dict(base)
        d.update(over)
        try:
            p = DisjointnessProof.from_dict(d)
            rows.append((name, ("ok", p.group_overlap_count, p.errors)))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    # frozen / slots
    proof = DisjointnessProof(status="verified", overlap_count=0, training_count=10,
                              evaluation_count=10, training_hash="a" * 64,
                              evaluation_hash="b" * 64)
    rows.append(("proof-frozen", outcome(lambda: setattr(proof, "status", "unknown"))))
    rows.append(("proof-slots", ("ok", hasattr(proof, "__dict__"))))
    rows.append(("proof-default-group", ("ok", proof.group_overlap_count)))
    rows.append(("proof-default-errors", ("ok", proof.errors)))
    rows.append(("proof-to-dict", outcome(lambda: proof.to_dict()["group_overlap_count"])))
    return rows
