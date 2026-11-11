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

Worker F: differential probes for the W2 domain-equivalent candidates.

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
from datetime import UTC

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
    from textforensics.trust import TRUST_DIMENSIONS, TrustDimension, _overall_state

    rows = []
    states = ("supported", "partial", "unknown", "out_of_scope")
    # every count-tuple summing to 8 (165 combos)
    for tup in itertools.product(range(9), repeat=4):
        if sum(tup) != 8:
            continue
        dims = []
        i = 0
        for st, n in zip(states, tup, strict=True):
            for _ in range(n):
                dims.append(
                    TrustDimension(
                        dimension=TRUST_DIMENSIONS[i % len(TRUST_DIMENSIONS)],
                        state=st,
                        reason="probe",
                    )
                )
                i += 1
        rows.append((tup, outcome(_overall_state, dims)))
    # dimension-set variants: exact DECLARED, subset, superset (rogue), empty.
    # _overall_state duck-types .dimension/.state, so rogue names go through
    # SimpleNamespace (TrustDimension.__post_init__ rejects unknown names).
    from types import SimpleNamespace

    for names in (
        list(TRUST_DIMENSIONS),
        list(TRUST_DIMENSIONS)[:7],
        list(TRUST_DIMENSIONS) + ["rogue_dim"],
        [],
    ):
        dims = [SimpleNamespace(dimension=n, state="supported") for n in names]
        rows.append((("set", tuple(names)), outcome(_overall_state, dims)))
    # 10-dim declared set (schema.py): strong needs exactly these 10.
    from textforensics.schema import DECLARED_TRUST_MAP_DIMENSIONS as DECLARED10

    declared10 = list(DECLARED10)
    for label, names, states in (
        ("exact10", declared10, ["supported"] * 10),
        ("exact10-one-partial", declared10, ["supported"] * 9 + ["partial"]),
        ("ten-plus-rogue", declared10 + ["rogue_dim"], ["supported"] * 11),
        ("ten-plus-rogue-partial", declared10 + ["rogue_dim"], ["supported"] * 10 + ["partial"]),
        ("nine-plus-rogue", declared10[:9] + ["rogue_dim"], ["supported"] * 10),
        ("ten-rogue-names", [f"rogue_{i}" for i in range(10)], ["supported"] * 10),
    ):
        dims = [SimpleNamespace(dimension=n, state=st) for n, st in zip(names, states, strict=True)]
        rows.append(((label,), outcome(_overall_state, dims)))
    # the exact C10 rogue-dimension scenario: 8 supported + 1 unknown + 1 rogue supported
    dims = [SimpleNamespace(dimension=n, state="supported") for n in TRUST_DIMENSIONS] + [
        SimpleNamespace(dimension="rogue_dim", state="supported")
    ]
    rows.append((("rogue",), outcome(_overall_state, dims)))
    # 9 DECLARED (8 supported + 1 unknown) + 1 rogue supported
    dims = (
        [SimpleNamespace(dimension=n, state="supported") for n in TRUST_DIMENSIONS[:7]]
        + [SimpleNamespace(dimension=TRUST_DIMENSIONS[7], state="unknown")]
        + [SimpleNamespace(dimension="rogue_dim", state="supported")]
    )
    rows.append((("rogue2",), outcome(_overall_state, dims)))
    return rows


# ---------------------------------------------------------------------------
# trust.assess_trust_map (Is_Eq: registry_verified is False/True -> ==)
# ---------------------------------------------------------------------------


def probe_trust_assess():
    from textforensics.detectors import DetectorPrediction
    from textforensics.evidence import InputConditions
    from textforensics.trust import assess_trust_map

    cond = InputConditions(
        schema="textforensics.input-conditions/v1",
        language="en",
        language_confidence="declared",
        script="latin",
        word_count=200,
        char_count=1000,
        length_band="medium",
        domain_genre="general",
        domain_confidence="declared",
        editing_regime="human_only",
        generator=None,
        human_population="unknown",
    )
    pred = DetectorPrediction(
        schema="textforensics.detector-result/v2",
        detector_id="detector",
        detector_version="1",
        detector_family="family",
        execution="local",
        score=0.8,
        score_semantics="test",
        verdict="ai_like",
        threshold=0.5,
    )
    rows = []
    for verified in (True, False, None):
        try:
            tm = assess_trust_map(cond, [pred], registry=None, registry_verified=verified)
            # timestamp-free: generated_at_utc varies per call; overall +
            # per-dimension states are the stable outputs.
            rows.append(
                (
                    verified,
                    (
                        "ok",
                        tm.overall,
                        [(d.dimension, d.state) for d in tm.dimensions],
                        sorted((tm.evidence_registry or {}).items()),
                        tuple(tm.limitations),
                    ),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append((verified, ("raise", type(exc).__name__, str(exc))))
    # failure_count / max_native_drift validation + fixed generated_at_utc
    for label, kwargs in (
        ("failure-true", {"failure_count": True}),
        ("failure-neg", {"failure_count": -1}),
        ("failure-1", {"failure_count": 1}),
        ("drift-0", {"max_native_drift": 0.0}),
        ("drift-neg", {"max_native_drift": -0.1}),
        ("drift-1", {"max_native_drift": 1.0}),
        ("generated-fixed", {"generated_at_utc": "2026-01-01T00:00:00+00:00"}),
    ):
        try:
            tm = assess_trust_map(cond, [pred], registry=None, **kwargs)
            # Record whether the fixed timestamp survived, not the raw
            # value: H.digest scrubs ALL ISO timestamps to "TIME", so the
            # raw value is invisible to the kill-test digest. The boolean
            # kills OrWithAnd:6 [516,42] (`generated_at_utc or now()` ->
            # `and`): the mutant returns now() instead of the fixed value.
            rows.append(
                (
                    (label,),
                    (
                        "ok",
                        tm.overall,
                        [(d.dimension, d.state) for d in tm.dimensions],
                        sorted((tm.evidence_registry or {}).items()),
                        tuple(tm.limitations),
                        tm.generated_at_utc == kwargs["generated_at_utc"]
                        if "generated_at_utc" in kwargs
                        else None,
                    ),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(((label,), ("raise", type(exc).__name__, str(exc))))
    # empty vs non-empty registry (Delete_Not:14 limitation branch)
    import test_audit_w2_worker_a as A

    for label, reg in (
        ("registry-empty", A._v3_registry()),
        ("registry-one", A._v3_registry(A._v3_record_dict(status="supported"))),
    ):
        try:
            tm = assess_trust_map(cond, [pred], registry=reg)
            rows.append(
                (
                    (label,),
                    (
                        "ok",
                        tm.overall,
                        [(d.dimension, d.state) for d in tm.dimensions],
                        sorted((tm.evidence_registry or {}).items()),
                        tuple(tm.limitations),
                    ),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(((label,), ("raise", type(exc).__name__, str(exc))))
    return rows


# ---------------------------------------------------------------------------
# trust.trust_map_from_capability_ledger
# ---------------------------------------------------------------------------


def _ledger_claim(capability="language", tier_name="VALIDATED", valid_until=None, evidence=True):
    from textforensics.policy import CapabilityClaim, EvidenceLabel, EvidenceRef, EvidenceTier

    tier = getattr(EvidenceTier, tier_name)
    return CapabilityClaim(
        detector_id="a",
        capability=capability,
        tier=tier,
        evidence=[EvidenceRef(label=EvidenceLabel.EXECUTED, tier=tier, artifact="runs/1.json")]
        if evidence
        else [],
        valid_until=valid_until,
    )


def _ledger_with(*claims):
    from textforensics.policy import CapabilityLedger

    ledger = CapabilityLedger()
    for claim in claims:
        ledger.register(claim)
    return ledger


def probe_trust_ledger():
    from textforensics.trust import trust_map_from_capability_ledger

    rows = []

    # Record limitations too: the Eq_Is:9 mutant (claim.capability == -> is)
    # only changes the dimension LIMITATIONS (the expired claim's expiry
    # note drops out of `relevant`); state/reason/evidence_refs are
    # identical, so without limitations the cap-joined row cannot see it.
    def _dims(tm):
        return [
            (d.dimension, d.state, d.reason, tuple(d.evidence_refs), tuple(d.limitations))
            for d in tm.dimensions
        ]

    caps = ("language", "length", "domain", "editing", "generator", "human_population")
    for cap in caps:
        for tier in ("VALIDATED", "READABLE", "TOOL_BACKED"):
            ledger = _ledger_with(_ledger_claim(capability=cap, tier_name=tier))
            tm = trust_map_from_capability_ledger(ledger)
            rows.append(((cap, tier), tm.overall, _dims(tm)))
    # expired / evidence-less / ineffective claims (the NumberReplacer:48/50/51 shapes)
    for kwargs in (
        {"valid_until": "2000-01-01"},
        {"evidence": False},
        {"tier_name": "READABLE", "evidence": False},
    ):
        ledger = _ledger_with(_ledger_claim(**kwargs))
        tm = trust_map_from_capability_ledger(ledger)
        rows.append((("ineffective", tuple(sorted(kwargs.items()))), tm.overall, _dims(tm)))
    # 6 dims with 2 unknown (the :50 shape) and 4 dims with 2 unknown (the :51 shape)
    for n_unknown in (0, 1, 2, 3, 4):
        claims = [_ledger_claim(capability=c) for c in caps[:6]]
        # make n_unknown of them ineffective by expiring them
        claims = [
            (
                _ledger_claim(capability=c, valid_until="2000-01-01")
                if i < n_unknown
                else _ledger_claim(capability=c)
            )
            for i, c in enumerate(caps[:6])
        ]
        tm = trust_map_from_capability_ledger(_ledger_with(*claims))
        rows.append((("unknown-count", n_unknown), tm.overall, _dims(tm)))
    # odd dimension counts for the //2 threshold: 5 dims, 2 unknown
    # (5//2=2 vs 5/2=2.5: unknown>=2 differs)
    for n_unknown in (0, 1, 2, 3):
        claims = [
            (
                _ledger_claim(capability=c, valid_until="2000-01-01")
                if i < n_unknown
                else _ledger_claim(capability=c)
            )
            for i, c in enumerate(caps[:5])
        ]
        tm = trust_map_from_capability_ledger(_ledger_with(*claims))
        rows.append((("unknown-count-5", n_unknown), tm.overall, _dims(tm)))
    # distinct-but-equal capability strings: `is` vs `==` (Eq_Is:9).
    # Two claims, one VALIDATED with the joined string, one expired with the
    # literal: under `==` both are relevant; under `is` only the set member.
    joined_cap = "".join(["lang", "uage"])
    ledger = _ledger_with(
        _ledger_claim(capability=joined_cap, tier_name="VALIDATED"),
        _ledger_claim(capability="language", tier_name="VALIDATED", valid_until="2000-01-01"),
    )
    tm = trust_map_from_capability_ledger(ledger)
    rows.append((("cap-joined",), tm.overall, _dims(tm)))
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
        for st, n in zip(states, tup, strict=True):
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
    # 10-dim declared set (schema.py DECLARED_TRUST_MAP_DIMENSIONS): the
    # strong gate needs exactly these 10 names, all supported. The 8-name
    # grid above can never derive strong.
    from textforensics.schema import DECLARED_TRUST_MAP_DIMENSIONS as DECLARED10

    declared10 = list(DECLARED10)
    for label, names, states in (
        ("exact10", declared10, ["supported"] * 10),
        ("exact10-one-partial", declared10, ["supported"] * 9 + ["partial"]),
        ("exact10-one-unknown", declared10, ["supported"] * 9 + ["unknown"]),
        ("ten-plus-rogue", declared10 + ["rogue_dim"], ["supported"] * 11),
        ("nine-plus-rogue", declared10[:9] + ["rogue_dim"], ["supported"] * 10),
        ("ten-rogue-names", [f"rogue_{i}" for i in range(10)], ["supported"] * 10),
        ("ten-plus-rogue-partial", declared10 + ["rogue_dim"], ["supported"] * 10 + ["partial"]),
        ("eleven-supported", declared10 + ["rogue_dim"], ["supported"] * 11),
    ):
        try:
            dims = [make_dim(n, st) for n, st in zip(names, states, strict=True)]
        except ValueError:
            dims = [
                SimpleNamespace(dimension=n, state=st) for n, st in zip(names, states, strict=True)
            ]
        rows.append(((label,), outcome(fn, dims)))
    return rows


def probe_validation_overall_v3():
    # _overall_state_v3 takes the same TrustDimension list shape as trust
    from textforensics.trust import TRUST_DIMENSIONS, TrustDimension
    from textforensics.validation import _overall_state_v3

    return _overall_grid(
        _overall_state_v3,
        lambda name, st: TrustDimension(dimension=name, state=st, reason="probe"),
        TRUST_DIMENSIONS,
    )


def probe_verify_recompute():
    from textforensics.verify import _recompute_overall, _recompute_overall_v3

    rows = []
    for fn, label in ((_recompute_overall, "v2"), (_recompute_overall_v3, "v3")):
        sub = _overall_grid(
            fn,
            lambda name, st: {"dimension": name, "state": st},
            (
                "language",
                "text_length",
                "domain_genre",
                "editing_revision",
                "generator_scope",
                "human_population",
                "human_false_positive_evidence",
                "temporal_version_stability",
            ),
        )
        rows.append((label, sub))
    return rows


def probe_sa_recompute():
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "standalone_verify",
        Path("/home/hatch/workspace/TextForensics-w2-f/src/textforensics/_standalone_verify.py"),
    )
    sa = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sa)
    rows = []
    # trust_map shape: {"dimensions": {name: {"state": ...}}, "overall": ...}
    states = ("supported", "partial", "unknown", "out_of_scope")
    names = (
        "language",
        "text_length",
        "domain_genre",
        "editing_revision",
        "generator_scope",
        "human_population",
        "human_false_positive_evidence",
        "temporal_version_stability",
    )
    for schema in (None, "textforensics.trust-map/v2", "textforensics.trust-map/v3"):
        for tup in itertools.product(range(9), repeat=4):
            if sum(tup) != 8:
                continue
            dims, i = [], 0
            for st, n in zip(states, tup, strict=True):
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
        (
            "dim-mixed",
            [
                {"dimension": "language", "state": "supported"},
                {"dimension": None, "state": "out_of_scope"},
                {"dimension": 123, "state": "partial"},
            ],
        ),
        ("dim-nonstr-out-of-scope", [{"dimension": None, "state": "out_of_scope"}]),
    ]:
        rows.append(
            (
                (name, dims),
                outcome(
                    sa._recompute_trust_map_overall,
                    {"dimensions": dims, "schema": "textforensics.trust-map/v3"},
                ),
            )
        )
    # 10-dim declared set: strong needs exactly these 10 names, all supported.
    from textforensics.schema import DECLARED_TRUST_MAP_DIMENSIONS as DECLARED10

    declared10 = list(DECLARED10)
    for schema in ("textforensics.trust-map/v3", "textforensics.trust-map/v2", None):
        for label, names, states in (
            ("exact10", declared10, ["supported"] * 10),
            ("exact10-one-partial", declared10, ["supported"] * 9 + ["partial"]),
            ("ten-plus-rogue", declared10 + ["rogue_dim"], ["supported"] * 11),
            ("nine-plus-rogue", declared10[:9] + ["rogue_dim"], ["supported"] * 10),
            ("ten-rogue-names", [f"rogue_{i}" for i in range(10)], ["supported"] * 10),
            (
                "ten-plus-rogue-partial",
                declared10 + ["rogue_dim"],
                ["supported"] * 10 + ["partial"],
            ),
        ):
            dims = [{"dimension": n, "state": st} for n, st in zip(names, states, strict=True)]
            tm = {"dimensions": dims}
            if schema is not None:
                tm["schema"] = schema
            rows.append(
                ((f"10dim-{schema}-{label}",), outcome(sa._recompute_trust_map_overall, tm))
            )
    return rows


# ---------------------------------------------------------------------------
# probe_metrics (pure functions)
# ---------------------------------------------------------------------------


def probe_pm_brier():
    from textforensics.probe_metrics import brier

    rows = []
    for probs, labels in (
        ([0.1, 0.9], [0, 1]),
        ([0.5, 0.5], [0, 1]),
        ([0.0, 1.0], [0, 1]),
        ([0.3, 0.3, 0.7], [0, 1, 1]),
    ):
        rows.append(((probs, labels), outcome(brier, probs, labels)))
    # mismatched lengths: must raise identically under both (strict never fires)
    rows.append((("mismatch",), outcome(brier, [0.1, 0.2], [0])))
    rows.append((("mismatch-short",), outcome(brier, [0.1], [0, 1])))
    # >256 equal lengths: NotEq_IsNot (len is not len)
    rows.append((("len-300",), outcome(brier, [0.5] * 300, [0] * 300)))
    # invalid probs: ZeroIterationForLoop validation
    for probs in ([2.0, 0.5], [-0.5, 0.5], [float("nan"), 0.5]):
        rows.append(((f"badprob-{probs[0]!r}",), outcome(brier, probs, [0, 1])))
    return rows


def probe_pm_ece():
    from textforensics.probe_metrics import ece

    rows = []
    for probs, labels, nb in (
        ([0.1, 0.9, 0.4, 0.6], [0, 1, 0, 1], 10),
        ([0.0, 1.0, 0.5], [0, 1, 1], 2),
        ([0.25, 0.75], [0, 1], 1),
        ([0.1, 0.9], [0, 1], 300),
        # p == 1.0 in last bin with label 0 (Eq_Is:15): the p=1.0 member
        # contributes |1.0 - 0| * 1/n, so excluding it changes the ECE
        # (orig 0.4, mutant 0.0667). With label 1 its contribution is
        # 0.0 and the exclusion is invisible.
        ([0.1, 0.9, 1.0], [0, 1, 0], 300),
        ([0.1, 0.9, 1.0], [0, 1, 1], 10),
        ([0.0, 0.0, 1.0, 1.0], [0, 0, 1, 1], 4),
    ):
        rows.append(((probs, labels, nb), outcome(ece, probs, labels, n_bins=nb)))
    # Default n_bins (10 -> 11/9): kills NumberReplacer:102/103 [399,64].
    # Every other row passes n_bins explicitly, so the default never fired.
    # Probs straddle the 0.1 boundary: with n_bins=10 they fall in
    # different bins (ECE 0.495), with 9 or 11 they share a bin (ECE 0.4).
    # (The old [0.1, 0.9] row gave ECE 0.1 under all three binnings —
    # each prob alone in its bin — so it was invisible on the disk driver.)
    rows.append((("default-nbins",), outcome(ece, [0.095, 0.105], [0, 1])))
    # Prob below 0: kills NumberReplacer:107 [413,15] (the range check's
    # lower bound 0 -> -1/1: -0.5 passes the mutant, raises originally).
    rows.append((("prob-neg",), outcome(ece, [-0.5, 0.5], [0, 1], n_bins=10)))
    rows.append((("mismatch",), outcome(ece, [0.1, 0.2], [0])))
    rows.append((("mismatch-short",), outcome(ece, [0.1], [0, 1])))
    rows.append((("len-300",), outcome(ece, [0.5] * 300, [0] * 300, n_bins=10)))
    for nb in (0, 1, 2):
        rows.append(((f"nb-{nb}",), outcome(ece, [0.1, 0.9], [0, 1], n_bins=nb)))
    for labels in ([True, 1], [2, 1], ["x", 1]):
        rows.append(((f"badlabel-{labels[0]!r}",), outcome(ece, [0.1, 0.9], labels, n_bins=10)))
    return rows


def probe_pm_fpr():
    from textforensics.probe_metrics import fpr_at_threshold

    rows = []
    for scores, labels, thr, direction in (
        ([0.1, 0.9, 0.4, 0.6], [0, 1, 0, 1], 0.5, "higher_means_ai"),
        ([0.1, 0.9], [0, 1], 0.0, "higher_means_ai"),
        ([0.1, 0.9], [0, 1], 1.0, "lower_means_ai"),
        ([0.5, 0.5], [0, 1], 0.5, "higher_means_ai"),
    ):
        rows.append(
            (
                (scores, labels, thr, direction),
                outcome(fpr_at_threshold, scores, labels, thr, direction=direction),
            )
        )
    rows.append((("mismatch",), outcome(fpr_at_threshold, [0.1], [0, 1], 0.5)))
    rows.append((("mismatch-long",), outcome(fpr_at_threshold, [0.1, 0.2], [0], 0.5)))
    rows.append((("len-300",), outcome(fpr_at_threshold, [0.5] * 300, [0] * 300, 0.5)))
    for labels in ([True, 1], [2, 1], ["x", 1]):
        rows.append(
            ((f"badlabel-{labels[0]!r}",), outcome(fpr_at_threshold, [0.1, 0.9], labels, 0.5))
        )
    return rows


def probe_pm_is_ai_like():
    from textforensics.probe_metrics import is_ai_like

    rows = []
    for score, thr, direction in (
        (0.5, 0.5, "higher_means_ai"),
        (0.4, 0.5, "higher_means_ai"),
        (0.6, 0.5, "higher_means_ai"),
        (0.5, 0.5, "lower_means_ai"),
        (0.0, 0.0, "higher_means_ai"),
        (1.0, 1.0, "lower_means_ai"),
    ):
        rows.append(((score, thr, direction), outcome(is_ai_like, score, thr, direction=direction)))
    return rows


def probe_pm_ks_pvalue():
    from textforensics.probe_metrics import ks_pvalue

    rows = []
    for d, n, m in (
        (0.0, 10, 10),
        (0.5, 10, 10),
        (1.0, 5, 7),
        (0.25, 100, 100),
        (0.0, 1, 1),
        (-0.5, 10, 10),
        (1.5, 10, 10),
        (0.05, 100, 100),
        (0.01, 100, 100),
        (0.5, 0, 10),
        (0.5, 1, 10),
        (0.5, 10, 0),
        (0.5, 10, 1),
        (0.9, 100, 100),
        (0.3, 20, 30),
    ):
        rows.append(((d, n, m), outcome(ks_pvalue, d, n, m)))
    # Tiny d: the series oscillates +/-2.0 and only the j>100 break stops
    # it, so break timing flips the clamped result 1.0 <-> 0.0. Kills
    # Sub_Add:3 [302,35], Gt_Eq:2 / Gt_GtE:2 [304,34], NumberReplacer:66/67
    # [304,36]. (The d=0.0 rows early-return 1.0 before the series.)
    rows.append((("tiny-d",), outcome(ks_pvalue, 1e-9, 1, 1)))
    return rows


def probe_pm_ks_statistic():
    from textforensics.probe_metrics import ks_statistic

    rows = []
    for a, b in (
        ([1, 2, 3], [1, 2, 3]),
        ([1, 2], [3, 4, 5]),
        ([0.5], [0.5, 0.6]),
        ([1, 1, 1], [2, 2, 2]),
        (list(range(300)), list(range(300))),
        ([3, 4, 5], [1, 2]),  # b shorter: j hits m first
        ([1, 3], [2, 4]),  # interleaved
        ([1, 2, 3], [1, 2]),  # b shorter, ties
        (list(range(400)), list(range(300))),  # b shorter, >256
        (list(range(300)), list(range(400))),  # a shorter, >256
        ([1, 1, 2, 2, 3], [1, 2, 3, 3]),  # ties + interleaved
        ([5], [1, 2, 3, 4]),
    ):  # a single, b longer
        rows.append(((a, b), outcome(ks_statistic, a, b)))
    return rows


def probe_pm_oriented():
    from textforensics.probe_metrics import oriented_scores

    rows = []
    for scores, direction in (
        ([0.1, 0.9], "higher_means_ai"),
        ([0.1, 0.9], "lower_means_ai"),
        ([], "higher_means_ai"),
        ([0.5], "lower_means_ai"),
    ):
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
        ([0.5, 0.5], [0, 1], 0.01, "higher_means_ai"),
        # valid lower_means_ai rows (native threshold negation)
        ([0.1, 0.9], [0, 1], 0.5, "lower_means_ai"),
        ([0.1, 0.9, 0.4, 0.6], [0, 1, 0, 1], 0.01, "lower_means_ai"),
        # target_fpr boundaries (Lt_NotEq / Lt_LtE / NumberReplacer)
        ([0.1, 0.9], [0, 1], -0.5, "higher_means_ai"),
        ([0.1, 0.9], [0, 1], 0.0, "higher_means_ai"),
        ([0.1, 0.9], [0, 1], 1.0, "higher_means_ai"),
        ([0.1, 0.9], [0, 1], 1.5, "higher_means_ai"),
        # fpr exactly == target_fpr: threshold 0.9 is the unique best
        # (tpr 1.0); the LtE_Lt mutant drops it and falls back to tpr 0.5
        ([0.9, 0.95] + [0.1] * 99 + [0.9], [1, 1] + [0] * 99 + [0], 0.01, "higher_means_ai"),
        # tied tpr: equal tpr, different fpr/threshold (USub tie-breaks)
        ([0.2, 0.8, 0.3, 0.7], [0, 1, 0, 1], 0.5, "higher_means_ai"),
        (
            [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8],
            [0, 0, 0, 0, 1, 1, 1, 1],
            0.25,
            "higher_means_ai",
        ),
        # Tie at the threshold: kills USub_Not:3 [587,24] (the
        # -threshold tiebreak): original threshold 0.5 / fpr 0.5,
        # mutant threshold 0.45 / fpr 0.75.
        ([0.3, 0.45, 0.5, 0.6, 0.7, 0.9], [0, 0, 1, 0, 0, 1], 0.8, "higher_means_ai"),
    ):
        rows.append(
            (
                (scores, labels, target, direction),
                outcome(tpr_at_fpr, scores, labels, target_fpr=target, direction=direction),
            )
        )
    # default target_fpr (0.01): NumberReplacer on the default
    for scores, labels, direction in (
        ([0.1, 0.9, 0.4, 0.6], [0, 1, 0, 1], "higher_means_ai"),
        ([0.1, 0.9], [0, 1], "lower_means_ai"),
    ):
        rows.append(
            ((f"default-{direction}",), outcome(tpr_at_fpr, scores, labels, direction=direction))
        )
    rows.append((("mismatch-long",), outcome(tpr_at_fpr, [0.1, 0.2], [0], target_fpr=0.5)))
    rows.append((("mismatch-short",), outcome(tpr_at_fpr, [0.1], [0, 1], target_fpr=0.5)))
    rows.append((("len-300",), outcome(tpr_at_fpr, [0.5] * 300, [0] * 300, target_fpr=0.5)))
    rows.append((("empty",), outcome(tpr_at_fpr, [], [], target_fpr=0.5)))
    for labels in ([True, 1], [2, 1], ["x", 1]):
        rows.append(
            ((f"badlabel-{labels[0]!r}",), outcome(tpr_at_fpr, [0.1, 0.9], labels, target_fpr=0.5))
        )
    return rows


# ---------------------------------------------------------------------------
# explain._coverage_label
# ---------------------------------------------------------------------------


def probe_explain_coverage_label():
    from textforensics.execution_policy import CompletenessAccounting
    from textforensics.explain import _coverage_label

    rows = []
    rows.append((("none",), outcome(_coverage_label, None)))
    for succeeded, selected in ((0, 0), (0, 5), (5, 5), (3, 5), (1, 300), (300, 300)):
        # attempted=selected, abstained=0, failed=attempted-succeeded (valid partition)
        acc = CompletenessAccounting(
            selected=selected,
            attempted=selected,
            succeeded=succeeded,
            abstained=0,
            failed=selected - succeeded,
        )
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
                "score_shift": {
                    "ks_statistic": None,
                    "psi": psi,
                    "ks_pvalue_holm_adjusted": None,
                    "n_paired": n_paired,
                },
                "flips": {
                    "n": n_paired,
                    "flips": 0,
                    "flip_rate": 0.0,
                    "flip_rate_ci": [0.01, 0.5],
                    "human_to_ai": 0,
                    "ai_to_human": 0,
                    "to_abstain": 0,
                    "from_abstain": 0,
                    "n_human_paired": n_paired,
                    "human_to_ai_human": 0,
                },
                "calibration": {"ece": None, "baseline_ece": None},
                "human_fpr": None,
            }
        },
        "overall": {"flips": None},
        "worst_slice_fpr": None,
        "holm": {"alpha_per_run": 0.05, "family": "per-slice KS tests", "adjusted_pvalues": {}},
    }


def _et_metrics(
    *,
    psi=None,
    n_paired=60,
    slice_n="default",
    drift_allowed=True,
    shift=None,
    flips="default",
    calibration=None,
    human_fpr=None,
    is_human=True,
    overall="default",
    drop_overall=False,
):
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
    if drop_overall or overall == "absent":
        m.pop("overall", None)
    elif overall is not None and overall != "default":
        m["overall"] = overall
    elif overall is None:
        m["overall"] = None
    return m


def _et_flips(
    *,
    n=60,
    flips=0,
    rate=0.0,
    ci=(0.01, 0.5),
    human_to_ai=0,
    ai_to_human=0,
    n_human_paired="default",
    human_to_ai_human="default",
    drop=(),
):
    d = {
        "n": n,
        "flips": flips,
        "flip_rate": rate,
        "flip_rate_ci": [ci[0], ci[1]],
        "human_to_ai": human_to_ai,
        "ai_to_human": ai_to_human,
        "to_abstain": 0,
        "from_abstain": 0,
    }
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
    from textforensics.probe_runs import RULE_DRIFT_STATISTIC, evaluate_tiers

    rows = []
    for psi in (None, 0.1, 0.5, 1.0):
        for prev in ([], [{"rule": RULE_DRIFT_STATISTIC, "slice": "human-native"}]):
            rows.append(
                (
                    (psi, len(prev)),
                    outcome(
                        evaluate_tiers,
                        metrics=_tier_metrics(psi=psi),
                        detector_version="0.1.0",
                        previous_breaches=prev,
                    ),
                )
            )
    # below-floor paired denominator: no escalation either way
    rows.append(
        (
            ("floor",),
            outcome(
                evaluate_tiers,
                metrics=_tier_metrics(psi=0.5, n_paired=49),
                detector_version="0.1.0",
                previous_breaches=[],
            ),
        )
    )
    # --- drift / floor shapes -------------------------------------------
    extra = [
        ("drift-allowed-false", dict(psi=0.5, drift_allowed=False), {}),
        ("shift-absent", dict(psi=0.5, shift="absent"), {}),
        ("shift-npaired-none-n60", dict(psi=0.5, shift={}, slice_n=60), {}),
        ("shift-npaired-none-n49", dict(psi=0.5, shift={}, slice_n=49), {}),
        ("shift-npaired-none-n-none", dict(psi=0.5, shift={}, slice_n=None), {}),
        ("npaired-50", dict(psi=0.5, n_paired=50), {}),
        (
            "ks-breach",
            dict(
                psi=None,
                shift={
                    "ks_statistic": 0.11,
                    "psi": None,
                    "ks_pvalue_holm_adjusted": 0.04,
                    "ks_pvalue": 0.01,
                    "n_paired": 60,
                },
            ),
            {},
        ),
        (
            "ks-stat-below",
            dict(
                psi=None,
                shift={
                    "ks_statistic": 0.09,
                    "psi": None,
                    "ks_pvalue_holm_adjusted": 0.04,
                    "ks_pvalue": 0.01,
                    "n_paired": 60,
                },
            ),
            {},
        ),
        (
            "ks-p-above",
            dict(
                psi=None,
                shift={
                    "ks_statistic": 0.11,
                    "psi": None,
                    "ks_pvalue_holm_adjusted": 0.05,
                    "ks_pvalue": 0.01,
                    "n_paired": 60,
                },
            ),
            {},
        ),
        (
            "ks-p-none",
            dict(
                psi=None,
                shift={
                    "ks_statistic": 0.11,
                    "psi": None,
                    "ks_pvalue_holm_adjusted": None,
                    "ks_pvalue": 0.01,
                    "n_paired": 60,
                },
            ),
            {},
        ),
        ("psi-exact-0.2", dict(psi=0.2), {}),
        ("no-overall-key", dict(psi=0.5, drop_overall=True), {}),
        # --- flip tier-1 (human->AI) --------------------------------------
        (
            "t1-rate-0.06",
            dict(
                flips=_et_flips(
                    n=60, flips=3, rate=0.06, human_to_ai=3, n_human_paired=50, human_to_ai_human=3
                )
            ),
            {},
        ),
        (
            "t1-rate-0.05",
            dict(
                flips=_et_flips(
                    n=60, flips=3, rate=0.06, human_to_ai=3, n_human_paired=60, human_to_ai_human=3
                )
            ),
            {},
        ),
        (
            "t1-rate-0.04",
            dict(
                flips=_et_flips(
                    n=60, flips=2, rate=0.06, human_to_ai=2, n_human_paired=50, human_to_ai_human=2
                )
            ),
            {},
        ),
        (
            "t1-n49",
            dict(
                flips=_et_flips(
                    n=60,
                    flips=10,
                    rate=0.20,
                    human_to_ai=10,
                    n_human_paired=49,
                    human_to_ai_human=10,
                )
            ),
            {},
        ),
        (
            "t1-n0",
            dict(
                flips=_et_flips(
                    n=0, flips=0, rate=0.0, human_to_ai=0, n_human_paired=0, human_to_ai_human=0
                )
            ),
            {},
        ),
        (
            "t1-legacy-0.10",
            dict(
                flips=_et_flips(
                    n=60,
                    flips=6,
                    rate=0.10,
                    human_to_ai=6,
                    drop=("n_human_paired", "human_to_ai_human"),
                )
            ),
            {},
        ),
        (
            "t1-legacy-0.05",
            dict(
                flips=_et_flips(
                    n=60,
                    flips=3,
                    rate=0.05,
                    human_to_ai=3,
                    drop=("n_human_paired", "human_to_ai_human"),
                )
            ),
            {},
        ),
        (
            "t1-legacy-0.0",
            dict(
                flips=_et_flips(
                    n=60,
                    flips=0,
                    rate=0.0,
                    human_to_ai=0,
                    drop=("n_human_paired", "human_to_ai_human"),
                )
            ),
            {},
        ),
        (
            "t1-one-key-nhp",
            dict(
                flips=_et_flips(
                    n=60,
                    flips=3,
                    rate=0.06,
                    human_to_ai=3,
                    n_human_paired=50,
                    drop=("human_to_ai_human",),
                )
            ),
            {},
        ),
        (
            "t1-one-key-htah",
            dict(
                flips=_et_flips(
                    n=60,
                    flips=3,
                    rate=0.06,
                    human_to_ai=3,
                    human_to_ai_human=3,
                    drop=("n_human_paired",),
                )
            ),
            {},
        ),
        ("t1-flips-none", dict(flips=None), {}),
        ("t1-flips-absent", dict(flips="absent"), {}),
        ("t1-flips-n-none", dict(flips=_et_flips(n=None, flips=0, rate=0.0)), {}),
        (
            "t1-nhp-none",
            dict(
                flips=_et_flips(
                    n=60, flips=0, rate=0.0, n_human_paired=None, human_to_ai_human=None
                )
            ),
            {},
        ),
        (
            "t1-htah-none",
            dict(
                flips=_et_flips(n=60, flips=0, rate=0.0, n_human_paired=60, human_to_ai_human=None)
            ),
            {},
        ),
        (
            "t1-human-to-ai-none",
            dict(
                flips=_et_flips(
                    n=60,
                    flips=0,
                    rate=0.0,
                    human_to_ai=None,
                    drop=("n_human_paired", "human_to_ai_human"),
                )
            ),
            {},
        ),
        (
            "t1-nonhuman-slice",
            dict(
                is_human=False,
                flips=_et_flips(
                    n=60,
                    flips=12,
                    rate=0.20,
                    human_to_ai=12,
                    n_human_paired=50,
                    human_to_ai_human=12,
                ),
            ),
            {},
        ),
        # --- flip tier-2 ---------------------------------------------------
        ("t2-rate-0.02-ci0.01", dict(flips=_et_flips(n=60, flips=2, rate=0.02)), {}),
        ("t2-rate-0.01", dict(flips=_et_flips(n=60, flips=1, rate=0.01)), {}),
        ("t2-rate-0.02-ci0", dict(flips=_et_flips(n=60, flips=2, rate=0.02, ci=(0.0, 0.5))), {}),
        # Negative CI lower bound: the Tier-2 elif's `ci_lo > 0` vs `!= 0`
        # differ only here (ci_lo == 0.0 agrees under both). Kills
        # Gt_NotEq:6 [1211,94] (per-slice Tier-2). Tier-1 cannot fire:
        # human_to_ai_human defaults to 0, so human_to_ai_rate is 0.0.
        ("t2-ci-neg", dict(flips=_et_flips(n=60, flips=2, rate=0.02, ci=(-0.01, 0.5))), {}),
        ("t2-rate-0.02-n49", dict(flips=_et_flips(n=49, flips=2, rate=0.02)), {}),
        ("t2-rate-0.02-n50", dict(flips=_et_flips(n=50, flips=2, rate=0.02)), {}),
        ("t2-rate-none", dict(flips=_et_flips(n=60, flips=0, rate=None)), {}),
        # --- overall flips -------------------------------------------------
        (
            "overall-t2",
            dict(
                overall={
                    "flips": {"flip_rate": 0.02, "flip_rate_ci": [0.01, 0.5], "flips": 2, "n": 60}
                }
            ),
            {},
        ),
        (
            "overall-rate-0.01",
            dict(
                overall={
                    "flips": {"flip_rate": 0.01, "flip_rate_ci": [0.01, 0.5], "flips": 1, "n": 60}
                }
            ),
            {},
        ),
        (
            "overall-ci0",
            dict(
                overall={
                    "flips": {"flip_rate": 0.02, "flip_rate_ci": [0.0, 0.5], "flips": 2, "n": 60}
                }
            ),
            {},
        ),
        (
            "overall-n49",
            dict(
                overall={
                    "flips": {"flip_rate": 0.02, "flip_rate_ci": [0.01, 0.5], "flips": 2, "n": 49}
                }
            ),
            {},
        ),
        # Overall-flips boundaries: n == 50 exactly (`>=` vs `>`),
        # rate below the Tier-2 threshold (`>` vs `!=`), and a negative
        # CI lower bound (`ci_lo > 0` vs `!= 0`). Kill GtE_Gt:7 [1242,42],
        # Gt_NotEq:7 [1243,21], Gt_NotEq:8 [1244,22] respectively.
        (
            "overall-n50",
            dict(
                overall={
                    "flips": {"flip_rate": 0.02, "flip_rate_ci": [0.01, 0.5], "flips": 2, "n": 50}
                }
            ),
            {},
        ),
        (
            "overall-rate-0.005",
            dict(
                overall={
                    "flips": {"flip_rate": 0.005, "flip_rate_ci": [0.01, 0.5], "flips": 1, "n": 60}
                }
            ),
            {},
        ),
        (
            "overall-ci-neg",
            dict(
                overall={
                    "flips": {"flip_rate": 0.02, "flip_rate_ci": [-0.01, 0.5], "flips": 2, "n": 60}
                }
            ),
            {},
        ),
        (
            "overall-rate-none",
            dict(
                overall={
                    "flips": {"flip_rate": None, "flip_rate_ci": [0.01, 0.5], "flips": 0, "n": 60}
                }
            ),
            {},
        ),
        (
            "overall-n-none",
            dict(
                overall={
                    "flips": {"flip_rate": 0.02, "flip_rate_ci": [0.01, 0.5], "flips": 2, "n": None}
                }
            ),
            {},
        ),
        ("overall-absent", dict(overall="absent"), {}),
        # --- ECE ------------------------------------------------------------
        (
            "ece-up-0.06",
            dict(calibration={"ece": 0.10, "baseline_ece": 0.04, "n_calibrated_paired": 60}),
            {},
        ),
        (
            "ece-up-0.05",
            dict(calibration={"ece": 0.10, "baseline_ece": 0.05, "n_calibrated_paired": 60}),
            {},
        ),
        (
            "ece-up-0.04",
            dict(calibration={"ece": 0.09, "baseline_ece": 0.05, "n_calibrated_paired": 60}),
            {},
        ),
        (
            "ece-n49",
            dict(calibration={"ece": 0.10, "baseline_ece": 0.04, "n_calibrated_paired": 49}),
            {},
        ),
        (
            "ece-n-none",
            dict(calibration={"ece": 0.10, "baseline_ece": 0.04, "n_calibrated_paired": None}),
            {},
        ),
        (
            "ece-none",
            dict(calibration={"ece": None, "baseline_ece": 0.04, "n_calibrated_paired": 60}),
            {},
        ),
        (
            "ece-base-none",
            dict(calibration={"ece": 0.10, "baseline_ece": None, "n_calibrated_paired": 60}),
            {},
        ),
        (
            "ece-down",
            dict(calibration={"ece": 0.02, "baseline_ece": 0.10, "n_calibrated_paired": 60}),
            {},
        ),
        # --- FPR cap ---------------------------------------------------------
        (
            "fpr-cap-breach",
            dict(
                human_fpr={
                    "fpr_claim_allowed": True,
                    "fpr": 0.06,
                    "fpr_ci": [0.06, 0.10],
                    "n_human": 120,
                    "false_positives": 7,
                }
            ),
            {},
        ),
        (
            "fpr-cap-exact",
            dict(
                human_fpr={
                    "fpr_claim_allowed": True,
                    "fpr": 0.05,
                    "fpr_ci": [0.05, 0.10],
                    "n_human": 120,
                    "false_positives": 6,
                }
            ),
            {},
        ),
        (
            "fpr-cap-below",
            dict(
                human_fpr={
                    "fpr_claim_allowed": True,
                    "fpr": 0.04,
                    "fpr_ci": [0.04, 0.10],
                    "n_human": 120,
                    "false_positives": 5,
                }
            ),
            {},
        ),
        (
            "fpr-not-allowed",
            dict(
                human_fpr={
                    "fpr_claim_allowed": False,
                    "fpr": 0.06,
                    "fpr_ci": [0.06, 0.10],
                    "n_human": 120,
                    "false_positives": 7,
                }
            ),
            {},
        ),
        # --- version change ---------------------------------------------------
        (
            "ver-10d",
            dict(),
            dict(
                previous_detector_version="0.0.9",
                previous_run_at="2026-11-01T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
        (
            "ver-7d",
            dict(),
            dict(
                previous_detector_version="0.0.9",
                previous_run_at="2026-11-04T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
        (
            "ver-6d",
            dict(),
            dict(
                previous_detector_version="0.0.9",
                previous_run_at="2026-11-05T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
        (
            "ver-no-run-at",
            dict(),
            dict(
                previous_detector_version="0.0.9",
                previous_run_at=None,
                run_at="2026-11-11T00:00:00",
            ),
        ),
        (
            "ver-same",
            dict(),
            dict(
                previous_detector_version="0.1.0",
                previous_run_at="2026-11-01T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
        (
            "ver-prev-none",
            dict(),
            dict(
                previous_detector_version=None,
                previous_run_at="2026-11-01T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
        # --- provider diff ------------------------------------------------------
        (
            "prov-diff-10d",
            dict(),
            dict(
                previous_provider_metadata={"a": 1},
                provider_metadata={"a": 2},
                previous_run_at="2026-11-01T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
        (
            "prov-diff-7d",
            dict(),
            dict(
                previous_provider_metadata={"a": 1},
                provider_metadata={"a": 2},
                previous_run_at="2026-11-04T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
        (
            "prov-diff-key",
            dict(),
            dict(
                previous_provider_metadata={"a": 1},
                provider_metadata={"a": 1, "b": 2},
                previous_run_at="2026-11-01T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
        (
            "prov-nodiff",
            dict(),
            dict(
                previous_provider_metadata={"a": 1},
                provider_metadata={"a": 1},
                previous_run_at="2026-11-01T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
        (
            "prov-prev-none",
            dict(),
            dict(
                previous_provider_metadata=None,
                provider_metadata={"a": 1},
                previous_run_at="2026-11-01T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
        (
            "prov-meta-none",
            dict(),
            dict(
                previous_provider_metadata={"a": 1},
                provider_metadata=None,
                previous_run_at="2026-11-01T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
        (
            "prov-no-run-at",
            dict(),
            dict(
                previous_provider_metadata={"a": 1},
                provider_metadata={"a": 2},
                previous_run_at=None,
                run_at="2026-11-11T00:00:00",
            ),
        ),
        # --- version / provider identity boundaries ------------------------
        # ver-distinct-equal: previous == current as DISTINCT objects.
        # `!=` is False, `is not` is True. Kills NotEq_IsNot:1 [1332,75].
        # (The existing "ver-same" row uses two literals "0.1.0" in one
        # function, which CPython interns to one object, so `is not` agrees.)
        (
            "ver-distinct-equal",
            dict(),
            dict(
                previous_detector_version="".join(["0", ".1.0"]),
                previous_run_at="2026-11-01T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
        # ver-prev-greater: previous sorts AFTER current. `!=` is True,
        # `<` is False. Kills NotEq_Lt:2 [1332,75]. (The existing rows
        # have previous "0.0.9" < current, where both agree True.)
        (
            "ver-prev-greater",
            dict(),
            dict(
                previous_detector_version="0.2.0",
                previous_run_at="2026-11-01T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
        # prov-distinct-equal: a shared provider key with distinct-equal
        # values. `!=` is False, `is not` is True. Kills NotEq_IsNot:2
        # [1361,20]. (The existing "prov-nodiff" row uses the literal 1,
        # which is the same cached int object on both sides.)
        (
            "prov-distinct-equal",
            dict(),
            dict(
                previous_provider_metadata={"a": "".join(["", "x"])},
                provider_metadata={"a": "x"},
                previous_run_at="2026-11-01T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
        # prov-diff-3d: a provider diff with only 3 days since the previous
        # run. `days > 7` is False; `days is not 7` and `days != 7` are both
        # True. Kills Gt_IsNot:8 [1367,31] and Gt_NotEq:12 [1367,31].
        # (The existing 7-day row agrees under every mutant: 7 > 7, 7 is
        # not 7 and 7 != 7 are all False.)
        (
            "prov-diff-3d",
            dict(),
            dict(
                previous_provider_metadata={"a": 1},
                provider_metadata={"a": 2},
                previous_run_at="2026-11-08T00:00:00",
                run_at="2026-11-11T00:00:00",
            ),
        ),
    ]
    for key, mk, ck in extra:
        rows.append(
            (
                (key,),
                outcome(
                    evaluate_tiers,
                    metrics=_et_metrics(**mk),
                    detector_version="0.1.0",
                    previous_breaches=[],
                    **ck,
                ),
            )
        )

    # --- multi-slice rows (the ContinueWithBreak / AddNot / Is_IsNot -----
    # mutants in the drift and flips loops only differ when a LATER slice
    # is reached after an EARLY slice triggers the guard). Slices sort
    # a..f, so the order is the list order.
    def _et_multi(specs):
        base = _tier_metrics()
        base["slices"] = {}
        for name, mk in specs:
            base["slices"][name] = _et_metrics(**mk)["slices"]["human-native"]
        return base

    # Drift loop: a skips (drift off), b breaches, c is below the floor,
    # d has no breach, e breaches, f breaches via the slice-n fallback
    # (shift without n_paired). Kills ContinueWithBreak:0 [1090,12] (a),
    # :1 [1102,12] (c), :2 [1105,12] (d), AddNot:62 [1099,11] and
    # Is_IsNot:6 [1099,20] (f: the `n_paired is None` fallback). The
    # single-slice "shift-npaired-none-n60" row does NOT kill Is_IsNot:6:
    # its shift is empty, so there is no breach to lose.
    rows.append(
        (
            ("multi-drift",),
            outcome(
                evaluate_tiers,
                metrics=_et_multi(
                    [
                        ("a", dict(psi=0.5, drift_allowed=False)),
                        ("b", dict(psi=0.5, n_paired=60)),
                        ("c", dict(psi=0.5, n_paired=49)),
                        ("d", dict(psi=None)),
                        ("e", dict(psi=0.5, n_paired=60)),
                        ("f", dict(psi=0.5, shift={"psi": 0.5}, slice_n=60)),
                    ]
                ),
                detector_version="0.1.0",
                previous_breaches=[],
            ),
        )
    )
    # Flips loop: a has no flips (drift off), b is a Tier-1 breaching
    # slice. Kills ContinueWithBreak:3 [1168,12] (`if not flips: continue`
    # -> break: the mutant never reaches b's breach).
    rows.append(
        (
            ("multi-flips",),
            outcome(
                evaluate_tiers,
                metrics=_et_multi(
                    [
                        ("a", dict(flips="absent", drift_allowed=False)),
                        (
                            "b",
                            dict(
                                flips=_et_flips(
                                    n=60,
                                    flips=3,
                                    rate=0.06,
                                    human_to_ai=3,
                                    n_human_paired=50,
                                    human_to_ai_human=3,
                                )
                            ),
                        ),
                    ]
                ),
                detector_version="0.1.0",
                previous_breaches=[],
            ),
        )
    )
    return rows


# ---------------------------------------------------------------------------
# policy._claim_is_effective (NotEq_IsNot / Eq_Is enum identity)
# ---------------------------------------------------------------------------


def probe_policy_claim_effective():
    from datetime import date

    from textforensics.policy import EvidenceTier, _claim_is_effective

    rows = []
    for tier in (EvidenceTier.VALIDATED, EvidenceTier.READABLE, EvidenceTier.TOOL_BACKED):
        for valid_until in (None, "2999-01-01", "2000-01-01"):
            claim = _ledger_claim(tier_name=tier.name, valid_until=valid_until)
            rows.append(
                (
                    (tier.name, valid_until),
                    outcome(_claim_is_effective, claim, today=date(2026, 11, 11)),
                )
            )
    # evidence-ref label variants (EXECUTED vs others)
    from textforensics.policy import CapabilityClaim, EvidenceLabel, EvidenceRef

    for label in (
        EvidenceLabel.EXECUTED,
        EvidenceLabel.REPORTED,
        EvidenceLabel.CALCULATED,
        EvidenceLabel.PROPOSED,
    ):
        claim = CapabilityClaim(
            detector_id="a",
            capability="language",
            tier=EvidenceTier.VALIDATED,
            evidence=[
                EvidenceRef(label=label, tier=EvidenceTier.VALIDATED, artifact="runs/1.json")
            ],
        )
        rows.append(
            (("label", label.name), outcome(_claim_is_effective, claim, today=date(2026, 11, 11)))
        )
    return rows


# ---------------------------------------------------------------------------
# calibration
# ---------------------------------------------------------------------------


def _hex64(seed):
    return f"{seed:064x}"


def _platt_curve(**over):
    from textforensics.calibration import CalibrationCurve

    kw = dict(
        method="platt",
        parameters={"A": 1.0, "B": 0.0},
        reference_dataset_hash=_hex64(1),
        reference_dataset_name="test",
        calibrated_at="2024-01-01T00:00:00Z",
        sample_count=200,
    )
    kw.update(over)
    return CalibrationCurve(**kw)


def probe_cal_post_init():
    from textforensics.calibration import CURVE_SCHEMA, LEGACY_CURVE_SCHEMA, CalibrationCurve

    rows = []
    for method in ("platt", "temperature", "isotonic", "beta", "identity", "unknown", ""):
        for schema in (CURVE_SCHEMA, LEGACY_CURVE_SCHEMA, "wrong"):
            for semantics in ("probability", "logit", "legacy_raw_score", "bogus"):
                for direction in ("higher_means_ai", "lower_means_ai", "bogus"):
                    rows.append(
                        (
                            (method, schema, semantics, direction),
                            outcome(
                                CalibrationCurve,
                                method=method,
                                parameters={"A": 1.0, "B": 0.0},
                                schema=schema,
                                input_semantics=semantics,
                                native_score_direction=direction,
                            ),
                        )
                    )
    return rows


def probe_cal_calibrate():
    rows = []
    for method, params in (
        ("platt", {"A": 1.0, "B": 0.0}),
        ("temperature", {"T": 2.0}),
        ("isotonic", {"x": [0.0, 0.5, 1.0], "y": [0.0, 0.5, 1.0]}),
        ("beta", {"a": 2.0, "b": 2.0}),
        ("identity", {}),
    ):
        for semantics in ("probability", "logit", "legacy_raw_score"):
            for direction in ("higher_means_ai", "lower_means_ai"):
                try:
                    curve = _platt_curve(
                        method=method,
                        parameters=params,
                        input_semantics=semantics,
                        native_score_direction=direction,
                    )
                except Exception as exc:  # noqa: BLE001
                    rows.append(
                        ((method, semantics, direction), ("raise", type(exc).__name__, str(exc)))
                    )
                    continue
                for score in (0.0, 0.25, 0.5, 0.75, 1.0, -1.0, 2.0):
                    rows.append(
                        ((method, semantics, direction, score), outcome(curve.calibrate, score))
                    )
    # LEGACY-schema temperature + legacy_raw_score: the only construction
    # that reaches the legacy branch of calibrate (line 506+). CURVE schema
    # + legacy_raw_score raises in __post_init__, so this branch was
    # previously unexercised. Kills Eq_LtE:13 [506,65] (out-of-range scores
    # raise under _unit_interval, pass under _finite_number) and
    # Div_Mul:3 / Div_Mod:3 / Div_Pow:3 [516,38] (value / T in the legacy
    # branch; T=2, scores 0.25/0.75/1.0 separate / from * / % / **).
    from textforensics.calibration import LEGACY_CURVE_SCHEMA

    for direction in ("higher_means_ai", "lower_means_ai"):
        try:
            curve = _platt_curve(
                method="temperature",
                parameters={"T": 2.0},
                schema=LEGACY_CURVE_SCHEMA,
                input_semantics="legacy_raw_score",
                native_score_direction=direction,
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(
                (
                    ("legacy-temperature", "legacy_raw_score", direction),
                    ("raise", type(exc).__name__, str(exc)),
                )
            )
            continue
        for score in (0.0, 0.25, 0.5, 0.75, 1.0, -1.0, 2.0):
            rows.append(
                (
                    ("legacy-temperature", "legacy_raw_score", direction, score),
                    outcome(curve.calibrate, score),
                )
            )
    return rows


def _scored_jsonl(path):
    import json

    rows = [{"label": "human", "text": f"human observation {i}"} for i in range(4)] + [
        {"label": "ai", "text": f"ai sample {i}"} for i in range(4)
    ]
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def _eval_with_proof(
    eval_path,
    status,
    overlap,
    diagnostic,
    *,
    evaluation_hash=None,
    training_hash=None,
    calibration_dataset_hash=None,
    allow_same_dataset=False,
):
    from textforensics.benchmark import DisjointnessProof, dataset_sha256
    from textforensics.calibration import evaluate_threshold

    proof = DisjointnessProof(
        status=status,
        overlap_count=overlap,
        training_count=8,
        evaluation_count=8,
        training_hash=_hex64(1) if training_hash is None else training_hash,
        evaluation_hash=dataset_sha256(eval_path) if evaluation_hash is None else evaluation_hash,
        errors=(),
    )
    return evaluate_threshold(
        eval_path,
        0.5,
        disjointness_proof=proof,
        diagnostic=diagnostic,
        calibration_dataset_hash=calibration_dataset_hash,
        allow_same_dataset=allow_same_dataset,
    )


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
                    rows.append(
                        (
                            (status, overlap, diagnostic),
                            outcome(_eval_with_proof, eval_path, status, overlap, diagnostic),
                        )
                    )
        # Hash-mismatch directions at [1886,85] (evaluation_hash != test_hash):
        # "0"*64 < any real sha kills NotEq_Gt:22 (mutant `>` is False, so no
        # raise) and NotEq_Is:18 (mutant `is` is False, so no raise);
        # "f"*64 > any real sha kills NotEq_Lt:22 (mutant `<` is False).
        for ev_hash, tag in (("0" * 64, "eval-hash-zero"), ("f" * 64, "eval-hash-max")):
            rows.append(
                (
                    (tag, "verified", 0, False),
                    outcome(
                        _eval_with_proof, eval_path, "verified", 0, False, evaluation_hash=ev_hash
                    ),
                )
            )
        # Training-hash mismatch directions at [1891,49]
        # (training_hash != calibration_dataset_hash).
        for tr_hash, tag in (("0" * 64, "train-hash-zero"), ("f" * 64, "train-hash-max")):
            rows.append(
                (
                    (tag, "verified", 0, False),
                    outcome(
                        _eval_with_proof,
                        eval_path,
                        "verified",
                        0,
                        False,
                        training_hash=tr_hash,
                        calibration_dataset_hash=_hex64(2),
                    ),
                )
            )
        # Same-object equal hashes: `is` is True, so the NotEq_Is:19 mutant
        # raises where the original does not.
        shared = _hex64(1)
        rows.append(
            (
                ("train-hash-shared", "verified", 0, False),
                outcome(
                    _eval_with_proof,
                    eval_path,
                    "verified",
                    0,
                    False,
                    training_hash=shared,
                    calibration_dataset_hash=shared,
                ),
            )
        )
        # allow_same_dataset + proof: Eq_GtE:37 [1905,53]
        # (contamination_detected == "contaminated" -> >=): "verified" and
        # "unknown" both sort above "contaminated", so the mutant reports
        # contamination where the original does not.
        for status in ("verified", "unknown"):
            rows.append(
                (
                    (f"allow-same-{status}", status, 0, False),
                    outcome(_eval_with_proof, eval_path, status, 0, False, allow_same_dataset=True),
                )
            )
        # allow_same_dataset + proof=None + cal hash below the test hash:
        # Eq_GtE:36 [1899,52] (test_hash == cal -> >=): the mutant takes the
        # "contaminated" branch, the original the "unknown" branch
        # (overlap_count -1). Also exercises the [1904,28/29] -1 rows.
        from textforensics.benchmark import dataset_sha256
        from textforensics.calibration import evaluate_threshold

        rows.append(
            (
                ("allow-same-noproof-cal-low",),
                outcome(
                    evaluate_threshold,
                    eval_path,
                    0.5,
                    calibration_dataset_hash="0" * 64,
                    diagnostic=False,
                    allow_same_dataset=True,
                ),
            )
        )
        # proof=None + allow_same_dataset=False: ReplaceFalseWithTrue:19
        # [1910,33] (contamination_detected False -> True) and the
        # [1909,24/25] overlap_count=-1 rows.
        for diagnostic in (False, True):
            rows.append(
                (
                    (f"noproof-diag-{diagnostic}",),
                    outcome(evaluate_threshold, eval_path, 0.5, diagnostic=diagnostic),
                )
            )
        # Same-dataset hash match (no proof): disjointness_status is
        # "contaminated" via the calibration_dataset_hash branch. This is the
        # only way evaluate_threshold reaches the contaminated comparison
        # without raising first.
        # allow_same_dataset=True is REQUIRED to reach the contaminated
        # comparison: without it the hash match raises before line 1905.
        for diagnostic in (False, True):
            rows.append(
                (
                    ("hash-match", -1, diagnostic),
                    outcome(
                        evaluate_threshold,
                        eval_path,
                        0.5,
                        calibration_dataset_hash=dataset_sha256(eval_path),
                        diagnostic=diagnostic,
                        allow_same_dataset=True,
                    ),
                )
            )
    return rows


def probe_cal_from_dict():
    from textforensics.calibration import CalibrationCurve

    rows = []
    params_for = {
        "platt": {"A": 1.0, "B": 0.0},
        "temperature": {"T": 2.0},
        "isotonic": {"x": [0.0, 0.5, 1.0], "y": [0.0, 0.5, 1.0]},
        "beta": {"a": 2.0, "b": 2.0},
        "identity": {},
    }
    for schema in (
        "textforensics.calibration-curve/v3",
        "textforensics.calibration-curve/v2",
        "wrong",
    ):
        for method, params in params_for.items():
            d = dict(
                _platt_curve(method=method, parameters=params).to_dict(),
                schema=schema,
                method=method,
            )
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
        # Identical files with a bad-JSON line: the identical branch counts
        # valid samples with strict=False (count 2); the strict=True mutant
        # (ReplaceFalseWithTrue:23 [2002,71]) raises and falls to count 0.
        bad = Path(tmp) / "bad.jsonl"
        # 2 valid rows + 1 bad-JSON line.
        bad.write_text(
            "".join(
                _json.dumps(r) + "\n"
                for r in [
                    {"label": "human", "text": "human observation 0"},
                    {"label": "ai", "text": "ai sample 0"},
                ]
            )
            + "this is not json\n"
        )
        rows.append((("bad-json-identical",), outcome(validate_no_contamination, bad, bad)))
        # Identical files with invalid UTF-8: dataset_sha256 reads bytes
        # fine, but the sample hasher decodes UTF-8 and raises
        # UnicodeDecodeError. Kills ExceptionReplacer:14 [2003,15] (the
        # `except Exception` guard) and NumberReplacer:188/189 [2004,20]
        # (the except's count 0 -> 1/-1).
        bad8 = Path(tmp) / "bad8.jsonl"
        bad8.write_bytes(b'{"label": "human", "text": "ok"}\n\xff\xfe bad utf8\n')
        rows.append((("bad-utf8-identical",), outcome(validate_no_contamination, bad8, bad8)))
        # Partial overlap + one bad-JSON line each: prove_disjointness
        # (strict=False) reports contaminated; the shared-hash recompute
        # with strict=False skips the bad lines, while the strict=True
        # mutants (ReplaceFalseWithTrue:27 [2033,76] and :28 [2034,70])
        # raise and fall back to shared=[].
        cal2 = Path(tmp) / "cal2.jsonl"
        ev2 = Path(tmp) / "ev2.jsonl"
        shared_rows = [{"label": "human", "text": f"shared {i}"} for i in range(3)]
        cal2.write_text(
            "".join(
                _json.dumps(r) + "\n"
                for r in shared_rows + [{"label": "human", "text": "cal only"}]
            )
            + "not json\n"
        )
        ev2.write_text(
            "".join(
                _json.dumps(r) + "\n" for r in shared_rows + [{"label": "ai", "text": "ev only"}]
            )
            + "not json either\n"
        )
        rows.append((("partial-overlap-bad-json",), outcome(validate_no_contamination, cal2, ev2)))
        # Empty side: prove_disjointness returns "unknown" with non-empty
        # errors, so the warning is the joined errors. Kills OrWithAnd:32
        # [2028,52] (`or` -> `and` yields the fallback message instead).
        empty = Path(tmp) / "empty.jsonl"
        empty.write_text("")
        rows.append((("empty-side",), outcome(validate_no_contamination, empty, a)))
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
                rows.append(
                    (
                        (status, overlap, group),
                        outcome(
                            DisjointnessProof,
                            status=status,
                            overlap_count=overlap,
                            group_overlap_count=group,
                            training_count=8,
                            evaluation_count=8,
                            training_hash=_hex64(1),
                            evaluation_hash=_hex64(2),
                            errors=(),
                        ),
                    )
                )
    # Invalid counts: the validation loops never fire on the grid above
    # (all counts valid), so these rows are the only ones that reach them.
    # Kills ZeroIteration:4/5 (no validation at all), OrWithAnd:7/8/9/10
    # (the `or` chain becomes `and`), USub_Invert:4 and
    # NumberReplacer:72/75 (the -1/0 bound literals).
    for field in ("overlap_count", "group_overlap_count"):
        for value in (True, -2, "x"):
            kw = dict(
                status="verified",
                overlap_count=0,
                group_overlap_count=0,
                training_count=8,
                evaluation_count=8,
                training_hash=_hex64(1),
                evaluation_hash=_hex64(2),
                errors=(),
            )
            kw[field] = value
            rows.append(((f"invalid-{field}", value), outcome(DisjointnessProof, **kw)))
    for field in ("training_count", "evaluation_count"):
        for value in (True, -1, "x"):
            kw = dict(
                status="verified",
                overlap_count=0,
                group_overlap_count=0,
                training_count=8,
                evaluation_count=8,
                training_hash=_hex64(1),
                evaluation_hash=_hex64(2),
                errors=(),
            )
            kw[field] = value
            rows.append(((f"invalid-{field}", value), outcome(DisjointnessProof, **kw)))
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
            (
                [
                    {"label": "human", "text": "different human sentence."},
                    {"label": "ai", "text": "different ai sentence."},
                ],
                "disjoint",
            ),
            (
                [
                    {"label": "human", "text": "human sentence 0."},
                    {"label": "ai", "text": "different ai sentence."},
                ],
                "overlap",
            ),
            ([], "empty-eval"),
            ([{"label": "human", "text": "human sentence 0."}], "train-only-human"),
        ):
            _proof_rows(ev, ev_rows)
            rows.append(((label,), outcome(prove_disjointness, train, ev)))
        _proof_rows(train, [])
        _proof_rows(ev, human)
        rows.append((("empty-train",), outcome(prove_disjointness, train, ev)))
        # --- missing files (hash OSError excepts) -------------------------
        rows.append((("missing-train",), outcome(prove_disjointness, Path(tmp) / "nope.jsonl", ev)))
        rows.append(
            (("missing-eval",), outcome(prove_disjointness, train, Path(tmp) / "nope.jsonl"))
        )
        rows.append(
            (
                ("missing-both",),
                outcome(prove_disjointness, Path(tmp) / "nope1.jsonl", Path(tmp) / "nope2.jsonl"),
            )
        )
        # --- bad lines (samples Exception excepts; strict True/False) -----
        _proof_rows(train, human + ai)
        bad_train = Path(tmp) / "bad-train.jsonl"
        bad_train.write_text(
            '{"label": "human", "text": "Good one."}\nNOT JSON\n', encoding="utf-8"
        )
        bad_ev = Path(tmp) / "bad-eval.jsonl"
        bad_ev.write_text('{"label": "human", "text": "Good one."}\nNOT JSON\n', encoding="utf-8")
        _proof_rows(ev, human + ai)
        rows.append((("bad-train-strict",), outcome(prove_disjointness, bad_train, ev)))
        rows.append((("bad-eval-strict",), outcome(prove_disjointness, train, bad_ev)))
        rows.append(
            (("bad-train-lenient",), outcome(prove_disjointness, bad_train, ev, strict=False))
        )
        rows.append(
            (("bad-eval-lenient",), outcome(prove_disjointness, train, bad_ev, strict=False))
        )
        rows.append(
            (("bad-both-lenient",), outcome(prove_disjointness, bad_train, bad_ev, strict=False))
        )
        # --- group overlap (same source id, different text) --------------
        _proof_rows(
            train,
            [
                {"label": "human", "text": "train text one.", "source_document_id": "doc-shared"},
                {"label": "ai", "text": "train text two."},
            ],
        )
        _proof_rows(
            ev,
            [
                {"label": "human", "text": "eval text one.", "source_document_id": "doc-shared"},
                {"label": "ai", "text": "eval text two."},
            ],
        )
        rows.append((("group-overlap",), outcome(prove_disjointness, train, ev)))
        # --- group overlap via normalized text (case/whitespace variant) --
        _proof_rows(train, [{"label": "human", "text": "  Hello   WORLD. "}])
        _proof_rows(ev, [{"label": "human", "text": "hello world."}])
        rows.append((("group-normalized-overlap",), outcome(prove_disjointness, train, ev)))
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
        DisjointnessProof,
        benchmark_with_calibration_jsonl,
        calibrate_threshold_jsonl,
        dataset_sha256,
        prove_disjointness,
    )

    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        cal = Path(tmp) / "cal.jsonl"
        ev = Path(tmp) / "eval.jsonl"
        _proof_rows(
            cal,
            [
                {"label": "human", "text": "human sentence one."},
                {"label": "ai", "text": "ai sentence one."},
            ],
        )
        _proof_rows(
            ev,
            [
                {"label": "human", "text": "human sentence two."},
                {"label": "ai", "text": "ai sentence two."},
            ],
        )
        artifact = calibrate_threshold_jsonl(cal, target_fpr=0.0)
        # verified proof from the real disjointness check
        proof = prove_disjointness(cal, ev)
        rows.append(
            (
                ("verified",),
                outcome(benchmark_with_calibration_jsonl, ev, artifact, disjointness_proof=proof),
            )
        )
        # unknown / contaminated proofs with matching hashes
        for status, overlap in (("unknown", -1), ("contaminated", 1)):
            proof = DisjointnessProof(
                status=status,
                overlap_count=overlap,
                training_count=2,
                evaluation_count=2,
                training_hash=dataset_sha256(cal),
                evaluation_hash=dataset_sha256(ev),
                errors=(),
            )
            rows.append(
                (
                    (status,),
                    outcome(
                        benchmark_with_calibration_jsonl, ev, artifact, disjointness_proof=proof
                    ),
                )
            )
        # no proof at all (diagnostic mode)
        rows.append(
            (("none",), outcome(benchmark_with_calibration_jsonl, ev, artifact, diagnostic=True))
        )
        # --- hash-mismatch proofs (both orderings) -------------------------
        ev_sha = dataset_sha256(ev)
        for tag, ehash, thash in (
            ("eval-hash-lo", "0" * 64, dataset_sha256(cal)),
            ("eval-hash-hi", "f" * 64, dataset_sha256(cal)),
            ("train-hash-lo", ev_sha, "0" * 64),
            ("train-hash-hi", ev_sha, "f" * 64),
            ("eval-hash-none", None, dataset_sha256(cal)),
            ("train-hash-none", ev_sha, None),
        ):
            proof = DisjointnessProof(
                status="verified",
                overlap_count=0,
                training_count=2,
                evaluation_count=2,
                training_hash=thash,
                evaluation_hash=ehash,
                errors=(),
            )
            rows.append(
                (
                    (tag,),
                    outcome(
                        benchmark_with_calibration_jsonl, ev, artifact, disjointness_proof=proof
                    ),
                )
            )
        # --- allow_same_dataset: same file / different file / no proof -----
        rows.append(
            (
                ("same-file-allowed",),
                outcome(benchmark_with_calibration_jsonl, cal, artifact, allow_same_dataset=True),
            )
        )
        same_proof = DisjointnessProof(
            status="verified",
            overlap_count=0,
            training_count=2,
            evaluation_count=2,
            training_hash=dataset_sha256(cal),
            evaluation_hash=dataset_sha256(cal),
            errors=(),
        )
        rows.append(
            (
                ("same-file-allowed-proof",),
                outcome(
                    benchmark_with_calibration_jsonl,
                    cal,
                    artifact,
                    allow_same_dataset=True,
                    disjointness_proof=same_proof,
                ),
            )
        )
        rows.append(
            (
                ("diff-file-allowed-noproof",),
                outcome(benchmark_with_calibration_jsonl, ev, artifact, allow_same_dataset=True),
            )
        )
        rows.append(
            (("same-file-not-allowed",), outcome(benchmark_with_calibration_jsonl, cal, artifact))
        )
        # Swapped calibration: calibrate on ev, evaluate on cal. Here the
        # evaluation sha (78b4...) is GREATER than the calibration sha
        # (75e7...), which kills Eq_GtE:7 [286,28] (evaluation_sha ==
        # calibration sha -> >=): the mutant takes the "contaminated"
        # branch, the original the "unknown" branch. (The unswapped
        # diff-file row has evaluation_sha < calibration_sha, so `>=` and
        # `==` agree there.)
        artifact_swapped = calibrate_threshold_jsonl(ev, target_fpr=0.0)
        rows.append(
            (
                ("swapped-allowed-noproof",),
                outcome(
                    benchmark_with_calibration_jsonl, cal, artifact_swapped, allow_same_dataset=True
                ),
            )
        )
        # --- contaminated / unknown proofs without diagnostic (raise) ------
        for status, overlap in (("contaminated", 1), ("unknown", -1)):
            proof = DisjointnessProof(
                status=status,
                overlap_count=overlap,
                training_count=2,
                evaluation_count=2,
                training_hash=dataset_sha256(cal),
                evaluation_hash=dataset_sha256(ev),
                errors=("test error",),
            )
            rows.append(
                (
                    (f"{status}-nodq",),
                    outcome(
                        benchmark_with_calibration_jsonl, ev, artifact, disjointness_proof=proof
                    ),
                )
            )
            rows.append(
                (
                    (f"{status}-dq",),
                    outcome(
                        benchmark_with_calibration_jsonl,
                        ev,
                        artifact,
                        disjointness_proof=proof,
                        diagnostic=True,
                    ),
                )
            )
    return rows


# ---------------------------------------------------------------------------
# evidence
# ---------------------------------------------------------------------------


def _ev_record(
    *,
    evaluated_at="2026-11-01T00:00:00Z",
    status="active",
    n_human=120,
    n_ai=120,
    detector_version="1",
):
    from textforensics.evidence import (
        BenchmarkProvenance,
        EvidenceRecord,
        MetricEstimate,
        RunProvenance,
        SliceConditions,
        ValidationSlice,
    )

    slice_ = ValidationSlice(
        slice_id="s1",
        conditions=SliceConditions(
            languages=("en",), domains=("general",), editing_regimes=("human_only",)
        ),
        n_human=n_human,
        n_ai=n_ai,
        metrics={
            "auroc": MetricEstimate(
                value=0.8, n=n_human + n_ai, ci_lower=0.7, ci_upper=0.9, method="bootstrap"
            )
        },
        threshold=0.5,
    )
    return EvidenceRecord(
        evidence_id="ev-1",
        detector_id="det",
        detector_version=detector_version,
        detector_family="fam",
        evaluated_at_utc=evaluated_at,
        benchmark=BenchmarkProvenance(
            name="raid",
            version="1.0",
            fingerprint_sha256=_hex64(1),
            split="test",
            license="MIT",
            artifact_path="data/raid.jsonl",
            artifact_sha256=_hex64(2),
            contamination_controls=("disjoint_sample_ids",),
        ),
        slices=(slice_,),
        provenance=RunProvenance(
            git_sha="abc1234",
            command="textforensics benchmark",
            environment_sha256=_hex64(3),
            executed_at_utc=evaluated_at,
            run_artifact_path="runs/1.json",
            run_artifact_sha256=_hex64(4),
        ),
        status=status,
    )


def _ev_slice(*, n_human=120, n_ai=120, cond_over=None, fpr="default"):
    from textforensics.evidence import MetricEstimate, SliceConditions, ValidationSlice

    cond_kw = dict(languages=("en",), domains=("general",), editing_regimes=("human_only",))
    if cond_over:
        cond_kw.update(cond_over)
    if fpr == "default":
        metrics = {
            "auroc": MetricEstimate(
                value=0.8, n=n_human + n_ai, ci_lower=0.7, ci_upper=0.9, method="bootstrap"
            )
        }
    elif fpr is None:
        metrics = {}
    else:
        metrics = {"fpr": fpr}
    return ValidationSlice(
        slice_id="s1",
        conditions=SliceConditions(**cond_kw),
        n_human=n_human,
        n_ai=n_ai,
        metrics=metrics,
        threshold=0.5,
    )


def _ev_fpr(*, value=0.02, has_ci=True, ci_upper=0.03, ci_lower=0.01, n=120):
    """An fpr metric. MetricEstimate requires both CI bounds or neither,
    so has_ci=False means both bounds None; a lone ci_upper is
    unconstructible (and AndWithOr:35/36 are equivalent for that reason)."""
    from textforensics.evidence import MetricEstimate

    if has_ci:
        return MetricEstimate(
            value=value, n=n, ci_lower=ci_lower, ci_upper=ci_upper, method="wilson"
        )
    return MetricEstimate(value=value, n=n, ci_lower=None, ci_upper=None, method="wilson")


def probe_ev_record_candidate():
    from datetime import UTC, datetime

    from textforensics.evidence import SliceMatch, _record_candidate_for_dimension

    rows = []
    now = datetime(2026, 11, 11, tzinfo=UTC)

    def _run(dimension, match, record, slice_, key):
        try:
            cand = _record_candidate_for_dimension(
                record=record,
                slice_=slice_,
                match=match,
                now=now,
                max_age_days=30,
                dimension=dimension,
                fpr_ceiling=0.05,
            )
            if cand is None:
                rows.append((key, ("ok", None)))
            else:
                rows.append((key, ("ok", cand.state, cand.reason, cand.observed.get("age_days"))))
        except Exception as exc:  # noqa: BLE001
            rows.append((key, ("raise", type(exc).__name__, str(exc))))

    for dimension in (
        "language",
        "text_length",
        "domain_genre",
        "editing_revision",
        "generator_scope",
        "human_population",
        "human_false_positive_evidence",
        "temporal_version_stability",
    ):
        for match_vals in (
            ("match", "match", "match", "match"),
            ("unknown", "unknown", "unknown", "unknown"),
            ("mismatch", "mismatch", "mismatch", "mismatch"),
            ("match", "mismatch", "unknown", "match"),
        ):
            match = SliceMatch(
                language=match_vals[0],
                length=match_vals[1],
                domain=match_vals[2],
                editing=match_vals[3],
                applicable=True,
            )
            for age, nh, na in (
                ("2026-11-01T00:00:00Z", 120, 120),  # fresh + adequate
                ("2026-09-01T00:00:00Z", 120, 120),  # stale-ish
                ("2026-01-01T00:00:00Z", 120, 120),  # unknown fresh
                ("2026-11-01T00:00:00Z", 10, 10),
            ):  # partial sample
                record = _ev_record(evaluated_at=age, n_human=nh, n_ai=na)
                slice_ = _ev_slice(n_human=nh, n_ai=na)
                _run(dimension, match, record, slice_, (dimension, match_vals, age, nh))
    # --- fresh == "partial" (age 31..60 days) + fractional ages -----------
    for age, nh, na in (
        ("2026-10-01T00:00:00Z", 120, 120),  # 41d -> partial
        ("2026-10-01T00:00:00Z", 10, 10),  # partial + partial
        ("2026-11-10T10:40:48Z", 120, 120),  # 0.555d -> round() grid
        ("2026-10-12T00:00:00Z", 120, 120),
    ):  # 30d exactly
        for dimension in (
            "language",
            "text_length",
            "domain_genre",
            "editing_revision",
            "generator_scope",
            "human_population",
            "human_false_positive_evidence",
            "temporal_version_stability",
        ):
            match = SliceMatch(
                language="match", length="match", domain="match", editing="match", applicable=True
            )
            record = _ev_record(evaluated_at=age, n_human=nh, n_ai=na)
            slice_ = _ev_slice(n_human=nh, n_ai=na)
            _run(dimension, match, record, slice_, (dimension, ("match",) * 4, age, nh))
    # --- generator scope / population shapes ------------------------------
    for scope, gens, pops in (
        ("representative", ("g1", "g2", "g3"), ("p1", "p2")),
        ("multi", ("g1", "g2", "g3"), ("p1",)),
        ("multi", ("g1", "g2"), ("p1", "p2")),
        ("multi", ("g1",), ("representative",)),
        ("single", ("g1",), ("p1",)),
        ("single", (), ()),
        ("unknown", (), ("p1",)),
        ("unknown", ("g1",), ()),
        # scope > "multi" with >= 3 generators: kills Eq_GtE:39
        # [1488,47] (`scope == "multi"` -> `>=`): the mutant takes the
        # first branch, the original the `elif generators:` branch.
        ("single", ("g1", "g2", "g3"), ("p1",)),
        ("unknown", ("g1", "g2", "g3"), ("p1",)),
        # 4 generators with scope "multi": kills GtE_Eq:4 [1488,78]
        # (`len(generators) >= 3` -> `== 3`).
        ("multi", ("g1", "g2", "g3", "g4"), ("p1",)),
        # 3 distinct populations: kills GtE_Eq:5 [1513,33]
        # (`len(set(populations)) >= 2` -> `== 2`).
        ("multi", ("g1", "g2", "g3"), ("p1", "p2", "p3")),
    ):
        for age in ("2026-11-01T00:00:00Z", "2026-01-01T00:00:00Z"):
            match = SliceMatch(
                language="match", length="match", domain="match", editing="match", applicable=True
            )
            record = _ev_record(evaluated_at=age)
            slice_ = _ev_slice(
                cond_over={"generators": gens, "generator_scope": scope, "human_populations": pops}
            )
            for dimension in ("generator_scope", "human_population"):
                _run(dimension, match, record, slice_, (dimension, (scope, gens, pops), age, 120))
    # --- mixed fresh/sample shapes (reach the supported/partial line) -----
    # The default slice has scope "unknown" with no generators, so it never
    # reaches the `state = "supported" if fresh == ...` line; only the
    # shape rows do, and the shapes above use fresh+sample supported or
    # fresh unknown only. These rows mix them: fresh partial + sample
    # supported kills Eq_LtE:40 / Eq_LtE:47 (fresh <= "supported") and
    # AndWithOr:30 / AndWithOr:32 (and -> or); fresh supported + sample
    # partial kills Eq_LtE:41 / Eq_LtE:48 (sample <= "supported").
    for scope, gens, pops, age, nh in (
        ("multi", ("g1", "g2", "g3"), ("p1",), "2026-10-01T00:00:00Z", 120),
        ("multi", ("g1", "g2", "g3"), ("p1",), "2026-11-01T00:00:00Z", 10),
        ("multi", ("g1", "g2", "g3"), ("p1", "p2"), "2026-10-01T00:00:00Z", 120),
        ("multi", ("g1", "g2", "g3"), ("p1", "p2"), "2026-11-01T00:00:00Z", 10),
    ):
        match = SliceMatch(
            language="match", length="match", domain="match", editing="match", applicable=True
        )
        record = _ev_record(evaluated_at=age, n_human=nh, n_ai=nh)
        slice_ = _ev_slice(
            n_human=nh,
            n_ai=nh,
            cond_over={"generators": gens, "generator_scope": scope, "human_populations": pops},
        )
        for dimension in ("generator_scope", "human_population"):
            _run(dimension, match, record, slice_, (dimension, (scope, gens, pops), age, nh))
    # --- single-field mismatch (reaches the guarded mismatch lines) ------
    for match_vals in (
        ("mismatch", "match", "match", "match"),
        ("match", "mismatch", "match", "match"),
        ("match", "match", "mismatch", "match"),
        ("match", "match", "match", "mismatch"),
        ("match", "match", "unknown", "match"),
        ("match", "match", "match", "unknown"),
    ):
        match = SliceMatch(
            language=match_vals[0],
            length=match_vals[1],
            domain=match_vals[2],
            editing=match_vals[3],
            applicable=True,
        )
        for dimension in (
            "language",
            "text_length",
            "domain_genre",
            "editing_revision",
            "generator_scope",
            "human_population",
            "human_false_positive_evidence",
            "temporal_version_stability",
        ):
            record = _ev_record()
            slice_ = _ev_slice()
            _run(
                dimension,
                match,
                record,
                slice_,
                (dimension, match_vals, "2026-11-01T00:00:00Z", 120),
            )
    # --- out-of-vocabulary match values + dimensions ----------------------
    for field, val in (
        ("language", "zzz"),
        ("language", "aaa"),
        ("length", "zzz"),
        ("length", "aaa"),
        ("domain", "zzz"),
        ("domain", "aaa"),
        ("editing", "zzz"),
        ("editing", "aaa"),
    ):
        vals = {"language": "match", "length": "match", "domain": "match", "editing": "match"}
        vals[field] = val
        match = SliceMatch(
            language=vals["language"],
            length=vals["length"],
            domain=vals["domain"],
            editing=vals["editing"],
            applicable=True,
        )
        for dimension in (
            "language",
            "text_length",
            "domain_genre",
            "editing_revision",
            "generator_scope",
            "human_population",
            "human_false_positive_evidence",
            "temporal_version_stability",
        ):
            record = _ev_record()
            slice_ = _ev_slice()
            _run(
                dimension,
                match,
                record,
                slice_,
                (dimension, (field, val), "2026-11-01T00:00:00Z", 120),
            )
    for dimension in ("zzz", "aaa", "LANGUAGE", ""):
        match = SliceMatch(
            language="match", length="match", domain="match", editing="match", applicable=True
        )
        record = _ev_record()
        slice_ = _ev_slice()
        _run(
            dimension,
            match,
            record,
            slice_,
            (dimension, ("match",) * 4, "2026-11-01T00:00:00Z", 120),
        )
    # --- human-false-positive section: fpr metric shapes ------------------
    for nh, fpr in (
        (120, _ev_fpr(n=120)),
        (99, _ev_fpr(n=99)),
        (100, _ev_fpr(n=100)),
        (101, _ev_fpr(n=101)),
        (120, _ev_fpr(ci_upper=0.05, n=120)),
        (120, _ev_fpr(ci_upper=0.07, n=120)),
        (120, _ev_fpr(has_ci=False, n=120)),
        (120, None),
    ):
        for age in ("2026-11-01T00:00:00Z", "2026-10-01T00:00:00Z", "2026-01-01T00:00:00Z"):
            match = SliceMatch(
                language="match", length="match", domain="match", editing="match", applicable=True
            )
            record = _ev_record(evaluated_at=age, n_human=nh, n_ai=120)
            slice_ = _ev_slice(n_human=nh, n_ai=120, fpr=fpr)
            _run(
                "human_false_positive_evidence",
                match,
                record,
                slice_,
                (
                    "human_false_positive_evidence",
                    (nh, getattr(fpr, "ci_upper", None), getattr(fpr, "has_ci", None)),
                    age,
                    nh,
                ),
            )
    return rows


def probe_ev_check_eligibility():
    from datetime import UTC, datetime

    from textforensics.evidence import (
        DisjointnessProof,
        InferenceIdentity,
        check_record_eligibility,
    )

    rows = []
    now = datetime(2026, 11, 11, tzinfo=UTC)
    for status in ("active", "retracted"):
        for age in ("2026-11-01T00:00:00Z", "2026-01-01T00:00:00Z"):
            record = _ev_record(evaluated_at=age, status=status)
            for regime in ("human_only", "raw"):
                identity = InferenceIdentity(
                    detector_id="det",
                    detector_version="1",
                    provider=None,
                    model=None,
                    config_hash=None,
                    native_score_semantics=None,
                    calibration_id=None,
                    regime=regime,
                )
                for dj_status, dj_overlap in (
                    ("verified", 0),
                    ("unknown", 0),
                    ("contaminated", 1),
                    (None, None),
                ):
                    dj = (
                        None
                        if dj_status is None
                        else DisjointnessProof(
                            status=dj_status,
                            overlap_count=dj_overlap,
                            training_count=1000,
                            evaluation_count=400,
                            training_hash=_hex64(9),
                            evaluation_hash=record.benchmark.fingerprint_sha256,
                        )
                    )
                    try:
                        v = check_record_eligibility(
                            record, identity=identity, disjointness=dj, now=now, max_age_days=30
                        )
                        rows.append(
                            (
                                (status, age, regime, dj_status),
                                (
                                    "ok",
                                    v.eligible,
                                    list(v.reasons),
                                    list(v.unbound_identity_fields),
                                ),
                            )
                        )
                    except Exception as exc:  # noqa: BLE001
                        rows.append(
                            (
                                (status, age, regime, dj_status),
                                ("raise", type(exc).__name__, str(exc)),
                            )
                        )
    # Wildcard detector_version: the record_version == "*" check.
    identity = InferenceIdentity(
        detector_id="det",
        detector_version="1",
        provider=None,
        model=None,
        config_hash=None,
        native_score_semantics=None,
        calibration_id=None,
        regime="human_only",
    )
    record = _ev_record(detector_version="*")
    dj = DisjointnessProof(
        status="verified",
        overlap_count=0,
        training_count=1000,
        evaluation_count=400,
        training_hash=_hex64(9),
        evaluation_hash=record.benchmark.fingerprint_sha256,
    )
    try:
        v = check_record_eligibility(
            record, identity=identity, disjointness=dj, now=now, max_age_days=30
        )
        rows.append(
            (
                ("active", "2026-11-01T00:00:00Z", "human_only", "verified-*"),
                ("ok", v.eligible, list(v.reasons), list(v.unbound_identity_fields)),
            )
        )
    except Exception as exc:  # noqa: BLE001
        rows.append(
            (
                ("active", "2026-11-01T00:00:00Z", "human_only", "verified-*"),
                ("raise", type(exc).__name__, str(exc)),
            )
        )
    # Zero-count proofs: training_count / evaluation_count == 0.
    for tcount, ecount in ((0, 400), (1000, 0)):
        record = _ev_record()
        dj = DisjointnessProof(
            status="verified",
            overlap_count=0,
            training_count=tcount,
            evaluation_count=ecount,
            training_hash=_hex64(9),
            evaluation_hash=record.benchmark.fingerprint_sha256,
        )
        try:
            v = check_record_eligibility(
                record, identity=identity, disjointness=dj, now=now, max_age_days=30
            )
            rows.append(
                (
                    ("active", "2026-11-01T00:00:00Z", "human_only", f"verified-{tcount}-{ecount}"),
                    ("ok", v.eligible, list(v.reasons), list(v.unbound_identity_fields)),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(
                (
                    ("active", "2026-11-01T00:00:00Z", "human_only", f"verified-{tcount}-{ecount}"),
                    ("raise", type(exc).__name__, str(exc)),
                )
            )
    # --- identity / proof shape boundaries --------------------------------
    base_record = _ev_record()
    base_dj = DisjointnessProof(
        status="verified",
        overlap_count=0,
        training_count=1000,
        evaluation_count=400,
        training_hash=_hex64(9),
        evaluation_hash=base_record.benchmark.fingerprint_sha256,
    )

    def _ident(**over):
        kw = dict(
            detector_id="det",
            detector_version="1",
            provider=None,
            model=None,
            config_hash=None,
            native_score_semantics=None,
            calibration_id=None,
            regime="human_only",
        )
        kw.update(over)
        return InferenceIdentity(**kw)

    def _dj(**over):
        kw = dict(
            status="verified",
            overlap_count=0,
            training_count=1000,
            evaluation_count=400,
            training_hash=_hex64(9),
            evaluation_hash=base_record.benchmark.fingerprint_sha256,
        )
        kw.update(over)
        return DisjointnessProof(**kw)

    def _check(key, record, ident, dj, **kw):
        try:
            v = check_record_eligibility(
                record, identity=ident, disjointness=dj, now=now, max_age_days=30, **kw
            )
            rows.append((key, ("ok", v.eligible, list(v.reasons), list(v.unbound_identity_fields))))
        except Exception as exc:  # noqa: BLE001
            rows.append((key, ("raise", type(exc).__name__, str(exc))))

    _check(("id-aaa",), base_record, _ident(detector_id="aaa"), base_dj)
    _check(("id-zzz",), base_record, _ident(detector_id="zzz"), base_dj)
    _check(("ver-0.9",), base_record, _ident(detector_version="0.9"), base_dj)
    _check(("ver-2",), base_record, _ident(detector_version="2"), base_dj)
    _check(("rec-ver-bang",), _ev_record(detector_version="!"), _ident(), base_dj)
    _check(("rec-ver-0.9",), _ev_record(detector_version="0.9"), _ident(), base_dj)
    _check(("overlap-1",), base_record, _ident(), _dj(overlap_count=1))
    # Distinct-but-equal identity strings: `is not` vs `!=`. The record's
    # detector_id/version are the literals "det"/"1"; the joined strings
    # are equal but distinct objects, so the `is not` mutants report a
    # mismatch where the original matches. Kills NotEq_IsNot:6 [1072,28]
    # (detector_id) and NotEq_IsNot:7 [1077,33] (detector_version).
    _check(("id-distinct",), base_record, _ident(detector_id="".join(["d", "e", "t"])), base_dj)
    # NOTE: "".join(["1"]) does NOT work here — a single-element join returns
    # the item itself, so it IS the literal "1" and `is not` agrees with
    # `!=`. The two-part join builds a genuinely distinct equal string
    # (verified: "".join(["", "1"]) is "1" -> False, == "1" -> True).
    _check(("ver-distinct",), base_record, _ident(detector_version="".join(["", "1"])), base_dj)
    # Unknown proof with overlap -1: `overlap_count > 0` vs `!= 0` differ
    # only for negative overlap. Kills Gt_NotEq:6 [1104,38]. The constructor
    # forbids overlap_count < 0 for ANY status (_require_int minimum 0,
    # evidence.py:952), so the tampered proof is built by __setattr__ on a
    # valid proof — the frozen-dataclass technique the probe already uses
    # for calibration artifacts. (The earlier "unknown + -1 is valid" note
    # was wrong: it crashed the constructor, which is why the probe failed
    # on the original source until this fix.)
    _dj_neg1 = _dj(status="unknown")
    object.__setattr__(_dj_neg1, "overlap_count", -1)
    _check(("overlap-neg1-unknown",), base_record, _ident(), _dj_neg1)
    _check(("train-1",), base_record, _ident(), _dj(training_count=1))
    _check(("eval-1",), base_record, _ident(), _dj(evaluation_count=1))
    _check(("train-1-eval-1",), base_record, _ident(), _dj(training_count=1, evaluation_count=1))
    _check(("eval-hash-diff-lo",), base_record, _ident(), _dj(evaluation_hash="0" * 64))
    _check(("eval-hash-diff-hi",), base_record, _ident(), _dj(evaluation_hash="f" * 64))
    _check(("eval-hash-none",), base_record, _ident(), _dj(evaluation_hash=None))
    _check(
        ("hashes-equal",),
        base_record,
        _ident(),
        _dj(training_hash=base_record.benchmark.fingerprint_sha256),
    )
    # Distinct-but-equal hashes: training_hash is a NEW string object equal
    # to the evaluation hash (joining the 64 fingerprint chars rebuilds it).
    # `==` is True (the "not distinct" reason is appended); `is` is False
    # (no reason). Kills Eq_Is:4 [1117,42]. (The "hashes-equal" row uses the
    # SAME object for both hashes, so `is` agrees with `==` there.)
    _check(
        ("hashes-distinct-equal",),
        base_record,
        _ident(),
        _dj(training_hash="".join(base_record.benchmark.fingerprint_sha256)),
    )
    _check(("age-30",), _ev_record(evaluated_at="2026-10-12T00:00:00Z"), _ident(), base_dj)
    _check(("age-31",), _ev_record(evaluated_at="2026-10-11T00:00:00Z"), _ident(), base_dj)
    for nh, na in ((99, 120), (100, 120), (101, 120), (120, 99), (120, 100), (120, 101), (99, 99)):
        _check((f"samples-{nh}-{na}",), _ev_record(n_human=nh, n_ai=na), _ident(), base_dj)
    _check(("artifact-ok",), base_record, _ident(), base_dj, artifact_verification={"ev-1": True})
    _check(
        ("artifact-fail",), base_record, _ident(), base_dj, artifact_verification={"ev-1": False}
    )
    _check(
        ("artifact-missing-row",),
        base_record,
        _ident(),
        base_dj,
        artifact_verification={"other": True},
    )
    _check(("artifact-none",), base_record, _ident(), base_dj, artifact_verification=None)
    _check(
        ("artifact-bad-shape",),
        base_record,
        _ident(),
        base_dj,
        artifact_verification="not-a-mapping",
    )
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
            rows.append(
                (
                    (status, "base"),
                    list(cov.record_ids),
                    [(k, v.state, v.observed) for k, v in sorted(cov.dimensions.items())],
                    list(cov.limitations),
                )
            )
        # Out-of-scope metadata: language outside supported_languages and
        # word_count below min_words — exercises the metadata downgrade
        # branches (state == "out_of_scope").
        from textforensics.evidence import assess_detector_coverage

        record = A._v2_record(status="active")
        registry = EvidenceRegistry([record])
        base_inputs = A._eligible_inputs(registry, root)
        for tag, cond in (
            ("lang-fr", dataclasses.replace(A._v2_conditions(), language="fr")),
            ("words-10", A._v2_conditions(word_count=10)),
        ):
            # _v2_coverage hardcodes conditions, so call the function directly.
            cov = assess_detector_coverage(
                detector_id="a",
                detector_version="1",
                detector_family="fam1",
                supported_languages=("en",),
                min_words=80,
                max_words=1000,
                conditions=cond,
                registry=registry,
                now=A.NOW,
                **base_inputs,
            )
            rows.append(
                (
                    ("active", tag),
                    list(cov.record_ids),
                    [(k, v.state, v.observed) for k, v in sorted(cov.dimensions.items())],
                    list(cov.limitations),
                )
            )
        # --- empty registry / multi-record continue-vs-break --------------
        cov = A._v2_coverage(
            EvidenceRegistry([]), **A._eligible_inputs(EvidenceRegistry([record]), root)
        )
        rows.append(
            (
                ("empty-registry",),
                list(cov.record_ids),
                [(k, v.state, v.observed) for k, v in sorted(cov.dimensions.items())],
                list(cov.limitations),
            )
        )
        retracted = A._v2_record(status="retracted")
        retracted2 = A._v2_record(status="retracted", split="heldout")
        active = A._v2_record(status="active")
        # Second record needs a distinct evidence_id: split="heldout" is an
        # approved held-out split, so it stays eligible.
        active2 = A._v2_record(status="active", split="heldout")
        thin2 = A._v2_record(n_human=10, n_ai=10, split="heldout")
        for tag, recs in (
            ("retracted-then-active", [retracted, active2]),
            ("active-then-retracted", [active, retracted2]),
            ("thin-then-adequate", [A._v2_record(n_human=10, n_ai=10), active2]),
            ("adequate-then-thin", [active, thin2]),
        ):
            registry = EvidenceRegistry(recs)
            cov = A._v2_coverage(registry, **A._eligible_inputs(registry, root))
            rows.append(
                (
                    (tag,),
                    list(cov.record_ids),
                    [(k, v.state, v.observed) for k, v in sorted(cov.dimensions.items())],
                    list(cov.limitations),
                )
            )
        # --- non-applicable first slice (continue vs break) ---------------
        # The `continue` at [1850,20] is in the INNER per-slice loop, not
        # the outer per-record loop: `break` there only ends the current
        # record's slice iteration. A non-applicable RECORD followed by a
        # good record therefore does NOT distinguish it (the outer loop
        # moves on either way) — the distinguishing shape is ONE record
        # with TWO slices, the first non-applicable (fr-only) and the
        # second applicable. The original `continue` reaches the second
        # slice; the `break` mutant drops it, so the record contributes
        # nothing. Kills ContinueWithBreak:1 [1850,20]. (The first
        # attempt used two records, which the disk check correctly
        # reported as SAME — the inner/outer loop distinction above is
        # why.)
        base_rec = A._v2_record(status="active")
        fr_slice = dataclasses.replace(
            base_rec.slices[0],
            conditions=dataclasses.replace(base_rec.slices[0].conditions, languages=("fr",)),
        )
        en_slice2 = dataclasses.replace(base_rec.slices[0], slice_id="s2")
        two_slice = dataclasses.replace(base_rec, slices=(fr_slice, en_slice2))
        registry = EvidenceRegistry([two_slice])
        cov = A._v2_coverage(registry, **A._eligible_inputs(registry, root))
        rows.append(
            (
                ("nonapplicable-then-good",),
                list(cov.record_ids),
                [(k, v.state, v.observed) for k, v in sorted(cov.dimensions.items())],
                list(cov.limitations),
            )
        )
        # --- ineligible record with adequate slices and a worse FPR -------
        # The second record has a different detector_id, so the identity
        # (built from the first record) does not bind it: eligible False,
        # but its slice is adequate (n 200/200). Its FPR CI upper (0.09)
        # exceeds the default ceiling (0.05), so under the `or` mutant its
        # pair joins fpr_pairs and vetoes HFP support; the original `and`
        # excludes it. Kills AndWithOr:39 [1852,36]. (The existing thin
        # rows pair eligible False with adequate False, where both agree;
        # the CI (0.01, 0.09) keeps the metric value 0.02 inside the
        # interval, which the MetricEstimate invariant requires.)
        good = A._v2_record(status="active")
        bad = A._v2_record(detector_id="b", status="active", fpr_ci=(0.01, 0.09))
        registry = EvidenceRegistry([good, bad])
        cov = A._v2_coverage(registry, **A._eligible_inputs(registry, root))
        rows.append(
            (
                ("ineligible-worse-fpr",),
                list(cov.record_ids),
                [(k, v.state, v.observed) for k, v in sorted(cov.dimensions.items())],
                list(cov.limitations),
            )
        )
        # --- max_age_days / fpr_ceiling boundaries -------------------------
        for tag, kw in (
            ("max-age-0", dict(max_age_days=0)),
            ("max-age-1", dict(max_age_days=1)),
            ("max-age-2", dict(max_age_days=2)),
            ("fpr-ceiling-0", dict(fpr_ceiling=0.0)),
            ("fpr-ceiling-1", dict(fpr_ceiling=1.0)),
            ("fpr-ceiling-1.5", dict(fpr_ceiling=1.5)),
            ("fpr-ceiling-neg", dict(fpr_ceiling=-0.1)),
        ):
            try:
                cov = A._v2_coverage(registry, **A._eligible_inputs(registry, root), **kw)
                rows.append(
                    (
                        (tag,),
                        list(cov.record_ids),
                        [(k, v.state, v.observed) for k, v in sorted(cov.dimensions.items())],
                        list(cov.limitations),
                    )
                )
            except Exception as exc:  # noqa: BLE001
                rows.append(((tag,), ("raise", type(exc).__name__, str(exc))))
        # --- unbound identity fields (limitations message) -----------------
        from textforensics.evidence import InferenceIdentity

        bound_identity = InferenceIdentity(
            detector_id="a",
            detector_version="1",
            provider="prov",
            model="m",
            config_hash=_hex64(5),
            native_score_semantics="probability",
            calibration_id=None,
            regime="human_only",
        )
        cov = A._v2_coverage(
            registry, **{**A._eligible_inputs(registry, root), "identity": bound_identity}
        )
        rows.append(
            (
                ("unbound-identity",),
                list(cov.record_ids),
                [(k, v.state, v.observed) for k, v in sorted(cov.dimensions.items())],
                list(cov.limitations),
            )
        )
    return rows


# ---------------------------------------------------------------------------
# validation (v3) — reuse the W2-A test module's builders
# ---------------------------------------------------------------------------


def _v3():
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
            rows.append(
                (
                    (dimension, lcr),
                    outcome(
                        _support_blockers,
                        rec,
                        dimension=dimension,
                        detector_version=A.V3_VERSION,
                        now=A.NOW,
                        fpr_ceiling=0.05,
                        **kw,
                    ),
                )
            )
    # Dimension sorting before "human_false_positive_evidence" with a
    # failing FPR gate: the default record's worst CI upper (0.05) fails
    # ceiling 0.04 while passing every common blocker. The original skips
    # the FPR extension for "domain_genre"; the mutant `<=` adds the
    # worst-slice blocker. Kills Eq_LtE:12 [2074,17]. (The loop's
    # dimensions all sort at or after "human_false_positive_evidence":
    # "language" sorts after it, so `<=` agrees with `==` there.)
    rows.append(
        (
            ("domain_genre", "ceiling-004"),
            outcome(
                _support_blockers,
                rec,
                dimension="domain_genre",
                detector_version=A.V3_VERSION,
                now=A.NOW,
                fpr_ceiling=0.04,
            ),
        )
    )
    return rows


def probe_val_derive_dimension():
    from textforensics.validation import _derive_evidence_dimension

    A = _v3()
    rows = []
    statuses = ("supported", "partial", "unknown", "stale", "contested")
    base_kw = dict(
        detector_id=A.V3_DETECTOR,
        detector_version=A.V3_VERSION,
        now=A.NOW,
        fpr_ceiling=0.05,
        unobservable=False,
        unobservable_reason="",
        out_of_scope_reason="no matching record for language",
        out_of_scope_observed={},
    )
    for status in statuses:
        rec = A.ValidationRecord.from_dict(A._v3_record_dict(status=status))
        rows.append(
            (
                (status, False),
                outcome(
                    _derive_evidence_dimension,
                    "language",
                    matching=(rec,),
                    detector_records=(rec,),
                    **base_kw,
                ),
            )
        )
    # mixed matching sets: contested among others
    recs = tuple(
        A.ValidationRecord.from_dict(
            A._v3_record_dict(status=s, record_id=f"evr-20261106-synth{s}-builtin-heuristic")
        )
        for s in ("supported", "contested", "unknown")
    )
    rows.append(
        (
            ("mixed", False),
            outcome(
                _derive_evidence_dimension,
                "language",
                matching=recs,
                detector_records=recs,
                **base_kw,
            ),
        )
    )
    # unobservable dimension with no matching records
    rows.append(
        (
            ("empty-unobs", True),
            outcome(
                _derive_evidence_dimension,
                "language",
                matching=(),
                detector_records=(),
                **{**base_kw, "unobservable": True, "unobservable_reason": "no slice"},
            ),
        )
    )
    rows.append(
        (
            ("empty-oos", False),
            outcome(
                _derive_evidence_dimension,
                "language",
                matching=(),
                detector_records=recs,
                **base_kw,
            ),
        )
    )
    # every dimension name with a supporting record: Eq_Lt/Eq_LtE/Eq_GtE name mutants
    sup = A.ValidationRecord.from_dict(A._v3_record_dict(status="supported"))
    for name in (
        "language",
        "text_length",
        "domain_genre",
        "editing_revision",
        "generator_scope",
        "human_population",
        "human_false_positive_evidence",
        "temporal_version_stability",
    ):
        rows.append(
            (
                (f"name-{name}", False),
                outcome(
                    _derive_evidence_dimension,
                    name,
                    matching=(sup,),
                    detector_records=(sup,),
                    **base_kw,
                ),
            )
        )

    # temporal: clean_runs boundaries 0/1/2/3 + watch shapes
    def _long(runs, watch=None):
        d = {
            "consecutive_clean_full_runs": runs,
            "clean_full_run_ids": [f"run-{i}" for i in range(runs)],
            "corpus_fingerprint": "sha256:" + "a" * 64,
        }
        if watch is not None:
            d["watch"] = watch
        return d

    for runs in (0, 1, 2, 3):
        rows.append(
            (
                (f"temporal-runs{runs}", False),
                outcome(
                    _derive_evidence_dimension,
                    "temporal_version_stability",
                    matching=(sup,),
                    detector_records=(sup,),
                    **base_kw,
                    longitudinal=_long(runs),
                ),
            )
        )
    for watch in (None, {"reason": "drift"}, {"reason": "drift", "since": "2026-11-01"}):
        rows.append(
            (
                (f"temporal-watch-{watch is not None}", False),
                outcome(
                    _derive_evidence_dimension,
                    "temporal_version_stability",
                    matching=(sup,),
                    detector_records=(sup,),
                    **base_kw,
                    longitudinal=_long(2, watch),
                ),
            )
        )
    rows.append(
        (
            ("temporal-long-empty", False),
            outcome(
                _derive_evidence_dimension,
                "temporal_version_stability",
                matching=(sup,),
                detector_records=(sup,),
                **base_kw,
                longitudinal={},
            ),
        )
    )
    rows.append(
        (
            ("temporal-long-none", False),
            outcome(
                _derive_evidence_dimension,
                "temporal_version_stability",
                matching=(sup,),
                detector_records=(sup,),
                **base_kw,
                longitudinal=None,
            ),
        )
    )
    # HFP with supporting + other-name veto shapes
    for name in (
        "domain_genre",
        "editing_revision",
        "generator_scope",
        "language",
        "human_false_positive_evidence",
    ):
        rows.append(
            (
                (f"hfp-{name}", False),
                outcome(
                    _derive_evidence_dimension,
                    name,
                    matching=(sup,),
                    detector_records=(sup,),
                    **base_kw,
                ),
            )
        )
    # --- longitudinal + non-temporal names (supported branch) -------------
    # The name-* rows above pass no longitudinal, so the temporal guard's
    # `and longitudinal is not None` is False under every mutant there;
    # the temporal rows use name "temporal_version_stability", where the
    # `==` mutants agree. A non-temporal name WITH longitudinal set
    # separates them. Kills AndWithOr:43 [2283,48] (`and` -> `or`) and
    # Eq_LtE:18 [2283,16] (`==` -> `<=`) with name "language", and
    # Eq_GtE:18 [2283,16] (`==` -> `>=`) with name "text_length" (the only
    # dimension name sorting after "temporal_version_stability").
    for name in ("language", "text_length"):
        rows.append(
            (
                (f"long-name-{name}", False),
                outcome(
                    _derive_evidence_dimension,
                    name,
                    matching=(sup,),
                    detector_records=(sup,),
                    **base_kw,
                    longitudinal=_long(2),
                ),
            )
        )
    # --- longitudinal + non-temporal names (partial branch) ---------------
    # Same shapes with a record that cannot support (status "partial"):
    # supporting is empty, so the partial branch's guard at [2350,12]
    # decides whether the u3 fields are recorded. Kills Eq_LtE:21
    # [2350,12] (name "language") and Eq_GtE:21 [2350,12] (name
    # "text_length").
    partial_rec = A.ValidationRecord.from_dict(A._v3_record_dict(status="partial"))
    for name in ("language", "text_length"):
        rows.append(
            (
                (f"long-name-partial-{name}", False),
                outcome(
                    _derive_evidence_dimension,
                    name,
                    matching=(partial_rec,),
                    detector_records=(partial_rec,),
                    **base_kw,
                    longitudinal=_long(2),
                ),
            )
        )
    # --- cross-record veto with a lowered FPR ceiling ----------------------
    # The default record's worst FPR CI upper (0.05) meets the default
    # ceiling (0.05), so it passes the FPR gate; at ceiling 0.04 it fails
    # while passing every common blocker (signature intact — no record
    # tampering). With name "domain_genre" (sorting before
    # "human_false_positive_evidence") and supporting non-empty, the mutant
    # `<=` enters the veto block and empties supporting. Kills Eq_LtE:17
    # [2261,12].
    rows.append(
        (
            ("veto-ceiling-004", False),
            outcome(
                _derive_evidence_dimension,
                "domain_genre",
                matching=(sup,),
                detector_records=(sup,),
                **{**base_kw, "fpr_ceiling": 0.04},
            ),
        )
    )
    # --- partial branch HFP uppers with a non-HFP name ---------------------
    # A partial-status record with FPR-bearing slices: supporting is empty,
    # so the partial branch runs. The original skips the HFP uppers block
    # for name "domain_genre"; the mutant `<=` records the worst-slice
    # upper. Kills Eq_LtE:20 [2335,12]. (The existing status rows use name
    # "language", which sorts AFTER "human_false_positive_evidence", so
    # `<=` agrees with `==` there.)
    rows.append(
        (
            ("partial-hfp-domain", False),
            outcome(
                _derive_evidence_dimension,
                "domain_genre",
                matching=(partial_rec,),
                detector_records=(partial_rec,),
                **base_kw,
            ),
        )
    )
    return rows


def probe_val_derive_trust_map():
    from textforensics.validation import derive_trust_map

    A = _v3()
    rows = []
    for n_records, statuses in (
        (0, ()),
        (1, ("supported",)),
        (2, ("supported", "supported")),
        (3, ("supported", "partial", "unknown")),
    ):
        recs = [
            A._v3_record_dict(status=s, record_id=f"evr-20261106-synth{i}-builtin-heuristic")
            for i, s in enumerate(statuses)
        ]
        registry = A._v3_registry(*recs)
        cond = A._v3_conditions()
        tm = A._v3_derive(cond, registry)
        rows.append(
            (
                (n_records, statuses),
                tm.overall,
                [(d.dimension, d.state, d.observed) for d in tm.dimensions],
                list(tm.limitations),
            )
        )
    # fpr_ceiling / failure_count validation boundaries (call derive_trust_map directly)
    recs = [A._v3_record_dict(status="supported")]
    registry = A._v3_registry(*recs)
    cond = A._v3_conditions()
    for fc in (True, False, 0.0, 0.5, 1.0, -0.1, 1.1, "x", None):
        try:
            tm = derive_trust_map(
                cond,
                registry,
                detector_id=A.V3_DETECTOR,
                detector_version=A.V3_VERSION,
                now=A.NOW,
                fpr_ceiling=fc,
            )
            rows.append(
                (
                    (f"fpr-ceiling-{fc!r}",),
                    tm.overall,
                    [(d.dimension, d.state, d.observed) for d in tm.dimensions],
                    sorted(tm.evidence_registry.items()) if tm.evidence_registry else None,
                    list(tm.limitations),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(((f"fpr-ceiling-{fc!r}",), ("raise", type(exc).__name__, str(exc))))
    for nfail in (True, -1, 0, 1, 2):
        try:
            tm = derive_trust_map(
                cond,
                registry,
                detector_id=A.V3_DETECTOR,
                detector_version=A.V3_VERSION,
                now=A.NOW,
                failure_count=nfail,
            )
            rows.append(
                (
                    (f"failure-count-{nfail!r}",),
                    tm.overall,
                    [(d.dimension, d.state, d.observed) for d in tm.dimensions],
                    list(tm.limitations),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(((f"failure-count-{nfail!r}",), ("raise", type(exc).__name__, str(exc))))
    # out-of-vocabulary condition values: language/domain/population "zzz",
    # unknown domain (low confidence), unknown editing regime
    for label, overrides in (
        ("lang-zho", {"language": "zho"}),
        ("lang-und", {"language": "und"}),
        ("lang-lowconf", {"language_confidence": "low"}),
        ("domain-zzz", {"domain_genre": "zzz"}),
        ("domain-lowconf", {"domain_confidence": "low"}),
        ("editing-zzz", {"editing_regime": "zzz"}),
        ("editing-mixed", {"editing_regime": "mixed"}),
        ("pop-zzz", {"human_population": "zzz"}),
        ("pop-unknown", {"human_population": "unknown"}),
    ):
        try:
            c2 = A._v3_conditions(**overrides)
            tm = A._v3_derive(c2, registry)
            rows.append(
                (
                    (label,),
                    tm.overall,
                    [(d.dimension, d.state, d.observed) for d in tm.dimensions],
                    list(tm.limitations),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(((label,), ("raise", type(exc).__name__, str(exc))))
    # longitudinal watch shapes
    for label, longi in (
        ("long-none", None),
        ("long-empty", {}),
        ("long-watch-none", {"watch": None}),
        ("long-watch", {"watch": {"reason": "drift"}}),
    ):
        try:
            tm = derive_trust_map(
                cond,
                registry,
                detector_id=A.V3_DETECTOR,
                detector_version=A.V3_VERSION,
                now=A.NOW,
                longitudinal=longi,
            )
            rows.append(
                (
                    (label,),
                    tm.overall,
                    [(d.dimension, d.state, d.observed) for d in tm.dimensions],
                    list(tm.limitations),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(((label,), ("raise", type(exc).__name__, str(exc))))
    # short input: word_count below every record's length floor, so the
    # text_length dimension is out_of_scope and its observed dict (with
    # length_maxima) is recorded. The v3 record's max_words is None, so
    # the original filter (`is not None`) yields [] while the mutant
    # (`is None`) yields [None]. Kills IsNot_Is:66 [2574,65]. (Without
    # the observed recording above, the difference is constructed but
    # discarded on every row: out_of_scope_observed only surfaces when
    # the dimension IS out_of_scope.)
    for label, overrides in (("words-10", {"word_count": 10}),):
        try:
            c2 = A._v3_conditions(**overrides)
            tm = A._v3_derive(c2, registry)
            rows.append(
                (
                    (label,),
                    tm.overall,
                    [(d.dimension, d.state, d.observed) for d in tm.dimensions],
                    list(tm.limitations),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(((label,), ("raise", type(exc).__name__, str(exc))))
    # complete longitudinal dicts: the "long-*" rows above omit
    # consecutive_clean_full_runs, so derive_trust_map raises KeyError
    # before ever reaching the watch check at [2763,11/37]. With a
    # complete dict the watch branch is reached. Kills IsNot_Is:68
    # [2763,37] (`is not None` -> `is None`) and AddNot:249 [2763,11]
    # (same condition negated): watch set -> the watch limitation is
    # appended by the original and skipped by the mutant; watch None or
    # absent -> the mutant enters the branch and raises AttributeError
    # on None.get('run_id') while the original returns normally.
    _long_full = {
        "detector_id": A.V3_DETECTOR,
        "detector_version": A.V3_VERSION,
        "consecutive_clean_full_runs": 2,
        "clean_full_run_ids": ["run-0", "run-1"],
        # _validate_longitudinal requires a bare 64-char hex digest here
        # (not the "sha256:"-prefixed form _derive_evidence_dimension's
        # _long() helper uses) and the detector binding above.
        "corpus_fingerprint": "a" * 64,
    }
    for label, longi in (
        (
            "long-full-watch",
            {
                **_long_full,
                "watch": {"reason": "drift", "run_id": "r1", "run_at_utc": "2026-11-01T00:00:00Z"},
            },
        ),
        ("long-full-nowatch", dict(_long_full)),
        ("long-full-watch-none", {**_long_full, "watch": None}),
    ):
        try:
            tm = derive_trust_map(
                cond,
                registry,
                detector_id=A.V3_DETECTOR,
                detector_version=A.V3_VERSION,
                now=A.NOW,
                longitudinal=longi,
            )
            rows.append(
                (
                    (label,),
                    tm.overall,
                    [(d.dimension, d.state, d.observed) for d in tm.dimensions],
                    list(tm.limitations),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(((label,), ("raise", type(exc).__name__, str(exc))))
    # invalid `now`: _coerce_now raises ValidationError -> except falls back
    # (record no timestamp: the fallback uses datetime.now, non-deterministic)
    for label, now in (("now-bad", "not-a-date"), ("now-none", None)):
        try:
            tm = derive_trust_map(
                cond, registry, detector_id=A.V3_DETECTOR, detector_version=A.V3_VERSION, now=now
            )
            rows.append(
                (
                    (label,),
                    tm.overall,
                    [(d.dimension, d.state, d.observed) for d in tm.dimensions],
                    list(tm.limitations),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(((label,), ("raise", type(exc).__name__, str(exc))))
    return rows


# ---------------------------------------------------------------------------
# adversarial / semantic
# ---------------------------------------------------------------------------


def _adv_text(n_words=40, marker=""):
    words = [
        "The",
        "quick",
        "brown",
        "fox",
        "jumps",
        "over",
        "the",
        "lazy",
        "dog",
        "near",
        "the",
        "river",
        "bank",
        "while",
        "the",
        "old",
        "farmer",
        "watches",
        "the",
        "morning",
        "sun",
        "rise",
        "over",
        "the",
        "hills.",
    ]
    body = " ".join((words * ((n_words // len(words)) + 1))[:n_words])
    return (marker + " " + body).strip() if marker else body


def probe_adv_analyze():
    from textforensics.adversarial import AdversarialDetector

    det = AdversarialDetector()
    rows = []
    for text, language in (
        (_adv_text(40), None),
        (_adv_text(8), None),  # below MIN_WORDS (10)
        (_adv_text(9), None),  # MIN_WORDS - 1
        (_adv_text(10), None),  # MIN_WORDS exactly
        (_adv_text(11), None),  # MIN_WORDS + 1
        (_adv_text(120), None),
        ("As an AI language model, I cannot help with that request. " * 3, None),
        ("Delve into the multifaceted tapestry of human experience. " * 4, None),
        (_adv_text(40), "fr"),  # non-English declaration
        ("", None),
        ("   ", None),  # whitespace-only: empty branch
        ("   ", "fr"),  # whitespace + non-English
        (
            "\u4e2d\u6587\u6587\u672c\u6ca1\u6709\u62c9\u4e01\u5b57\u6bcd\u3002" * 3,
            None,
        ),  # no Latin letters
        ("\u4e2d\u6587\u6587\u672c\u6ca1\u6709\u62c9\u4e01\u5b57\u6bcd\u3002" * 3, "en"),
    ):  # declared en, no Latin
        try:
            rep = det.analyze(text, language=language)
            rows.append(
                (
                    (len(text.split()), language),
                    rep.overall_risk,
                    rep.support_status,
                    len(rep.findings),
                    rep.text_length,
                    len(rep.report_id),
                    tuple(sorted(rep.detector_outputs.items())),
                    tuple(sorted(rep.metadata.items())),
                    len(rep.limitations),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(((len(text.split()), language), ("raise", type(exc).__name__, str(exc))))
    # detector_outputs / metadata passthrough shapes (or->and, or {} mutants)
    for det_out, meta in (
        (None, None),
        ({}, {}),
        ({"d1": 0.9}, None),
        (None, {"k": "v"}),
        ({"d1": 0.9}, {"k": "v"}),
    ):
        try:
            rep = det.analyze(_adv_text(40), detector_outputs=det_out, metadata=meta)
            rows.append(
                (
                    ("passthrough", det_out is not None, meta is not None),
                    rep.overall_risk,
                    rep.support_status,
                    len(rep.findings),
                    rep.text_length,
                    len(rep.report_id),
                    tuple(sorted(rep.detector_outputs.items())),
                    tuple(sorted(rep.metadata.items())),
                    len(rep.limitations),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(
                (
                    ("passthrough", det_out is not None, meta is not None),
                    ("raise", type(exc).__name__, str(exc)),
                )
            )
    # summary(): text_sha256 prefix is [:16] + "..."
    for text in (_adv_text(40), _adv_text(10)):
        rep = det.analyze(text)
        s = rep.summary()
        rows.append(
            (
                ("summary", len(text.split())),
                (s["text_sha256"], s["overall_risk"], s["total_findings"], s["patterns_checked"]),
            )
        )
    return rows


def probe_adv_assess_risk():
    from textforensics.adversarial import AdversarialDetector, AdversarialFinding

    det = AdversarialDetector()
    rows = []

    def finding(severity, confidence, pattern="p1"):
        return AdversarialFinding(
            pattern_id=pattern,
            segment="full_text",
            evidence=0.5,
            severity=severity,
            confidence=confidence,
            location=(0, 10),
            description="synthetic",
        )

    for findings in (
        [],
        [finding("low", 0.1)],
        [finding("medium", 0.5)],
        [finding("high", 0.7)],
        [finding("critical", 0.9)],
        [finding("low", 0.1), finding("high", 0.7)],
        [finding("critical", 0.9), finding("critical", 0.9)],
        [finding("medium", 0.5), finding("medium", 0.5), finding("medium", 0.5)],
        # exact band boundaries (single high: risk == confidence)
        [finding("high", 0.65)],
        [finding("high", 0.45)],
        [finding("high", 0.25)],
        [finding("high", 0.15)],
        # exact boundaries via other weights
        [finding("critical", 0.4875)],
        [finding("critical", 0.3375)],
        [finding("critical", 0.1875)],
        [finding("critical", 0.1125)],
        [finding("medium", 0.84375)],
        [finding("medium", 0.46875)],
        [finding("medium", 0.28125)],
        [finding("low", 0.45)],
        [finding("low", 0.75)],
        # near-boundary weight rows (+/-1 weight crosses a band)
        [finding("critical", 0.3)],
        [finding("critical", 0.525)],
        [finding("high", 0.45)],
        [finding("high", 0.65)],
        [finding("medium", 0.5)],
        [finding("low", 1.0)],
        # unknown severity -> default weight 0
        [finding("bogus", 0.9)],
        [finding("bogus", 0.9), finding("critical", 0.9)],
    ):
        rows.append(
            (
                (tuple((f.severity, f.confidence) for f in findings),),
                outcome(det._assess_risk, findings),
            )
        )
    return rows


def probe_sem_analyze():
    from textforensics.semantic import SemanticConsistencyChecker

    checker = SemanticConsistencyChecker()
    rows = []
    three = (
        "The city council approved the new budget on Tuesday. "
        "Local residents welcomed the decision with cautious optimism. "
        "The mayor said the funds would support road repairs and schools."
    )
    two = (
        "The city council approved the new budget on Tuesday. "
        "Local residents welcomed the decision with cautious optimism."
    )
    long_mixed = (
        three + " " + "Quantum computers exploit superposition to solve "
        "certain problems exponentially faster than classical machines. " * 3
    )
    for text, language in (
        (three, None),
        (two, None),
        (long_mixed, None),
        (three, "fr"),
        ("", None),
        (" ".join(["word"] * 400), None),
        ("   ", None),  # whitespace-only
        ("\u4e2d\u6587\u6587\u672c\u6ca1\u6709\u62c9\u4e01\u5b57\u6bcd\u3002" * 3, None),
    ):  # no Latin
        try:
            rep = checker.analyze(text, language=language)
            rows.append(
                (
                    (len(text.split()), language),
                    rep.risk_level,
                    rep.support_status,
                    len(rep.findings),
                    rep.text_length,
                    rep.n_segments,
                    len(rep.report_id),
                    tuple(sorted(rep.metadata.items())),
                    len(rep.limitations),
                    rep.overall_consistency_score,
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(((len(text.split()), language), ("raise", type(exc).__name__, str(exc))))
    # summary(): text_sha256 prefix is [:16] + "..."
    for text in (three, two):
        rep = checker.analyze(text)
        s = rep.summary()
        rows.append(
            (
                ("summary", len(text.split())),
                (s["text_sha256"], s["risk_level"], s["total_findings"], s["support_status"]),
            )
        )
    # segment_word_target boundary: one-word sentences, 200 vs 201 words.
    # target 100 -> 200 words = 2 segments, 201 words = 3 segments.
    # target 101 -> 201 words = 2 segments; target 99 -> 200 words = 3.
    from textforensics.semantic import analyze_semantic_consistency

    for n in (199, 200, 201, 202):
        text = " ".join(f"Word{i}." for i in range(n))
        try:
            rep = analyze_semantic_consistency(text)
            rows.append(
                (
                    ("target-boundary", n),
                    rep.support_status,
                    rep.overall_consistency_score,
                    len(rep.findings),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append((("target-boundary", n), ("raise", type(exc).__name__, str(exc))))
    return rows


def probe_sem_assess_risk():
    from textforensics.semantic import SemanticConsistencyChecker

    checker = SemanticConsistencyChecker()
    rows = []

    def finding(severity, confidence):
        return {
            "finding_id": "f1",
            "category": "style",
            "description": "synthetic",
            "evidence": 0.5,
            "severity": severity,
            "confidence": confidence,
            "segment_indices": (0, 1),
            "details": {},
        }

    for findings in (
        [],
        [finding("low", 0.1)],
        [finding("medium", 0.5)],
        [finding("high", 0.7)],
        [finding("critical", 0.9)],
        [finding("low", 0.1), finding("high", 0.7)],
        [finding("critical", 0.9), finding("critical", 0.9)],
        # exact band boundaries (single critical: risk == confidence)
        [finding("critical", 0.5)],
        [finding("critical", 0.3)],
        [finding("critical", 0.15)],
        # exact 0.7: 3 criticals (0.5, 0.7, 0.9) -> 3.15/4.5 == 0.7
        [finding("critical", 0.5), finding("critical", 0.7), finding("critical", 0.9)],
        # exact boundaries via other weights
        [finding("high", 0.75)],
        [finding("high", 0.45)],
        [finding("high", 0.225)],
        [finding("medium", 0.75)],
        [finding("medium", 0.375)],
        [finding("low", 0.75)],
        [finding("low", 1.0)],
        # band-crossing low+high: kills NumberReplacer:317
        # [702,65] (the "low" dict VALUE 0.3 -> -0.7):
        # original total 0.3*1.0 + 1.0*0.75 = 1.05, risk
        # 1.05/3.0 = 0.35 -> "medium"; mutant total -0.7 + 0.75
        # = 0.05, risk 0.017 -> "low".
        [finding("low", 1.0), finding("high", 0.75)],
        # near-boundary weight rows (+/-1 weight crosses a band)
        [finding("critical", 0.45)],
        [finding("high", 0.75)],
        [finding("medium", 0.75)],
        [finding("low", 1.0)],
        # unknown severity -> default weight 0.3; missing keys -> defaults
        [finding("bogus", 0.9)],
        [finding("bogus", 0.9), finding("critical", 0.9)],
        [
            {
                "finding_id": "f1",
                "category": "style",
                "description": "synthetic",
                "evidence": 0.5,
                "confidence": 0.9,
                "segment_indices": (0, 1),
                "details": {},
            },
        ],
        [
            {
                "finding_id": "f1",
                "category": "style",
                "description": "synthetic",
                "evidence": 0.5,
                "severity": "critical",
                "segment_indices": (0, 1),
                "details": {},
            },
        ],
    ):
        rows.append(
            (
                (
                    tuple(
                        (f.get("severity", "<missing>"), f.get("confidence", "<missing>"))
                        for f in findings
                    ),
                ),
                outcome(checker._assess_risk, findings),
            )
        )
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
        "",  # 0 segments: LtE_Eq:0 limitation branch
        "   ",  # whitespace-only: 0 segments
    ]
    for text in texts:
        try:
            rep = expl.explain(text)
            rows.append(
                (
                    (len(text.split(".")),),
                    [(s.direction, round(s.delta, 6)) for s in rep.segment_attribution],
                    rep.completeness.selected,
                    rep.completeness.attempted,
                    [(a.direction, a.abs_delta) for a in rep.top_ai_driving],
                    [(a.direction, a.abs_delta) for a in rep.top_human_driving],
                    tuple(rep.limitations),
                    rep.n_segments,
                    rep.n_scored,
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(((len(text.split(".")),), ("raise", type(exc).__name__, str(exc))))
    # recording progress callback: Add family + NumberReplacer on idx+1
    calls = []
    try:
        rep = expl.explain(texts[0], progress=lambda c, t: calls.append((c, t)))
        rows.append(
            (
                ("progress",),
                [(s.direction, round(s.delta, 6)) for s in rep.segment_attribution],
                tuple(calls),
                rep.completeness.selected,
                rep.completeness.attempted,
            )
        )
    except Exception as exc:  # noqa: BLE001
        rows.append((("progress",), ("raise", type(exc).__name__, str(exc))))

    # raising score_fn: continue-vs-break (raise on one perturbed text only)
    def raising_fn(text):
        if "machine generated" not in text:
            raise ValueError("no machine marker")
        return score_fn(text)

    expl_r = CounterfactualExplainer(raising_fn, detector_id="d", detector_version="1")
    try:
        rep = expl_r.explain(texts[0])
        rows.append(
            (
                ("raising",),
                [(s.direction, round(s.delta, 6)) for s in rep.segment_attribution],
                rep.completeness.selected,
                rep.completeness.attempted,
                rep.completeness.failed,
                rep.completeness.succeeded,
                tuple(rep.limitations),
            )
        )
    except Exception as exc:  # noqa: BLE001
        rows.append((("raising",), ("raise", type(exc).__name__, str(exc))))
    # progress + raising score_fn: the except-path progress call (line 381).
    # The success-path "progress" row never reaches it, and the "raising"
    # row has no callback. Kills Add_*:2 (11) + NumberReplacer:50/51
    # [381,33/35] (the idx+1 arithmetic in the except path: the original
    # calls ((1,3),(2,3),(3,3)); the mutants differ at idx 0 of the
    # except-path calls).
    calls_r = []
    try:
        rep = expl_r.explain(texts[0], progress=lambda c, t: calls_r.append((c, t)))
        rows.append(
            (
                ("progress-raising",),
                [(s.direction, round(s.delta, 6)) for s in rep.segment_attribution],
                tuple(calls_r),
                rep.completeness.selected,
                rep.completeness.attempted,
                rep.completeness.failed,
                rep.completeness.succeeded,
            )
        )
    except Exception as exc:  # noqa: BLE001
        rows.append((("progress-raising",), ("raise", type(exc).__name__, str(exc))))
    # Same, with texts[1] (the "machine generated" segment is idx 1):
    # the except-path progress call is progress(2, 3), where `|` and `^`
    # differ from `+` (1|1=1, 1^1=0 vs 1+1=2). With texts[0] the raising
    # segment is idx 0 and 0+1 == 0|1 == 0^1 == 1, so Add_BitOr:2 /
    # Add_BitXor:2 [381,33] were invisible on the disk driver. Kills them.
    calls_r1 = []
    try:
        rep = expl_r.explain(texts[1], progress=lambda c, t: calls_r1.append((c, t)))
        rows.append(
            (
                ("progress-raising-idx1",),
                [(s.direction, round(s.delta, 6)) for s in rep.segment_attribution],
                tuple(calls_r1),
                rep.completeness.selected,
                rep.completeness.attempted,
                rep.completeness.failed,
                rep.completeness.succeeded,
            )
        )
    except Exception as exc:  # noqa: BLE001
        rows.append((("progress-raising-idx1",), ("raise", type(exc).__name__, str(exc))))

    # long-decimal score_fn: round(delta, 6) mutants
    def long_fn(text):
        score = 0.1234567891
        if "machine generated" in text:
            score += 0.1111111111
        if "handwritten note" in text:
            score -= 0.2222222222
        return score

    expl_l = CounterfactualExplainer(long_fn, detector_id="d", detector_version="1")
    try:
        rep = expl_l.explain(texts[0])
        rows.append(
            (
                ("long-decimal",),
                [(s.direction, s.delta, s.abs_delta) for s in rep.segment_attribution],
                [(a.direction, a.abs_delta) for a in rep.top_ai_driving],
                [(a.direction, a.abs_delta) for a in rep.top_human_driving],
            )
        )
    except Exception as exc:  # noqa: BLE001
        rows.append((("long-decimal",), ("raise", type(exc).__name__, str(exc))))

    # >256 segments: NotEq_IsNot:0 (i != idx -> i is not idx).
    # Counting score_fn + a marker in EVERY segment: removing segment idx
    # drops the count by 1 (delta -0.4); under the mutant, idx >= 257 keeps
    # its own segment in `remaining` (delta 0).
    def counting_fn(text):
        score = 0.5
        score += 0.4 * text.count("machine generated")
        score += 0.2 * text.count("AI wrote this")
        score -= 0.3 * text.count("handwritten note")
        score -= 0.1 * text.count("penned by hand")
        return score

    expl_c = CounterfactualExplainer(counting_fn, detector_id="d", detector_version="1")
    big_text = " ".join(f"Word {i} machine generated here." for i in range(260))
    try:
        rep = expl_c.explain(big_text)
        rows.append(
            (
                ("big-260",),
                rep.n_segments,
                rep.n_scored,
                round(sum(s.delta for s in rep.segment_attribution), 6),
                round(sum(s.abs_delta for s in rep.segment_attribution), 6),
                [(s.direction, round(s.delta, 6)) for s in rep.segment_attribution[:3]],
                [(s.direction, round(s.delta, 6)) for s in rep.segment_attribution[-3:]],
            )
        )
    except Exception as exc:  # noqa: BLE001
        rows.append((("big-260",), ("raise", type(exc).__name__, str(exc))))
    # two pushes_ai segments with DIFFERENT deltas: reverse=True ordering
    multi_text = (
        "This is machine generated content. AI wrote this paragraph here. "
        "This is a handwritten note from a friend. A passage penned by hand follows. "
        "The weather is fine today."
    )
    try:
        rep = expl_c.explain(multi_text)
        rows.append(
            (
                ("multi-direction",),
                [(s.direction, round(s.delta, 6)) for s in rep.segment_attribution],
                [(a.direction, a.abs_delta) for a in rep.top_ai_driving],
                [(a.direction, a.abs_delta) for a in rep.top_human_driving],
            )
        )
    except Exception as exc:  # noqa: BLE001
        rows.append((("multi-direction",), ("raise", type(exc).__name__, str(exc))))
    # abstaining score_fn (timestamp-free fields: created_at varies per call)
    expl2 = CounterfactualExplainer(lambda t: None, detector_id="d", detector_version="1")
    try:
        rep = expl2.explain(texts[0])
        rows.append(
            (
                ("abstain",),
                (
                    "ok",
                    rep.n_segments,
                    rep.n_scored,
                    rep.original_score,
                    rep.verdict,
                    rep.completeness.selected if rep.completeness else None,
                    rep.completeness.attempted if rep.completeness else None,
                ),
            )
        )
    except Exception as exc:  # noqa: BLE001
        rows.append((("abstain",), ("raise", type(exc).__name__, str(exc))))
    return rows


# ---------------------------------------------------------------------------
# probe_runs
# ---------------------------------------------------------------------------


def _pr_slice_inputs(n=10, flipped=0, direction="higher_means_ai", prev_verdicts=None):

    import test_w2_worker_d as D

    prev, curr, labels = [], [], {}
    for i in range(n):
        item_id = f"h-{i:03d}"
        is_flipped = i < flipped
        prev_verdict = (prev_verdicts or {}).get(item_id, "human_like")
        prev.append(D._rec(item_id, score=0.3, verdict=prev_verdict))
        curr.append(
            D._rec(
                item_id,
                score=0.9 if is_flipped else 0.3,
                verdict="ai_like" if is_flipped else "human_like",
                direction=direction,
            )
        )
        labels[item_id] = 0
    current = {r["sample_id"]: r for r in curr}
    baseline = {r["sample_id"]: r for r in prev}
    return [r["sample_id"] for r in curr], current, baseline, labels


def _pr_slice_inputs2(
    *,
    n_human=10,
    n_ai=0,
    n_none=0,
    flipped=0,
    direction="higher_means_ai",
    prev_verdicts=None,
    current_verdicts=None,
    cal=None,
    cal_id=None,
    baseline_cal=None,
    baseline_cal_id=None,
    scores=None,
    baseline_scores=None,
):
    """Slice inputs with mixed labels / verdicts / calibrated probs.

    ``cal``/``cal_id`` apply to current records (scalar or per-item list);
    ``baseline_cal``/``baseline_cal_id`` likewise for baseline records.
    ``scores``/``baseline_scores`` are per-item score lists (None = no score).
    """
    import test_w2_worker_d as D

    total = n_human + n_ai + n_none
    item_ids, current, baseline, labels = [], {}, {}, {}
    for i in range(total):
        item_id = f"h-{i:03d}"
        label = 0 if i < n_human else (1 if i < n_human + n_ai else None)
        is_flipped = i < flipped
        prev_verdict = (prev_verdicts or {}).get(item_id, "human_like")
        curr_verdict = (current_verdicts or {}).get(
            item_id, "ai_like" if is_flipped else "human_like"
        )
        score = 0.9 if is_flipped else 0.3
        if scores is not None:
            score = scores[i]
        bscore = 0.3
        if baseline_scores is not None:
            bscore = baseline_scores[i]
        c = cal[i] if isinstance(cal, list) else cal
        cid = cal_id[i] if isinstance(cal_id, list) else cal_id
        bc = baseline_cal[i] if isinstance(baseline_cal, list) else baseline_cal
        bcid = baseline_cal_id[i] if isinstance(baseline_cal_id, list) else baseline_cal_id
        prev = D._rec(
            item_id, score=bscore, verdict=prev_verdict, cal=bc, cal_id=bcid, direction=direction
        )
        curr = D._rec(
            item_id, score=score, verdict=curr_verdict, cal=c, cal_id=cid, direction=direction
        )
        item_ids.append(item_id)
        current[item_id] = curr
        baseline[item_id] = prev
        labels[item_id] = label
    return item_ids, current, baseline, labels


def probe_pr_slice_metrics():
    from datetime import UTC, datetime

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
        (10, 2, "higher_means_ai", {"h-000": "ai_like", "h-001": "abstain"}),
    ):
        item_ids, current, baseline, labels = _pr_slice_inputs(n, flipped, direction, prev_verdicts)
        key = (n, flipped, direction, tuple(sorted((prev_verdicts or {}).items())))
        human_scores = [0.3] * n
        human_labels = [0] * n
        # previous must be a real dict: the flip loop (`item in previous`)
        # is only reached when a previous run exists. baseline and previous
        # are the same records here (previous run == baseline run).
        out = outcome(
            _slice_metrics,
            item_ids=item_ids,
            current=current,
            baseline=baseline,
            previous=baseline,
            labels=labels,
            primitives=primitives,
            is_human_slice=True,
            is_attacked_slice=False,
            human_scores_all=human_scores,
            human_labels_all=human_labels,
            calibration_created_at=None,
            now=now,
            score_direction=direction,
        )
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
        ("n300-cal-all", dict(n_human=300, n_ai=0, flipped=3, cal=0.3, baseline_cal=0.3), {}),
        (
            "cal-partial",
            dict(
                n_human=10,
                n_ai=0,
                flipped=2,
                cal=[0.3] * 5 + [None] * 5,
                baseline_cal=[0.3] * 5 + [None] * 5,
            ),
            {},
        ),
        ("cal-all", dict(n_human=10, n_ai=0, flipped=2, cal=0.3, baseline_cal=0.3), {}),
        ("cal-baseline-only", dict(n_human=10, n_ai=0, flipped=2, baseline_cal=0.3), {}),
        ("cal-current-only", dict(n_human=10, n_ai=0, flipped=2, cal=0.3), {}),
        (
            "cal-ids-same",
            dict(
                n_human=10,
                n_ai=0,
                flipped=2,
                cal=0.3,
                cal_id="cal-1",
                baseline_cal=0.3,
                baseline_cal_id="cal-1",
            ),
            {},
        ),
        (
            "cal-ids-diff",
            dict(
                n_human=10,
                n_ai=0,
                flipped=2,
                cal=0.3,
                cal_id="cal-2",
                baseline_cal=0.3,
                baseline_cal_id="cal-1",
            ),
            {},
        ),
        ("cal-ids-baseline-only", dict(n_human=10, n_ai=0, flipped=2, baseline_cal_id="cal-1"), {}),
        ("cal-ids-current-only", dict(n_human=10, n_ai=0, flipped=2, cal_id="cal-1"), {}),
        (
            "cal-ages",
            dict(
                n_human=10,
                n_ai=0,
                flipped=2,
                cal=0.3,
                cal_id=["cal-1", "cal-2"] * 5,
                baseline_cal=0.3,
                baseline_cal_id="cal-1",
            ),
            dict(
                calibration_created_at={
                    "cal-1": "2026-11-01T00:00:00",
                    "cal-2": "2026-11-10T00:00:00",
                }
            ),
        ),
        (
            "cal-ages-unknown-id",
            dict(n_human=10, n_ai=0, flipped=2, cal=0.3, cal_id="cal-9", baseline_cal=0.3),
            dict(calibration_created_at={"cal-1": "2026-11-01T00:00:00"}),
        ),
        (
            "cal-ages-none-id",
            dict(n_human=10, n_ai=0, flipped=2, cal=0.3, baseline_cal=0.3),
            dict(calibration_created_at={"cal-1": "2026-11-01T00:00:00"}),
        ),
        (
            "abstain-current",
            dict(
                n_human=10,
                n_ai=0,
                flipped=2,
                current_verdicts={"h-002": "abstain", "h-003": "abstain"},
            ),
            {},
        ),
        (
            "abstain-all-current",
            dict(
                n_human=10,
                n_ai=0,
                flipped=0,
                current_verdicts={f"h-{i:03d}": "abstain" for i in range(10)},
            ),
            {},
        ),
        ("no-score-current", dict(n_human=10, n_ai=0, flipped=2, scores=[None] * 10), {}),
        ("some-no-score", dict(n_human=10, n_ai=0, flipped=2, scores=[0.3] * 5 + [None] * 5), {}),
        ("no-baseline", dict(n_human=10, n_ai=0, flipped=2), dict(no_baseline=True)),
        ("no-previous", dict(n_human=10, n_ai=0, flipped=2), dict(no_previous=True)),
        ("nonhuman-slice", dict(n_human=0, n_ai=10, flipped=0), dict(is_human_slice=False)),
        (
            "attacked",
            dict(n_human=0, n_ai=10, flipped=0),
            dict(is_attacked_slice=True, human_scores_all=[0.3] * 10, human_labels_all=[0] * 10),
        ),
        (
            "attacked-lower",
            dict(n_human=0, n_ai=10, flipped=0),
            dict(
                is_attacked_slice=True,
                human_scores_all=[0.3] * 10,
                human_labels_all=[0] * 10,
                score_direction="lower_means_ai",
            ),
        ),
        (
            "attacked-unknown-dir",
            dict(n_human=0, n_ai=10, flipped=0),
            dict(
                is_attacked_slice=True,
                human_scores_all=[0.3] * 10,
                human_labels_all=[0] * 10,
                score_direction="unknown",
            ),
        ),
        (
            "attacked-na-dir",
            dict(n_human=0, n_ai=10, flipped=0),
            dict(
                is_attacked_slice=True,
                human_scores_all=[0.3] * 10,
                human_labels_all=[0] * 10,
                score_direction="not_applicable",
            ),
        ),
        (
            "attacked-no-human-ref",
            dict(n_human=0, n_ai=10, flipped=0),
            dict(is_attacked_slice=True, human_scores_all=[], human_labels_all=[]),
        ),
        (
            "attacked-no-machine",
            dict(n_human=10, n_ai=0, flipped=0),
            dict(is_attacked_slice=True, human_scores_all=[0.3] * 10, human_labels_all=[0] * 10),
        ),
        (
            "attacked-machine-no-score",
            dict(n_human=0, n_ai=10, flipped=0, scores=[None] * 10),
            dict(is_attacked_slice=True, human_scores_all=[0.3] * 10, human_labels_all=[0] * 10),
        ),
        (
            "attacked-mixed-scores",
            dict(
                n_human=0,
                n_ai=10,
                flipped=0,
                scores=[0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.05],
            ),
            dict(
                is_attacked_slice=True,
                human_scores_all=[0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5],
                human_labels_all=[0] * 10,
            ),
        ),
    ]
    for key, bkw, ckw in variants:
        item_ids, current, baseline, labels = _pr_slice_inputs2(**bkw)
        n = len(item_ids)
        human_scores = [0.3] * n
        human_labels = [0] * n
        kw = dict(
            item_ids=item_ids,
            current=current,
            baseline=None if ckw.get("no_baseline") else baseline,
            previous=None if ckw.get("no_previous") else baseline,
            labels=labels,
            primitives=primitives,
            is_human_slice=ckw.get("is_human_slice", True),
            is_attacked_slice=ckw.get("is_attacked_slice", False),
            human_scores_all=ckw.get("human_scores_all", human_scores),
            human_labels_all=ckw.get("human_labels_all", human_labels),
            calibration_created_at=ckw.get("calibration_created_at"),
            now=now,
            score_direction=ckw.get("score_direction", "higher_means_ai"),
        )
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
    from datetime import UTC, datetime

    import test_w2_worker_d as D

    from textforensics.probe_runs import compute_run_metrics

    rows = []
    now = datetime(2026, 11, 11, tzinfo=UTC)
    # A far-past `now` separates `now or datetime.now(UTC)` from `and`:
    # with a fixed now near real now the mutant's real-now coincides, so
    # OrWithAnd:8 [824,14] was invisible. Kills OrWithAnd:8.
    now_far = datetime(2020, 1, 1, tzinfo=UTC)
    import ast as _ast

    def _run(key, **kw):
        out = outcome(compute_run_metrics, **kw)
        if out[0] == "ok":
            # Record the FULL outcome (it is JSON-safe): the old probe
            # recorded only sorted keys + overall verdict_counts,
            # discarding slices/worst_fpr, which hid the score_shift
            # (AddNot:57 / IsNot_Is:28,29 / OrWithAnd:9 [904,*]),
            # human/attacked-slice (TrueWithFalse:6 [916,23] /
            # FalseWithTrue:4 [917,26]) and worst_fpr-ci
            # (NumberReplacer:94/95/97 [937,*]) mutants.
            rows.append((key, _ast.literal_eval(out[1])))
        else:
            rows.append((key, out))

    for label, when in (("now", now), ("now-far-past", now_far)):
        for n, flipped in ((0, 0), (10, 0), (10, 2), (10, 10)):
            prev, curr, labels, slices = D._human_slice(n, flipped=flipped)
            _run(
                (label, n, flipped),
                current_records=curr,
                previous_records=prev,
                baseline_records=prev,
                labels=labels,
                slices=slices,
                detector_id="d",
                calibration_created_at=None,
                now=when,
            )
    # Score-shift with NO paired scores (baseline={}): ks_statistic and psi
    # are both None, so the [904] recompute guard is False in the original
    # (status stays "unavailable", reason "no paired scores...") but the
    # AddNot:57 / IsNot_Is:28/29 mutants run the recompute, which returns
    # ("unavailable", "no baseline run to compare against"). Kills those
    # three. (OrWithAnd:9 [904,49] is EQUIVALENT: ks and psi are always set
    # together in _slice_metrics, so `or` == `and` on the reachable inputs.)
    for label, when in (("now", now), ("now-far-past", now_far)):
        prev, curr, labels, slices = D._human_slice(10, flipped=2)
        _run(
            (label, "baseline-empty", 2),
            current_records=curr,
            previous_records=prev,
            baseline_records={},
            labels=labels,
            slices=slices,
            detector_id="d",
            calibration_created_at=None,
            now=when,
        )
    # Calibration staleness: `now` feeds (now - created).days, but only
    # when calibration_created_at is given (it was None in every row, so
    # OrWithAnd:8 [824,14] was invisible — the far-past rows changed
    # nothing observable). With a fixed creation date the far-past `now`
    # gives -2192 days in the original vs +314 under the mutant (real
    # now). Kills OrWithAnd:8.
    for label, when in (("now", now), ("now-far-past", now_far)):
        prev, curr, labels, slices = D._human_slice(10, flipped=2)
        curr_cal = [dict(r, calibration_id="cal1") for r in curr]
        _run(
            (label, "staleness", 2),
            current_records=curr_cal,
            previous_records=prev,
            baseline_records=prev,
            labels=labels,
            slices=slices,
            detector_id="d",
            calibration_created_at={"cal1": "2026-01-01T00:00:00+00:00"},
            now=when,
        )
    # Claimable worst-slice FPR (n_human >= 100): the (0..10) rows all have
    # worst_fpr None, so the fpr_ci index mutants never execute. Kills
    # NumberReplacer:94/95/97 [937,46/74].
    for n, flipped in ((100, 0), (100, 2)):
        prev, curr, labels, slices = D._human_slice(n, flipped=flipped)
        _run(
            ("now", n, flipped),
            current_records=curr,
            previous_records=prev,
            baseline_records=prev,
            labels=labels,
            slices=slices,
            detector_id="d",
            calibration_created_at=None,
            now=now,
        )
    return rows


# ---------------------------------------------------------------------------
# _standalone_verify
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# _standalone_verify — verify_bundle_bytes (W2-F2 Batch 6c)
#
# Strengthened (Worker F2, 2026-11-11) from the survivor draft's Cluster 2
# plan: the original grid had only 7 valid small bundles, so none of the
# entry-metadata, size-cap, comment, or digest-failure paths was exercised.
# Rows now record (name, signature, bundle_sha256-is-None, [(id, status,
# detail)], gaps, exit_code, scope_statement) — the detail/exit_code/scope
# fields are what distinguish the exit_code NumberReplacers, the Add_*
# string families, and the scope-statement Eq families. The sha256 is
# recorded as a boolean only: the hash VALUE embeds verify.py's own bytes,
# so recording it would make every _standalone_verify mutant distinguish
# vacuously (the probe input changes under the mutant).
# ---------------------------------------------------------------------------


def _sa_cd_records(data):
    """Walk the central directory; yield (name, record_offset)."""
    import struct

    eocd = data.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack("<I", data[eocd + 16 : eocd + 20])[0]
    cd_size = struct.unpack("<I", data[eocd + 12 : eocd + 16])[0]
    pos = cd_offset
    end = cd_offset + cd_size
    while pos + 46 <= end and data[pos : pos + 4] == b"PK\x01\x02":
        name_len, extra_len, comment_len = struct.unpack("<HHH", data[pos + 28 : pos + 34])
        name = data[pos + 46 : pos + 46 + name_len].decode("utf-8", "surrogateescape")
        yield name, pos
        pos += 46 + name_len + extra_len + comment_len


def _sa_patch_cd(data, name, offset, fmt, value):
    """Patch one field of the central-directory record for *name*."""
    import struct

    for entry_name, pos in _sa_cd_records(data):
        if entry_name == name:
            return (
                data[: pos + offset]
                + struct.pack(fmt, value)
                + data[pos + offset + struct.calcsize(fmt) :]
            )
    raise AssertionError(f"no central-directory record for {name!r}")


def _sa_patch_local(data, name, offset, fmt, value):
    """Patch one field of the local header for *name* (via zipfile offsets)."""
    import io
    import struct
    import zipfile

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.filename == name:
                pos = info.header_offset + offset
                return data[:pos] + struct.pack(fmt, value) + data[pos + struct.calcsize(fmt) :]
    raise AssertionError(f"no local header for {name!r}")


def _sa_patch_eocd_count(data, n):
    """Set both EOCD entry-count fields to *n*."""
    import struct

    eocd = data.rfind(b"PK\x05\x06")
    data = data[: eocd + 8] + struct.pack("<H", n) + data[eocd + 10 :]
    data = data[: eocd + 10] + struct.pack("<H", n) + data[eocd + 12 :]
    return data


def _sa_corrupt_entry_data(data, name):
    """Flip one byte of *name*'s STORED data in *data*.

    The central-directory CRC is left untouched, so reading the entry
    raises BadZipFile (CRC mismatch). The container loop still passes
    (CD fields unchanged), so the read loop's except path is exercised.
    """
    import io
    import struct
    import zipfile

    zf = zipfile.ZipFile(io.BytesIO(data))
    info = zf.getinfo(name)
    fn_len, extra_len = struct.unpack_from("<HH", data, info.header_offset + 26)
    data_off = info.header_offset + 30 + fn_len + extra_len
    bad = bytearray(data)
    bad[data_off] ^= 0xFF
    return bytes(bad)


def _sa_write_zip(entries, *, field_overrides=None, comment=None):
    """Build a zip with zipfile directly (sorted names, STORED, fixed date).

    *field_overrides*: name -> dict of ZipInfo attributes to set
    (create_system, date_time, external_attr, extra, comment,
    compress_type). The archive comment defaults to COMMENT_PREFIX +
    sha256(manifest_bytes) via S._set_archive_comment.
    """
    import hashlib
    import io
    import zipfile

    import test_standalone_verify as S

    field_overrides = field_overrides or {}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for name in sorted(entries):
            info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 0
            info.external_attr = 0o644 << 16
            for attr, value in field_overrides.get(name, {}).items():
                setattr(info, attr, value)
            zf.writestr(info, entries[name])
    data = buf.getvalue()
    if comment is None:
        manifest_bytes = entries.get("manifest.json", b"")
        comment = ("mpl-bundle-sha256:" + hashlib.sha256(manifest_bytes).hexdigest()).encode(
            "ascii"
        )
    return S._set_archive_comment(data, comment)


def _sa_manifest_bytes(manifest):
    import test_standalone_verify as S

    return S.canonical_json(manifest)


def _sa_bundle_with_manifest(manifest, entries, *, comment=None):
    """Pack *entries* with *manifest* as manifest.json (consistent comment)."""
    import hashlib

    entries = dict(entries)
    manifest_bytes = _sa_manifest_bytes(manifest)
    entries["manifest.json"] = manifest_bytes
    if comment is None:
        comment = ("mpl-bundle-sha256:" + hashlib.sha256(manifest_bytes).hexdigest()).encode(
            "ascii"
        )
    return _sa_write_zip(entries, comment=comment)


def probe_sa_verify_bundle():
    import copy
    import hashlib

    import test_standalone_verify as S

    from textforensics._standalone_verify import (
        MAX_BUNDLE_BYTES,
        MAX_ENTRY_BYTES,
        MAX_MANIFEST_BYTES,
        MAX_SEALED_RESULTS_BYTES,
        MAX_TIMESTAMP_TOKEN_BYTES,
        verify_bundle_bytes,
    )
    from textforensics.dsse import sign_envelope
    from textforensics.ed25519 import public_key_from_seed

    rows = []
    # Base valid bundle + case, built once and reused by the custom rows.
    case_bytes0, case0 = S.build_case_bytes()
    verifier_bytes = S.STANDALONE_PATH.read_bytes()
    base_entries = {"case.json": case_bytes0, "verify.py": verifier_bytes}
    base_manifest = S.make_manifest(base_entries, case_id=case0["case_sha256"])
    valid_data = _sa_bundle_with_manifest(base_manifest, base_entries)

    def bundle(
        case_bytes=None,
        case=None,
        *,
        case_id="KEEP",
        signature="KEEP",
        extra_entries=None,
        manifest=None,
    ):
        """Rebuild a bundle around (case_bytes, manifest).

        By default the manifest is rebuilt consistently (files list with
        correct sha/size, comment digest over the manifest bytes); pass
        *manifest* to use a hand-built one instead.
        """
        entries = dict(base_entries)
        if case_bytes is not None:
            entries["case.json"] = case_bytes
        if extra_entries:
            entries.update(extra_entries)
        if manifest is None:
            manifest = S.make_manifest(entries, case_id=case0["case_sha256"])
            if case_id != "KEEP":
                manifest["context"]["case_id"] = case_id
            if signature != "KEEP":
                manifest["context"]["signature"] = signature
        return _sa_bundle_with_manifest(manifest, entries)

    def case_with(mutate):
        """A (case_bytes, case) pair with *mutate* applied to the case dict."""
        case = copy.deepcopy(case0)
        mutate(case)
        return S.canonical_json(case), case

    def row(name, data, **kwargs):
        out = outcome(verify_bundle_bytes, data, **kwargs)
        if out[0] == "ok":
            import ast as _ast

            rep = _ast.literal_eval(out[1])
            rows.append(
                (
                    (name,),
                    rep["signature"],
                    # Boolean only: the hash VALUE embeds verify.py's
                    # own bytes, so recording it would make every
                    # _standalone_verify mutant "distinguish" vacuously
                    # (the probe input changes under the mutant).
                    rep["bundle_sha256"] is None,
                    [(c["id"], c["status"], c["detail"]) for c in rep["checks"]],
                    list(rep["gaps"]),
                    rep["exit_code"],
                    rep["scope_statement"],
                )
            )
        else:
            rows.append(((name,), out))

    # -- valid bundles (kept from the original grid) --
    row("sorted", S.build_bundle()[0])
    row("unsorted", S.build_bundle()[0])
    row("names-unsorted", S.pack_bundle({"b.txt": b"bee", "a.txt": b"aye"}, sort=False))
    row("names-sorted", S.pack_bundle({"b.txt": b"bee", "a.txt": b"aye"}, sort=True))
    row("deflate", S.pack_bundle({"a.txt": b"aye" * 100}, deflate={"a.txt"}))
    row("stored", S.pack_bundle({"a.txt": b"aye" * 100}, deflate=None))
    row("sig-bad-token", S.build_bundle(token_der=b"\x00\x01\x02")[0])
    row("valid", valid_data)
    row("valid-expected-match", valid_data, expected_digest=hashlib.sha256(valid_data).hexdigest())
    row("expected-low", valid_data, expected_digest="0" * 64)
    row("expected-high", valid_data, expected_digest="f" * 64)

    # -- signature states: unavailable (exit 2) / verified / wrong payload --
    row("sig-unavailable", bundle(signature="not-a-dsse-envelope"))
    seed = b"\x01" * 32
    public_key = public_key_from_seed(seed)
    unsigned = copy.deepcopy(base_manifest)
    unsigned["context"]["signature"] = None
    payload = S.canonical_json(unsigned)
    envelope = sign_envelope("textforensics.sealed-bundle-manifest/v1", payload, seed)
    row("sig-verified", bundle(signature=envelope), public_key=public_key)
    wrong_payload = sign_envelope(
        "textforensics.sealed-bundle-manifest/v1", b"~not-this-manifest", seed
    )
    row("sig-wrong-payload", bundle(signature=wrong_payload), public_key=public_key)

    # -- outer-size caps (288 MiB) --
    row("outer-exact-288M", b"\x00" * MAX_BUNDLE_BYTES)
    row("outer-over-288M", b"\x00" * (MAX_BUNDLE_BYTES + 1))

    # -- EOCD failures / entry-count lies --
    row("eocd-garbage", b"not a zip archive at all")
    row("eocd-count-1024", _sa_patch_eocd_count(valid_data, 1024))
    row("eocd-count-1025", _sa_patch_eocd_count(valid_data, 1025))

    # -- normalised-entry variants (one bad field each, on "a.txt") --
    tiny = {"a.txt": b"aye"}
    row("norm-create-system", _sa_write_zip(tiny, field_overrides={"a.txt": {"create_system": 3}}))
    row(
        "norm-mod-date",
        _sa_write_zip(tiny, field_overrides={"a.txt": {"date_time": (2024, 5, 6, 7, 8, 10)}}),
    )
    # mod_date AFTER 1980-01-01 but mod_time == 0: only the mod_date clause
    # of the normalised-entries OR can fail. (The norm-mod-date row above
    # also sets mod_time != 0, so it cannot distinguish the mod_date
    # comparison mutants.)
    row(
        "norm-mod-date-only",
        _sa_write_zip(tiny, field_overrides={"a.txt": {"date_time": (2024, 5, 6, 0, 0, 0)}}),
    )
    row("norm-mod-date-low", _sa_patch_cd(_sa_write_zip(tiny), "a.txt", 14, "<H", 0))
    row(
        "norm-mod-time",
        _sa_write_zip(tiny, field_overrides={"a.txt": {"date_time": (1980, 1, 1, 0, 0, 2)}}),
    )
    row(
        "norm-external-high",
        _sa_write_zip(tiny, field_overrides={"a.txt": {"external_attr": 0o777 << 16}}),
    )
    row(
        "norm-external-low",
        _sa_write_zip(tiny, field_overrides={"a.txt": {"external_attr": 0o600 << 16}}),
    )
    row("norm-extra", _sa_write_zip(tiny, field_overrides={"a.txt": {"extra": b"XX"}}))
    row("norm-comment", _sa_write_zip(tiny, field_overrides={"a.txt": {"comment": b"note"}}))

    # -- read failure (CRC corruption): the read loop's except path --
    # Flipping one byte of case.json's STORED data makes zipfile raise
    # BadZipFile (CRC mismatch, caught) -> container_read fail, exit 1.
    # (Truncation would raise EOFError, which the except tuple does not
    # catch, so it cannot exercise this path.)
    row("read-crc-bad", _sa_corrupt_entry_data(valid_data, "case.json"))

    # -- declared-size lies (central directory + local header agree) --
    declared_max = _sa_patch_local(
        _sa_patch_cd(valid_data, "manifest.json", 24, "<I", MAX_ENTRY_BYTES),
        "manifest.json",
        22,
        "<I",
        MAX_ENTRY_BYTES,
    )
    row("declared-max", declared_max)
    declared_max1 = _sa_patch_local(
        _sa_patch_cd(valid_data, "manifest.json", 24, "<I", MAX_ENTRY_BYTES + 1),
        "manifest.json",
        22,
        "<I",
        MAX_ENTRY_BYTES + 1,
    )
    row("declared-max-plus-1", declared_max1)
    big_declared = {}
    for suffix in ("a", "b", "c", "d"):
        big_declared[f"{suffix}.bin"] = b"x"
    total_exact = _sa_write_zip(big_declared)
    for suffix in ("a", "b", "c", "d"):
        total_exact = _sa_patch_cd(total_exact, f"{suffix}.bin", 24, "<I", MAX_ENTRY_BYTES)
    row("declared-total-exact", total_exact)
    total_plus = _sa_write_zip(dict(big_declared, **{"e.bin": b"y"}))
    for suffix in ("a", "b", "c", "d"):
        total_plus = _sa_patch_cd(total_plus, f"{suffix}.bin", 24, "<I", MAX_ENTRY_BYTES)
    total_plus = _sa_patch_cd(total_plus, "e.bin", 24, "<I", 1)
    row("declared-total-plus-1", total_plus)

    # -- real MAX-byte entry (read-size / on-read-cap mutants) --
    real_max_entries = dict(base_entries)
    real_max_entries["a.txt"] = b"x" * MAX_ENTRY_BYTES
    row("entry-real-max", bundle(extra_entries={"a.txt": b"x" * MAX_ENTRY_BYTES}))

    # -- manifest-size caps (1 MiB) --
    # Exact byte length: canonical JSON grows by len('"padding":"<pad>"')
    # minus the empty value; recompute by construction.
    def manifest_exact(target):
        man = S.make_manifest(base_entries, case_id=case0["case_sha256"])
        base_len = len(_sa_manifest_bytes(man))
        # '"padding":""' adds 13 chars for the key + quotes; each pad char adds 1.
        pad_len = target - base_len - 13
        assert pad_len >= 0
        man["padding"] = "x" * pad_len
        data = _sa_bundle_with_manifest(man, base_entries)
        assert len(_sa_manifest_bytes(man)) == target, (len(_sa_manifest_bytes(man)), target)
        return data

    row("manifest-exact-1m", manifest_exact(MAX_MANIFEST_BYTES))
    row("manifest-over-1m", manifest_exact(MAX_MANIFEST_BYTES + 1))

    # -- archive-comment variants --
    comment_over = hashlib.sha256(_sa_manifest_bytes(base_manifest)).hexdigest()
    row(
        "comment-nonascii",
        _sa_write_zip(
            base_entries | {"manifest.json": _sa_manifest_bytes(base_manifest)},
            comment=b"mpl-bundle-sha256:" + b"\xff" * 64,
        ),
    )
    row(
        "comment-wrong-prefix",
        _sa_write_zip(
            base_entries | {"manifest.json": _sa_manifest_bytes(base_manifest)},
            comment=("sha256:" + comment_over).encode("ascii"),
        ),
    )
    row(
        "comment-short-digest",
        _sa_write_zip(
            base_entries | {"manifest.json": _sa_manifest_bytes(base_manifest)},
            comment=("mpl-bundle-sha256:" + "a" * 63).encode("ascii"),
        ),
    )
    row(
        "comment-long-digest",
        _sa_write_zip(
            base_entries | {"manifest.json": _sa_manifest_bytes(base_manifest)},
            comment=("mpl-bundle-sha256:" + "a" * 65).encode("ascii"),
        ),
    )
    row(
        "comment-nonhex-digest",
        _sa_write_zip(
            base_entries | {"manifest.json": _sa_manifest_bytes(base_manifest)},
            comment=("mpl-bundle-sha256:" + "g" + "a" * 63).encode("ascii"),
        ),
    )
    row(
        "comment-mismatch-digest",
        _sa_write_zip(
            base_entries | {"manifest.json": _sa_manifest_bytes(base_manifest)},
            comment=("mpl-bundle-sha256:" + "f" * 64).encode("ascii"),
        ),
    )

    # -- manifest-shape variants (hand-built manifest, consistent comment) --
    garbage = b"{not json"
    row(
        "manifest-unparseable",
        _sa_write_zip(
            base_entries | {"manifest.json": garbage},
            comment=("mpl-bundle-sha256:" + hashlib.sha256(garbage).hexdigest()).encode("ascii"),
        ),
    )
    nonutf8 = b"\xff\xfe{bad utf8"
    row(
        "manifest-nonutf8",
        _sa_write_zip(
            base_entries | {"manifest.json": nonutf8},
            comment=("mpl-bundle-sha256:" + hashlib.sha256(nonutf8).hexdigest()).encode("ascii"),
        ),
    )
    wrong_schema = copy.deepcopy(base_manifest)
    wrong_schema["schema"] = "textforensics.sealed-bundle-manifest/v2"
    row("manifest-wrong-schema", bundle(manifest=wrong_schema))
    schema_low = copy.deepcopy(base_manifest)
    schema_low["schema"] = "a"
    row("manifest-schema-low", bundle(manifest=schema_low))
    schema_high = copy.deepcopy(base_manifest)
    schema_high["schema"] = "z"
    row("manifest-schema-high", bundle(manifest=schema_high))
    row(
        "manifest-is-list",
        _sa_write_zip(
            base_entries | {"manifest.json": S.canonical_json([1, 2, 3])},
            comment=(
                "mpl-bundle-sha256:" + hashlib.sha256(S.canonical_json([1, 2, 3])).hexdigest()
            ).encode("ascii"),
        ),
    )
    files_not_list = copy.deepcopy(base_manifest)
    files_not_list["files"] = "nope"
    row("manifest-files-not-list", bundle(manifest=files_not_list))
    files_nonstring = copy.deepcopy(base_manifest)
    files_nonstring["files"][0]["path"] = 123
    row("manifest-files-nonstring-path", bundle(manifest=files_nonstring))
    names_unsorted = copy.deepcopy(base_manifest)
    names_unsorted["files"] = list(reversed(names_unsorted["files"]))
    row("manifest-names-unsorted", bundle(manifest=names_unsorted))
    digest_order = copy.deepcopy(base_manifest)
    digest_order["files"] = [
        "junk",
        {"path": "missing.json", "role": "other", "sha256": "0" * 64, "size": 0},
    ]
    row("manifest-digest-order", bundle(manifest=digest_order))
    missing_then_bad = copy.deepcopy(base_manifest)
    case_entry = [f for f in missing_then_bad["files"] if f["path"] == "case.json"][0]
    missing_then_bad["files"] = [
        {"path": "missing.json", "role": "other", "sha256": "0" * 64, "size": 0},
        {"path": "case.json", "role": "case-file", "sha256": "f" * 64, "size": case_entry["size"]},
    ]
    row("manifest-missing-then-bad", bundle(manifest=missing_then_bad))
    sha_high = copy.deepcopy(base_manifest)
    for f in sha_high["files"]:
        if f["path"] == "case.json":
            f["sha256"] = "f" * 64
    row("manifest-sha-high", bundle(manifest=sha_high))
    size_plus = copy.deepcopy(base_manifest)
    for f in size_plus["files"]:
        if f["path"] == "case.json":
            f["size"] = f["size"] + 1
    row("manifest-size-plus-1", bundle(manifest=size_plus))
    size_minus = copy.deepcopy(base_manifest)
    for f in size_minus["files"]:
        if f["path"] == "case.json":
            f["size"] = f["size"] - 1
    row("manifest-size-minus-1", bundle(manifest=size_minus))
    ctx_missing = copy.deepcopy(base_manifest)
    del ctx_missing["context"]
    row("manifest-context-missing", bundle(manifest=ctx_missing))
    row("manifest-extra-low", bundle(extra_entries={"extra.txt": b"extra"}))
    row("manifest-extra-high", bundle(extra_entries={"z.txt": b"extra"}))

    # -- case-file variants (mutated case, manifest rebuilt consistently) --
    row("case-unparseable", bundle(case_bytes=b"{oops"))
    row("case-nonutf8", bundle(case_bytes=b"\xff\xfe"))
    row("case-is-list", bundle(case_bytes=S.canonical_json([1, 2])))
    sha_low_bytes, _ = case_with(lambda c: c.update({"case_sha256": "0" * 64}))
    row("case-sha-low", bundle(case_bytes=sha_low_bytes))
    rawtext_bytes, _ = case_with(lambda c: c.update({"raw_text_included": 0}))
    row("case-rawtext-zero", bundle(case_bytes=rawtext_bytes))
    forbidden_bytes, _ = case_with(
        lambda c: c.update(
            {
                k: "x"
                for k in ("text", "raw_text", "source_text", "document_text", "content", "snippet")
            }
        )
    )
    row("case-forbidden-6", bundle(case_bytes=forbidden_bytes))
    row("case-id-none", bundle(case_id=None))
    row("case-id-low", bundle(case_id="0" * 64))
    row("case-id-high", bundle(case_id="f" * 64))
    input_low_bytes, _ = case_with(lambda c: c["input"].update({"content_sha256": "0" * 64}))
    row("case-input-hash-low", bundle(case_bytes=input_low_bytes))
    input_high_bytes, _ = case_with(lambda c: c["input"].update({"content_sha256": "f" * 64}))
    row("case-input-hash-high", bundle(case_bytes=input_high_bytes))

    def _nodet_item():
        item = copy.deepcopy(case0["detector_observations"][0])
        item.pop("determinism", None)
        return item

    nodet_bytes, _ = case_with(lambda c: c["detector_observations"].__setitem__(0, _nodet_item()))
    row("case-obs-nodet", bundle(case_bytes=nodet_bytes))
    obs_break_bytes, _ = case_with(
        lambda c: c.update({"detector_observations": ["junk", _nodet_item()]})
    )
    row("case-obs-break", bundle(case_bytes=obs_break_bytes))
    obs_nondict_bytes, _ = case_with(
        lambda c: c.update(
            {"detector_observations": ["junk", copy.deepcopy(case0["detector_observations"][0])]}
        )
    )
    row("case-obs-nondict", bundle(case_bytes=obs_nondict_bytes))

    def _kind_item(kind):
        item = _nodet_item()
        item["kind"] = kind
        return item

    kind_low_bytes, _ = case_with(
        lambda c: c.update({"detector_observations": [_kind_item("aaa")]})
    )
    row("case-obs-kind-low", bundle(case_bytes=kind_low_bytes))
    kind_high_bytes, _ = case_with(
        lambda c: c.update({"detector_observations": [_kind_item("zzz")]})
    )
    row("case-obs-kind-high", bundle(case_bytes=kind_high_bytes))
    reason_int_bytes, _ = case_with(
        lambda c: c["detector_observations"][0].update({"determinism_reason": 123})
    )
    row("case-obs-reason-int", bundle(case_bytes=reason_int_bytes))
    process_str_bytes, _ = case_with(lambda c: c.update({"process": "x"}))
    row("case-process-str", bundle(case_bytes=process_str_bytes))
    v3_bytes, _ = case_with(lambda c: c.update({"schema": "textforensics.case-file/v3"}))
    row("case-v3", bundle(case_bytes=v3_bytes))
    v3_kind_bytes, _ = case_with(
        lambda c: (
            c.update({"schema": "textforensics.case-file/v3"}),
            c.update({"detector_observations": [_kind_item("aaa")]}),
        )
    )
    row("case-v3-kind", bundle(case_bytes=v3_kind_bytes))
    # v3 case whose first observation has NO determinism declaration: the
    # v4-only missing-declaration error is appended only when the schema
    # comparison at the determinism loop says "v4".
    v3_nodet_bytes, _ = case_with(
        lambda c: (
            c.update({"schema": "textforensics.case-file/v3"}),
            c["detector_observations"].__setitem__(0, _nodet_item()),
        )
    )
    row("case-v3-nodet", bundle(case_bytes=v3_nodet_bytes))

    def _detdiff_item():
        item = copy.deepcopy(case0["detector_observations"][0])
        # "non_deterministic" differs from the bundle-recorded
        # "deterministic" expected value, so the v4 EXACT observation
        # comparison fails while the v3 STRIPPED comparison passes.
        item["determinism"] = "non_deterministic"
        return item

    detdiff_bytes, _ = case_with(
        lambda c: c["detector_observations"].__setitem__(0, _detdiff_item())
    )
    row("case-obs-detdiff", bundle(case_bytes=detdiff_bytes))
    v3_detdiff_bytes, _ = case_with(
        lambda c: (
            c.update({"schema": "textforensics.case-file/v3"}),
            c["detector_observations"].__setitem__(0, _detdiff_item()),
        )
    )
    row("case-v3-detdiff", bundle(case_bytes=v3_detdiff_bytes))

    def _ref(sha, rid):
        return {"registry_sha256": sha, "registry_id": rid}

    refs_low_bytes, _ = case_with(
        lambda c: c.update({"validation_refs": [_ref("0" * 64, "f" * 64)]})
    )
    row("case-ref-low", bundle(case_bytes=refs_low_bytes))
    refs_high_bytes, _ = case_with(
        lambda c: c.update({"validation_refs": [_ref("f" * 64, "0" * 64)]})
    )
    row("case-ref-high", bundle(case_bytes=refs_high_bytes))
    refs_match_bytes, _ = case_with(
        lambda c: c.update({"validation_refs": [_ref(case0["case_sha256"], case0["case_sha256"])]})
    )
    row("case-ref-match", bundle(case_bytes=refs_match_bytes))
    refs_nondict_bytes, _ = case_with(lambda c: c.update({"validation_refs": ["junk"]}))
    row("case-ref-nondict", bundle(case_bytes=refs_nondict_bytes))
    refs_break_bytes, _ = case_with(
        lambda c: c.update({"validation_refs": ["junk", _ref("0" * 64, "f" * 64)]})
    )
    row("case-ref-break", bundle(case_bytes=refs_break_bytes))

    def _plain(mutate):
        def _do(case):
            plain = case["limitations"]["plain_language"]
            mutate(plain)

        return _do

    limit_missing_bytes, _ = case_with(_plain(lambda p: p.pop("human_fpr", None)))
    row("case-limitations-missing", bundle(case_bytes=limit_missing_bytes))
    limit_int_bytes, _ = case_with(_plain(lambda p: p.update({"human_fpr": 123})))
    row("case-limitations-int", bundle(case_bytes=limit_int_bytes))
    algo_low_bytes, _ = case_with(lambda c: c["seal"].update({"algorithm": "a"}))
    row("case-seal-algo-low", bundle(case_bytes=algo_low_bytes))
    algo_high_bytes, _ = case_with(lambda c: c["seal"].update({"algorithm": "z"}))
    row("case-seal-algo-high", bundle(case_bytes=algo_high_bytes))
    head_low_bytes, _ = case_with(lambda c: c["seal"].update({"custody_head": "0" * 64}))
    row("case-custody-head-low", bundle(case_bytes=head_low_bytes))
    head_high_bytes, _ = case_with(lambda c: c["seal"].update({"custody_head": "f" * 64}))
    row("case-custody-head-high", bundle(case_bytes=head_high_bytes))

    def _custody_2(case):
        import test_standalone_verify as _S

        mod = _S.load_standalone()
        first = copy.deepcopy(case["custody"][0])
        second = {
            "actor": "probe",
            "action": "seal",
            "at_utc": "1970-01-01T00:00:00+00:00",
            "note": None,
            "prev_hash": first["entry_hash"],
        }
        second["entry_hash"] = mod._custody_entry_hash(
            second["actor"], second["action"], second["at_utc"], second["note"], second["prev_hash"]
        )
        case["custody"] = [first, second]
        case["seal"]["custody_head"] = second["entry_hash"]

    custody2_bytes, _ = case_with(_custody_2)
    row("case-custody-2", bundle(case_bytes=custody2_bytes))

    # -- case-size caps (32 MiB) --
    def case_exact(target):
        c = copy.deepcopy(case0)
        base_len = len(S.canonical_json(c))
        # '"padding":""' adds 13 chars; each pad char adds 1.
        pad_len = target - base_len - 13
        assert pad_len >= 0, (base_len, target)
        c["padding"] = "x" * pad_len
        data = bundle(case_bytes=S.canonical_json(c))
        assert len(S.canonical_json(c)) == target
        return data

    row("case-exact-32m", case_exact(MAX_SEALED_RESULTS_BYTES))
    row("case-over-32m", case_exact(MAX_SEALED_RESULTS_BYTES + 1))

    # -- timestamp-token caps (1 MiB) --
    row("token-exact-1m", S.build_bundle(token_der=b"\x00" * MAX_TIMESTAMP_TOKEN_BYTES)[0])
    row("token-over-1m", S.build_bundle(token_der=b"\x00" * (MAX_TIMESTAMP_TOKEN_BYTES + 1))[0])
    return rows


# ---------------------------------------------------------------------------
# semantic._compute_consistency_score (new probe, W2-F kill tests)
# ---------------------------------------------------------------------------
def _sem_segment(ttr=0.5, entropy=1.0, hapax=0.2, wc=10, index=0):
    from textforensics.semantic import SemanticSegment

    return SemanticSegment(
        index=index,
        text="x",
        word_count=wc,
        sentence_count=1,
        avg_word_length=4.0,
        type_token_ratio=ttr,
        hapax_ratio=hapax,
        pos_distribution={},
        semantic_density=1.0,
        entropy=entropy,
    )


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
        (
            "all-spread",
            [
                _sem_segment(ttr=v, entropy=2 * v, hapax=v, wc=int(100 * v))
                for v in (0.0, 0.05, 0.10)
            ],
        ),
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
            rows.append(
                (
                    n_sent,
                    rep.n_segments,
                    rep.support_status,
                    rep.overall_consistency_score is None,
                    rep.risk_level,
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append((n_sent, ("raise", type(exc).__name__, str(exc))))
    return rows


# ---------------------------------------------------------------------------
# schema trust-map validators (new probes, W2-F kill tests)
# ---------------------------------------------------------------------------
def _schema_map(version="v3", dims=None, **overrides):
    from textforensics.trust import TRUST_DIMENSIONS

    if dims is None:
        dims = [
            {"dimension": d, "state": "supported", "reason": "ok"} for d in sorted(TRUST_DIMENSIONS)
        ]
    m = {
        "schema": f"textforensics.trust-map/{version}",
        "dimensions": dims,
        "input_conditions": {"language": "en"},
        "evidence_registry": {},
        "generated_at_utc": "2026-01-01T00:00:00Z",
        "coverage": {"supported": len(dims), "partial": 0, "unknown": 0, "out_of_scope": 0},
    }
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
        (
            "dim-string-then-bad",
            _schema_map("v3", dims=["language", {"dimension": dims[0], "state": "bogus"}]),
        ),
        (
            "dim-no-name-then-bad",
            _schema_map(
                "v3", dims=[{"state": "supported"}, {"dimension": dims[0], "state": "bogus"}]
            ),
        ),
        ("dim-no-name", _schema_map("v3", dims=[{"state": "supported"}])),
        ("dim-empty-name", _schema_map("v3", dims=[{"dimension": "", "state": "supported"}])),
        (
            "state-bogus",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "bogus"}]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
        ),
        (
            "v2-stale-state",
            _schema_map(
                "v2",
                dims=[{"dimension": dims[0], "state": "stale"}]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
        ),
        (
            "v3-stale-state-ok",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "stale"}]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
        ),
        (
            "dup2",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "supported"}] * 2
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
        ),
        (
            "dup3",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "supported"}] * 3
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
        ),
        (
            "unknown-dim",
            _schema_map(
                "v3",
                dims=[{"dimension": "nope", "state": "supported"}]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
        ),
        (
            "missing-dim",
            _schema_map(
                "v3",
                dims=[{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
        ),
        (
            "two-invalid",
            _schema_map(
                "v3",
                dims=[
                    {"dimension": dims[0], "state": "bogus"},
                    {"dimension": dims[1], "state": "bogus"},
                ]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[2:]],
            ),
        ),
        ("empty-dims", _schema_map("v3", dims=[])),
    ]
    return [(name, outcome(validate_trust_map_dimensions, m)) for name, m in cases]


def probe_schema_completeness():

    from textforensics.schema import validate_trust_map_completeness
    from textforensics.trust import TRUST_DIMENSIONS

    dims = sorted(TRUST_DIMENSIONS)
    base = _schema_map("v3")
    cases = [
        ("valid-v3", base),
        ("valid-v2", _schema_map("v2")),
        ("list-map", []),
        ("v1", _schema_map("v1")),
        (
            "reason-123",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "supported", "reason": 123}]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
        ),
        (
            "reason-empty",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "supported", "reason": ""}]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
        ),
        (
            "reason-missing",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "supported"}]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
        ),
        (
            "two-bad-reasons",
            _schema_map(
                "v3",
                dims=[
                    {"dimension": dims[0], "state": "supported", "reason": ""},
                    {"dimension": dims[1], "state": "supported", "reason": 1},
                ]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[2:]],
            ),
        ),
        (
            "reason-nonmapping-then-bad",
            _schema_map(
                "v3",
                dims=[123, {"dimension": dims[0], "state": "supported", "reason": ""}]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
        ),
        (
            "counts-nonmapping",
            _schema_map(
                "v3",
                dims=[123] + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims],
            ),
        ),
        ("no-input-conditions", {k: v for k, v in base.items() if k != "input_conditions"}),
        ("input-conditions-list", _schema_map("v3", input_conditions=[])),
        ("no-evidence-registry", {k: v for k, v in base.items() if k != "evidence_registry"}),
        ("generated-none", _schema_map("v3", generated_at_utc=None)),
        ("generated-empty", _schema_map("v3", generated_at_utc="")),
        ("coverage-list", _schema_map("v3", coverage=[])),
        ("coverage-extra", _schema_cov(base, bogus=1)),
        ("coverage-missing", {k: v for k, v in base.items() if k != "coverage"}),
        (
            "coverage-missing-key",
            _schema_map(
                "v3",
                coverage={"supported": len(dims), "partial": 0, "unknown": 0, "out_of_scope": 0},
            ),
        ),
        ("coverage-bool", _schema_cov(base, supported=True)),
        ("coverage-str", _schema_cov(base, supported="x")),
        ("coverage-neg", _schema_cov(base, supported=-1)),
        ("coverage-zero", _schema_cov(base, supported=0)),
        ("coverage-wrong-count", _schema_cov(base, supported=len(dims) - 1, partial=1)),
        (
            "coverage-300",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "supported", "reason": "ok"}] * 300,
                coverage={
                    "supported": 300,
                    "partial": 0,
                    "unknown": 0,
                    "out_of_scope": 0,
                    "stale": 0,
                },
            ),
        ),
        (
            "coverage-300-off",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "supported", "reason": "ok"}] * 300,
                coverage={
                    "supported": 299,
                    "partial": 0,
                    "unknown": 0,
                    "out_of_scope": 0,
                    "stale": 0,
                },
            ),
        ),
    ]
    return [(name, outcome(validate_trust_map_completeness, m)) for name, m in cases]


def probe_schema_load():
    from textforensics.schema import load_schema

    rows = []
    rows.append(("maxsize", outcome(lambda: load_schema.cache_info().maxsize)))
    rows.append(("bogus-name", outcome(load_schema, "no-such-schema")))
    rows.append(("bad-version", outcome(load_schema, "case-file", version="v9")))
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
    r = {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "evaluated": evaluated,
        "accuracy": acc,
        "true_positive_rate": tpr,
        "false_positive_rate": fpr,
        "specificity": spec,
        "false_negative_rate": fnr,
        "precision": prec,
        "dataset_sha256": fp_sha if fp_sha is not None else "a" * 64,
    }
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
        # zero denominators with total > 0 (inside `if total:`): the else-0.0
        # NumberReplacers and the ** mutants (0**0 == 1 -> ZeroDivisionError)
        ("tp-fn-0-fp1", _bm_result(tp=0, fn=0, fp=1, tn=1, evaluated=2)),
        ("tp-fn-0-fp1-tn0", _bm_result(tp=0, fn=0, fp=1, tn=0, evaluated=1)),
        ("fn-tp-0", _bm_result(tp=0, fn=2, fp=1, tn=0, evaluated=3)),
        ("fp-tn-0", _bm_result(tp=1, fn=0, fp=0, tn=0, evaluated=1)),
        ("tp-fp-0", _bm_result(tp=0, fn=1, fp=0, tn=1, evaluated=2)),
        ("tn-fp-0", _bm_result(tp=1, fn=1, fp=0, tn=0, evaluated=2)),
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
        (
            "diff-exact-001",
            _bm_result(tp=0, fn=0, fp=0, tn=0, evaluated=0, rates={"true_positive_rate": 0.001}),
        ),
        (
            "diff-01",
            _bm_result(tp=0, fn=0, fp=0, tn=0, evaluated=0, rates={"true_positive_rate": 0.1}),
        ),
        (
            "diff-05",
            _bm_result(tp=0, fn=0, fp=0, tn=0, evaluated=0, rates={"true_positive_rate": 0.5}),
        ),
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

    from textforensics.casefile import seal_case_file
    from textforensics.report import build_forensic_bundle

    case = seal_case_file(build_forensic_bundle(text).to_dict())
    for path, value in tamper.items():
        obj = case
        keys = path.split(".")
        for k in keys[:-1]:
            obj = obj[k]
        obj[keys[-1]] = value
    return case


def probe_verify_case_file():
    import copy

    from textforensics.verify import verify_case_file

    ascii_text = "The city council approved the budget on Tuesday. " * 20
    nonascii_text = "Café naïve façade — the résumé was über. " * 20
    base = _vc_case(ascii_text)
    base_na = _vc_case(nonascii_text)
    tm = base["forensic_bundle"]["trust_map"]
    derived = tm["overall"]
    cases = [
        ("valid", base),
        ("valid-nonascii", base_na),
        (
            "overall-partial",
            _vc_case(ascii_text, **{"forensic_bundle.trust_map.overall": "partial"}),
        ),
        (
            "overall-unknown",
            _vc_case(ascii_text, **{"forensic_bundle.trust_map.overall": "unknown"}),
        ),
        (
            "overall-supported",
            _vc_case(ascii_text, **{"forensic_bundle.trust_map.overall": "supported"}),
        ),
        (
            "overall-insufficient",
            _vc_case(ascii_text, **{"forensic_bundle.trust_map.overall": "insufficient"}),
        ),
        ("overall-strong", _vc_case(ascii_text, **{"forensic_bundle.trust_map.overall": "strong"})),
        ("overall-same", _vc_case(ascii_text, **{"forensic_bundle.trust_map.overall": derived})),
        # stored overall built dynamically: `is` vs `==` (Eq_Is:15) - the
        # literal "mixed" may be interned, a joined string is not.
        (
            "overall-same-dynamic",
            _vc_case(ascii_text, **{"forensic_bundle.trust_map.overall": "".join(["mi", "xed"])}),
        ),
        # rogue dimension name: _verify_trust_dimension returns a status
        # sorting after "ok" (NotEq_Lt:0).
        (
            "tm-rogue-dim",
            _vc_case(
                ascii_text,
                **{
                    "forensic_bundle.trust_map.dimensions": [
                        {"dimension": "rogue_dim", "state": "supported", "reason": "ok"}
                    ]
                    + tm["dimensions"]
                },
            ),
        ),
        ("raw-0", _vc_case(ascii_text, **{"raw_text_included": 0})),
        ("raw-1", _vc_case(ascii_text, **{"raw_text_included": 1})),
        ("raw-true", _vc_case(ascii_text, **{"raw_text_included": True})),
        ("raw-none", _vc_case(ascii_text, **{"raw_text_included": None})),
        ("input-raw-0", _vc_case(ascii_text, **{"forensic_bundle.input.raw_text_included": 0})),
        (
            "input-raw-true",
            _vc_case(ascii_text, **{"forensic_bundle.input.raw_text_included": True}),
        ),
        ("not-dict", "x"),
        ("list-payload", []),
        ("seal-63", _vc_case(ascii_text, **{"case_sha256": "a" * 63})),
        ("seal-65", _vc_case(ascii_text, **{"case_sha256": "a" * 65})),
        ("seal-upper", _vc_case(ascii_text, **{"case_sha256": "A" * 64})),
        ("content-63", _vc_case(ascii_text, **{"forensic_bundle.content_sha256": "a" * 63})),
        ("content-65", _vc_case(ascii_text, **{"forensic_bundle.content_sha256": "a" * 65})),
        ("content-upper", _vc_case(ascii_text, **{"forensic_bundle.content_sha256": "A" * 64})),
        (
            "tm-v2",
            _vc_case(
                ascii_text, **{"forensic_bundle.trust_map.schema": "textforensics.trust-map/v2"}
            ),
        ),
        (
            "tm-v1",
            _vc_case(
                ascii_text, **{"forensic_bundle.trust_map.schema": "textforensics.trust-map/v1"}
            ),
        ),
        (
            "tm-bad-schema",
            _vc_case(
                ascii_text, **{"forensic_bundle.trust_map.schema": "textforensics.trust-map/v9"}
            ),
        ),
        ("tm-dims-empty", _vc_case(ascii_text, **{"forensic_bundle.trust_map.dimensions": []})),
        (
            "tm-dim-string",
            _vc_case(ascii_text, **{"forensic_bundle.trust_map.dimensions": ["language"]}),
        ),
        (
            "tm-no-trust-map",
            {k: v for k, v in copy.deepcopy(base)["forensic_bundle"].items() if k != "trust_map"}
            and _vc_case(ascii_text),
        ),
        ("bundle-not-dict", _vc_case(ascii_text, **{"forensic_bundle": "x"})),
        ("no-bundle", {k: v for k, v in base.items() if k != "forensic_bundle"}),
        ("bad-case-schema", _vc_case(ascii_text, **{"schema": "textforensics.case-file/v9"})),
        (
            "bad-bundle-schema",
            _vc_case(ascii_text, **{"forensic_bundle.schema": "textforensics.forensic-bundle/v9"}),
        ),
        ("dr-not-list", _vc_case(ascii_text, **{"forensic_bundle.detector_results": "x"})),
        (
            "dr-wrong-schema",
            _vc_case(
                ascii_text,
                **{
                    "forensic_bundle.detector_results": [
                        {"schema": "wrong", "detector_id": "d1", "score": 0.5, "verdict": "ai_like"}
                    ]
                },
            ),
        ),
        (
            "dr-score-str",
            _vc_case(
                ascii_text,
                **{
                    "forensic_bundle.detector_results": [
                        {
                            "schema": "textforensics.detector-result/v2",
                            "detector_id": "d1",
                            "score": "0.5",
                            "verdict": "ai_like",
                        }
                    ]
                },
            ),
        ),
        (
            "dr-score-nan",
            _vc_case(
                ascii_text,
                **{
                    "forensic_bundle.detector_results": [
                        {
                            "schema": "textforensics.detector-result/v2",
                            "detector_id": "d1",
                            "score": float("nan"),
                            "verdict": "ai_like",
                        }
                    ]
                },
            ),
        ),
        (
            "dr-verdict-bad",
            _vc_case(
                ascii_text,
                **{
                    "forensic_bundle.detector_results": [
                        {
                            "schema": "textforensics.detector-result/v2",
                            "detector_id": "d1",
                            "score": 0.5,
                            "verdict": "maybe",
                        }
                    ]
                },
            ),
        ),
    ]
    # v2/v3-divergent map: 1 partial + 8 unknown -> v3 derives "mixed",
    # v2 derives "insufficient" (unknown >= 4 rule). Hand-sealed minimal case.
    import hashlib
    import json
    import math

    from textforensics.trust import TRUST_DIMENSIONS

    dims9 = sorted(TRUST_DIMENSIONS)
    v3dims = [{"dimension": dims9[0], "state": "partial", "reason": "ok"}] + [
        {"dimension": d, "state": "unknown", "reason": "ok"} for d in dims9[1:]
    ]
    tm3 = _schema_map("v3", dims=v3dims)
    tm3["overall"] = "mixed"
    tm3["coverage"] = {"supported": 0, "partial": 1, "unknown": 9, "out_of_scope": 0, "stale": 0}
    minimal = {
        "schema": "textforensics.case-file/v1",
        "raw_text_included": False,
        "forensic_bundle": {
            "schema": "textforensics.forensic-bundle/v2",
            "content_sha256": "a" * 64,
            "trust_map": tm3,
            "input": {"raw_text_included": False},
            "detector_results": [],
        },
        "case_sha256": "x" * 64,
    }

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
    minimal["case_sha256"] = hashlib.sha256(
        json.dumps(
            stripped, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    ).hexdigest()
    cases.append(("v3-partial-unknown", minimal))
    # v2-schema variant of the divergent map: v2 derives "insufficient"
    # (unknown >= 4), v3 derives "mixed". Kills the is_v3 `is not` mutant
    # (which would run the v3 recompute for a v2 map).
    tm2 = _schema_map("v2", dims=v3dims)
    tm2["overall"] = "insufficient"
    tm2["coverage"] = {"supported": 0, "partial": 1, "unknown": 9, "out_of_scope": 0}
    minimal2 = {
        "schema": "textforensics.case-file/v1",
        "raw_text_included": False,
        "forensic_bundle": {
            "schema": "textforensics.forensic-bundle/v2",
            "content_sha256": "a" * 64,
            "trust_map": tm2,
            "input": {"raw_text_included": False},
            "detector_results": [],
        },
        "case_sha256": "x" * 64,
    }
    stripped2 = _sanitize(copy.deepcopy(minimal2))
    stripped2.pop("case_sha256", None)
    stripped2.pop("created_at_utc", None)
    minimal2["case_sha256"] = hashlib.sha256(
        json.dumps(
            stripped2, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    ).hexdigest()
    cases.append(("v2-partial-unknown", minimal2))
    # Non-ASCII in a hashed field, re-sealed with ensure_ascii=False:
    # kills FalseWithTrue:6 [246,25] (ensure_ascii=False -> True): the
    # mutant's canonical bytes escape the character, so the recomputed
    # hash no longer matches the seal. (The "valid-nonascii" row has
    # non-ASCII only in the raw text, which is not hashed.)
    dims_cafe = copy.deepcopy(tm["dimensions"])
    dims_cafe[0]["reason"] = "café"
    cafe = _vc_case(ascii_text, **{"forensic_bundle.trust_map.dimensions": dims_cafe})
    stripped_c = _sanitize(copy.deepcopy(cafe))
    stripped_c.pop("case_sha256", None)
    stripped_c.pop("created_at_utc", None)
    cafe["case_sha256"] = hashlib.sha256(
        json.dumps(
            stripped_c, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    ).hexdigest()
    cases.append(("seal-nonascii-reason", cafe))
    # A tuple containing NaN in a hashed field: _sanitize_for_json recurses
    # dicts and lists but NOT tuples, so the NaN reaches json.dumps and
    # allow_nan=False raises. Kills FalseWithTrue:7 [249,22]
    # (allow_nan=False -> True): the mutant dumps successfully and reports
    # a seal mismatch instead of raising. (A bare NaN float is sanitized
    # to the string "NaN" before the dumps, so it cannot reach the flag.)
    nan_tuple = _vc_case(
        ascii_text, **{"forensic_bundle.trust_map.limitations": ["ok", (float("nan"),)]}
    )
    cases.append(("seal-nan-tuple", nan_tuple))
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
            rows.append(
                (
                    name,
                    (
                        "ok",
                        out["valid"],
                        out["seal_verified"],
                        out["trust_map_verified"],
                        sorted(out["errors"]),
                        sorted(out["dimensions"].items()),
                    ),
                )
            )
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


def _mo_to_dict_record(payload):
    """A record object whose to_dict() returns *payload* (need not be a Mapping)."""
    from types import SimpleNamespace

    return SimpleNamespace(to_dict=lambda: payload)


def _mo_registry(*records):
    # Raw-dict registry: segment_covered_regimes accepts any object with a
    # .records attribute of mappings (or to_dict() objects). Raw dicts let
    # the probe use values ValidationRecord.from_dict would reject
    # (e.g. contamination_flag "clean") while keeping a valid signature.
    from types import SimpleNamespace

    return SimpleNamespace(records=list(records))


def probe_mixed_origin_regimes():
    from textforensics.detectors import BuiltinHeuristicDetector
    from textforensics.mixed_origin import segment_covered_regimes

    # The exact version object segment_covered_regimes compares against
    # when detector_version=None (used by the version-same-object row).
    _MO_VERSION = BuiltinHeuristicDetector.detector_version
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
        (
            "regime-mixed",
            [_mo_record(editing_regime="mixed-origin", domain=("news", "essays"))],
            {},
        ),
        (
            "slice-unknown",
            [
                _mo_record(
                    fpr_slices=(
                        {
                            "slice_id": "other",
                            "value": 0.02,
                            "ci": (0.0, 0.05),
                            "worst_slice": True,
                        },
                    ),
                    domain=("news", "essays"),
                )
            ],
            {},
        ),
        ("bucket-list", [_mo_set(good, "regime.length_bucket", ["x"])], {"word_count": 80}),
        (
            "floor-true",
            [_mo_set(good, "regime.length_bucket.floor_words", True)],
            {"word_count": 80},
        ),
        ("floor-str", [_mo_set(good, "regime.length_bucket.floor_words", "x")], {"word_count": 80}),
        (
            "floor-100-wc99",
            [_mo_set(good, "regime.length_bucket.floor_words", 100)],
            {"word_count": 99},
        ),
        (
            "floor-100-wc100",
            [_mo_set(good, "regime.length_bucket.floor_words", 100)],
            {"word_count": 100},
        ),
        (
            "max-100-wc100",
            [
                _mo_set(
                    _mo_set(good, "regime.length_bucket.max_words", 100),
                    "regime.length_bucket.floor_words",
                    80,
                )
            ],
            {"word_count": 100},
        ),
        (
            "max-100-wc101",
            [
                _mo_set(
                    _mo_set(good, "regime.length_bucket.max_words", 100),
                    "regime.length_bucket.floor_words",
                    80,
                )
            ],
            {"word_count": 101},
        ),
        (
            "max-100-wc99",
            [
                _mo_set(
                    _mo_set(good, "regime.length_bucket.max_words", 100),
                    "regime.length_bucket.floor_words",
                    80,
                )
            ],
            {"word_count": 99},
        ),
        ("max-true", [_mo_set(good, "regime.length_bucket.max_words", True)], {"word_count": 80}),
        ("max-str", [_mo_set(good, "regime.length_bucket.max_words", "x")], {"word_count": 80}),
        ("max-none", [good], {"word_count": 500}),
        ("language-none", [_mo_set(good, "regime.language", None)], {}),
        ("domain-empty", [_mo_set(good, "regime.domain", [])], {}),
        ("language-none-domain-set", [_mo_set(good, "regime.language", None)], {}),
        ("fail-detector-then-good", [_mo_set(good, "detector_id", "zzz"), good], {}),
        ("fail-nhuman-then-good", [_mo_record(n_human=99, domain=("news",)), good], {}),
        ("fail-regime-then-good", [_mo_record(editing_regime="raw", domain=("news",)), good], {}),
        (
            "fail-slice-then-good",
            [
                _mo_record(
                    fpr_slices=({"slice_id": "other", "value": 0.02, "ci": (0.0, 0.05)},),
                    domain=("news",),
                ),
                good,
            ],
            {},
        ),
        # --- fail-X-then-good pairs (the `continue` guards only differ
        # from `break` when a GOOD record follows a skipped one) --------
        ("fail-version-then-good", [_mo_set(good, "detector_version", "9.9.9"), good], {}),
        ("fail-status-then-good", [_mo_record(status="stale", domain=("news",)), good], {}),
        ("fail-data-then-good", [_mo_set(good, "data", None), good], {}),
        # NOTE (F2, disk-verified): the fail-data / fail-regime-notmapping /
        # fail-bucket pairs do NOT kill ContinueWithBreak:5 [185] / :10
        # [205] / :13 [214] — those three `continue`s are DEAD CODE. The
        # line-182 gate requires effective_status == "supported", which
        # requires missing_mandatory_fields == [], which requires data,
        # regime and length_bucket all to BE Mappings (_lookup returns
        # _MISSING through any non-Mapping intermediate). Any record
        # reaching lines 185/205/214 therefore already passed the
        # isinstance checks, so the `continue`s never execute and
        # `continue` -> `break` is unobservable. EQUIVALENT. The pairs
        # stay as rows: they exercise the effective_status cap path.
        ("fail-split-then-good", [_mo_record(split_role="fit", domain=("news",)), good], {}),
        (
            "fail-contamination-then-good",
            [_mo_record(contamination="yes", domain=("news",)), good],
            {},
        ),
        ("fail-signature-then-good", [_mo_set(good, "data.n_human", 121, resign=False), good], {}),
        ("fail-regime-notmapping-then-good", [_mo_set(good, "regime", ["x"]), good], {}),
        (
            "fail-bucket-then-good",
            [_mo_set(good, "regime.length_bucket", ["x"]), good],
            {"word_count": 80},
        ),
        (
            "fail-bucket-floor-then-good",
            [_mo_set(good, "regime.length_bucket.floor_words", 100), good],
            {"word_count": 99},
        ),
        # to_dict() returning a non-Mapping: the [176] guard `continue`s;
        # the `break` mutant stops before the good record.
        ("fail-payload-notmapping-then-good", [_mo_to_dict_record(["x"]), good], {}),
        # Empty-string domain: the final `language is not None and domain`
        # guard skips it; the `or` mutant (AndWithOr:3 [230,36]) adds
        # ("en", ""). (The "domain-empty" row has no domains at all, so
        # the loop never runs there.)
        ("domain-empty-string", [_mo_set(good, "regime.domain", [""])], {}),
        ("two-good", [good, _mo_record(domain=("science",))], {}),
        # version orderings (NotEq_Lt/Gt) + identical-object version (NotEq_Is)
        ("version-less", [_mo_record(detector_version="0.0.1", domain=("news", "essays"))], {}),
        ("version-greater", [_mo_record(detector_version="9.9.9", domain=("news", "essays"))], {}),
        # `!=` -> `is` (NotEq_Is:1 [179,43]): distinct-but-equal does NOT
        # distinguish (`!=` False and `is` False agree); only the IDENTICAL
        # object differs (`!=` False, `is` True). The expected version
        # object is BuiltinHeuristicDetector.detector_version (the probe
        # passes detector_version=None, so `version` IS that object).
        # The old "version-dynamic" row used a distinct-equal join and was
        # invisible on the disk driver; this row kills NotEq_Is:1.
        ("version-same-object", [_mo_set(good, "detector_version", _MO_VERSION)], {}),
        # effective_status "unknown" (< "supported": NotEq_Lt:2)
        ("status-unknown", [_mo_record(status="unknown", domain=("news", "essays"))], {}),
        ("status-contested", [_mo_record(status="contested", domain=("news", "essays"))], {}),
        # language/domain combos (AndWithOr:3)
        ("language-set-domain-empty", [_mo_set(good, "regime.domain", [])], {}),
        (
            "language-none-domain-empty",
            [_mo_set(_mo_set(good, "regime.language", None), "regime.domain", [])],
            {},
        ),
        ("domain-missing", [_mo_set(good, "regime.domain", None)], {}),
        # non-Mapping record (first `continue`): break would stop before good
        ("nonmapping-then-good", ["not a record", good], {}),
        ("nonmapping-only", ["not a record"], {}),
    ]
    for name, records, kwargs in cases:
        # sorted list: set repr order varies across processes (hash seed)
        try:
            rows.append(
                (name, ("ok", sorted(segment_covered_regimes(_mo_registry(*records), **kwargs))))
            )
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
        r["failures"] = [
            {k: v for k, v in f.items() if k != "runtime_ms"} for f in row.get("failures") or []
        ]
        r["_failure_has_runtime_ms"] = [("runtime_ms" in f) for f in row.get("failures") or []]
        robustness.append(r)
    return {
        "schema": d.get("schema"),
        "content_sha256": d.get("content_sha256"),
        "detector_results": results,
        "detector_failures": failures,
        "robustness": robustness,
        "trust_overall": tm.get("overall"),
        "trust_dims": [(x.get("dimension"), x.get("state")) for x in tm.get("dimensions") or []],
        "trust_dim_limitations": [
            (x.get("dimension"), x.get("limitations")) for x in tm.get("dimensions") or []
        ],
        "trust_coverage": tm.get("coverage"),
        "limitations": d.get("limitations"),
        "skipped": (d.get("provenance") or {}).get("skipped_detectors"),
        "legacy": d.get("legacy"),
        "evidence_registry": d.get("evidence_registry"),
    }


def _records_registry():
    import test_audit_w2_worker_a as A

    reg = _MockRegistry(True, [])
    reg._records_for = [A._v2_record()]
    reg.records = reg._records_for
    return reg


def _builtin_records_registry():
    """Registry with a record FOR the builtin heuristic detector, so
    artifact_verification + disjointness can make it eligible (CORE-01).
    verify_artifacts returns a real RegistryVerification with an ok row."""
    import test_audit_w2_worker_a as A

    reg = _VerifiedMockRegistry(True, [])
    rec = A._v2_record(
        detector_id="textforensics/builtin-heuristic",
        detector_version="0.1.0",
        benchmark_fingerprint="b" * 64,
    )
    reg._records_for = [rec]
    reg.records = reg._records_for
    return reg


class _VerifiedMockRegistry(_MockRegistry):
    """Mock registry whose verify_artifacts returns a real
    RegistryVerification with an ok row for the builtin record."""

    def verify_artifacts(self, root="."):
        from textforensics.evidence import RegistryVerification

        self.roots.append(root)
        return RegistryVerification(
            verified=self.verified,
            errors=tuple(self.errors),
            records={"ev-textforensics/builtin-heuristic-0.1.0-test": {"ok": True}},
            checked_at_utc="2026-01-01T00:00:00+00:00",
        )


def probe_report_bundle():
    from types import SimpleNamespace

    from textforensics.benchmark import DisjointnessProof
    from textforensics.detectors import BuiltinHeuristicDetector
    from textforensics.report import build_forensic_bundle

    text = (
        "The city council approved the new budget on Tuesday. "
        "Local residents welcomed the decision with cautious optimism. " * 8
    )
    det = [BuiltinHeuristicDetector()]
    proof = DisjointnessProof(
        status="verified",
        overlap_count=0,
        training_count=10,
        evaluation_count=10,
        training_hash="a" * 64,
        evaluation_hash="b" * 64,
        group_overlap_count=0,
    )

    def failing_detector():
        d = SimpleNamespace(
            detector_id="fake/failing",
            detector_version="1",
            detector_family="fake",
            execution="local",
        )

        def detect(t):
            raise RuntimeError("boom")

        d.detect = detect
        return d

    def remote_detector():
        d = SimpleNamespace(
            detector_id="fake/remote",
            detector_version="1",
            detector_family="fake",
            execution="remote",
        )
        d.detect = lambda t: None
        return d

    def curly_quote_detector():
        # Succeeds on text containing a curly quote (delegates to the
        # builtin detector) and raises on anything else. The benign
        # variant with normalized punctuation replaces the curly quote
        # with a straight quote, so exactly that variant fails: a
        # robustness failure WITH a runtime_ms, which the deterministic
        # strip at [487,19]/[489,66] removes. Kills ZeroIterationForLoop:3
        # [487,19] (the strip loop) and NotEq_Eq:2 / NotEq_LtE:2 /
        # NotEq_Gt:2 / NotEq_GtE:2 [489,66] (the strip condition).
        builtin = BuiltinHeuristicDetector()
        d = SimpleNamespace(
            detector_id="fake/curly",
            detector_version="1",
            detector_family="fake",
            execution="local",
        )

        def detect(t):
            if "\u201c" not in t:
                raise RuntimeError("no curly quote")
            # Re-wrap the builtin prediction with THIS detector's identity:
            # validate_prediction (detectors.py) rejects a prediction whose
            # id/version/family do not match the adapter, so delegating the
            # builtin prediction verbatim fails the main detection with
            # DetectorContractError (robustness stays [] and the strip
            # mutants are invisible — the disk driver caught this).
            import dataclasses

            return dataclasses.replace(
                builtin.detect(t),
                detector_id="fake/curly",
                detector_version="1",
                detector_family="fake",
            )

        d.detect = detect
        return d

    text_curly = text + " The mayor said \u201cwe will proceed with caution.\u201d"

    rows = []
    cases = [
        ("default", {}, None),
        ("deterministic", {"deterministic": True}, None),
        (
            "deterministic-fixed-ts",
            {"deterministic": True, "fixed_timestamp": "2026-01-01T00:00:00+00:00"},
            None,
        ),
        ("legacy", {"include_legacy": True}, None),
        ("text-int", {"text": 123}, None),
        ("text-empty", {"text": ""}, None),
        ("text-spaces", {"text": "   "}, None),
        ("both-registry", {"registry": _MockRegistry(), "registry_path": "x.json"}, None),
        ("verify-no-registry", {"verify_evidence": True}, None),
        ("verify-ok", {"verify_evidence": True, "registry": _MockRegistry(True, [])}, "roots"),
        (
            "verify-fail-1",
            {"verify_evidence": True, "registry": _MockRegistry(False, ["bad artifact"])},
            "roots",
        ),
        (
            "verify-fail-6",
            {
                "verify_evidence": True,
                "registry": _MockRegistry(False, [f"err{i}" for i in range(6)]),
            },
            "roots",
        ),
        (
            "verify-root",
            {
                "verify_evidence": True,
                "registry": _MockRegistry(True, []),
                "evidence_root": "/tmp/ev",
            },
            "roots",
        ),
        ("disjointness", {"disjointness": proof}, None),
        ("failing-detector", {"detectors": det + [failing_detector()]}, None),
        ("failing-det-det", {"detectors": det + [failing_detector()], "deterministic": True}, None),
        (
            "robustness-failure-det",
            {"detectors": [curly_quote_detector()], "deterministic": True, "text": text_curly},
            None,
        ),
        ("skipped-remote", {"detectors": det + [remote_detector()]}, None),
        ("no-detectors", {"detectors": []}, None),
        ("registry-records", {"registry": _records_registry()}, None),
        (
            "registry-records-disjointness",
            {"registry": _records_registry(), "disjointness": proof},
            None,
        ),
        # artifact_verification is a LOCAL set from registry.verify_artifacts()
        # (verify_evidence=True); it is NOT a build_forensic_bundle kwarg.
        # The eligible case needs the builtin record + binding proof + a
        # verified RegistryVerification; without verification the record is
        # ineligible and the trust dims stay partial/unknown.
        (
            "artifact-eligible",
            {
                "verify_evidence": True,
                "registry": _builtin_records_registry(),
                "disjointness": proof,
            },
            "roots",
        ),
        (
            "artifact-eligible-noverify",
            {"registry": _builtin_records_registry(), "disjointness": proof},
            None,
        ),
        (
            "artifact-empty",
            {"verify_evidence": True, "registry": _VerifiedMockRegistry(True, [])},
            "roots",
        ),
    ]
    for name, kwargs, extra in cases:
        text_arg = kwargs.pop("text", text)
        try:
            bundle = build_forensic_bundle(text_arg, **kwargs)
            rows.append(
                (
                    name,
                    (
                        "ok",
                        _report_summary(bundle),
                        kwargs.get("registry").roots if extra == "roots" else None,
                    ),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    return rows


# ---------------------------------------------------------------------------
# probe_metrics supplementary functions (new probe, W2-F kill tests)
# ---------------------------------------------------------------------------
def probe_pm_extra():
    from textforensics.probe_metrics import (
        coverage_shortfall_pp,
        holm_adjusted,
        psi,
        reject_nonfinite_value,
        require_finite_number,
        require_integer,
        set_coverage,
        wilson_ci,
    )

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
        (
            "psi-cut-edge",
            lambda: psi([0.0, 0.25, 0.5, 0.75, 1.0], [0.25, 0.25, 0.5, 0.75, 1.0], bins=4),
        ),
        # psi with default bins: this spread distribution gives distinct
        # values for bins 9/10/11 (1.061635 / 1.647748 / 0.840492)
        (
            "psi-spread",
            lambda: psi(
                [
                    0.037,
                    0.058,
                    0.07,
                    0.072,
                    0.091,
                    0.124,
                    0.151,
                    0.223,
                    0.324,
                    0.366,
                    0.397,
                    0.425,
                    0.434,
                    0.507,
                    0.536,
                    0.577,
                    0.627,
                    0.651,
                    0.827,
                    0.948,
                ],
                [
                    0.047,
                    0.06,
                    0.063,
                    0.118,
                    0.144,
                    0.181,
                    0.206,
                    0.29,
                    0.308,
                    0.314,
                    0.372,
                    0.428,
                    0.548,
                    0.582,
                    0.586,
                    0.639,
                    0.68,
                    0.816,
                    0.858,
                    0.976,
                ],
            ),
        ),
        (
            "psi-spread2",
            lambda: psi(
                [0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95], [0.5] * 10, bins=5
            ),
        ),
        ("psi-n1", lambda: psi([0.1], [0.9], bins=2)),
        ("psi-n2", lambda: psi([0.1, 0.9], [0.2, 0.8], bins=3)),
        ("wilson-0-10", lambda: wilson_ci(0, 10)),
        ("wilson-k-neg", lambda: wilson_ci(-1, 10)),
        ("wilson-10-10", lambda: wilson_ci(10, 10)),
        ("wilson-5-10", lambda: wilson_ci(5, 10)),
        ("wilson-1-100", lambda: wilson_ci(1, 100)),
        ("wilson-0-1", lambda: wilson_ci(0, 1)),
        ("wilson-k-gt-n", lambda: wilson_ci(11, 10)),
        ("wilson-n-0", lambda: wilson_ci(0, 0)),
        ("wilson-z-0", lambda: wilson_ci(1, 10, z=0.0)),
        ("wilson-z-neg", lambda: wilson_ci(1, 10, z=-1.0)),
        ("wilson-z-2", lambda: wilson_ci(5, 10, z=2.0)),
        # z in (0, 1]: kills NumberReplacer:8 [235,12] (`z <= 0` -> `z <= 1`).
        ("wilson-z-05", lambda: wilson_ci(5, 10, z=0.5)),
        # centre+half exceeds 1.0 by 1 ulp, so the min(1.0) clamp binds:
        # kills NumberReplacer:20 [241,41] (the min's 1.0 -> 2.0).
        ("wilson-3-3-z05", lambda: wilson_ci(3, 3, z=0.5)),
        ("shortfall-0", lambda: coverage_shortfall_pp(0.9, 0.9)),
        ("shortfall-5pp", lambda: coverage_shortfall_pp(0.85, 0.9)),
        ("shortfall-neg", lambda: coverage_shortfall_pp(0.95, 0.9)),
        ("shortfall-100", lambda: coverage_shortfall_pp(0.0, 1.0)),
        ("shortfall-emp-over", lambda: coverage_shortfall_pp(1.1, 0.9)),
        ("shortfall-nom-under", lambda: coverage_shortfall_pp(0.9, -0.1)),
        ("shortfall-nan", lambda: coverage_shortfall_pp(float("nan"), 0.9)),
        # shortfall boundary rows: (-0.5, 0.9) kills NumberReplacer:133
        # [474,11]; (1.0, 0.9) kills LtE_Lt:10 [474,33]; (0.9, 0.0) kills
        # LtE_Lt:11 [476,15]; (0.9, 1.5) kills NumberReplacer:138 [476,34].
        ("shortfall-neg-emp", lambda: coverage_shortfall_pp(-0.5, 0.9)),
        ("shortfall-emp-1", lambda: coverage_shortfall_pp(1.0, 0.9)),
        ("shortfall-nom-0", lambda: coverage_shortfall_pp(0.9, 0.0)),
        ("shortfall-nom-over", lambda: coverage_shortfall_pp(0.9, 1.5)),
        ("holm-single", lambda: holm_adjusted([0.03])),
        # Negative p-value: kills NumberReplacer:169 [639,15].
        ("holm-neg", lambda: holm_adjusted([-0.5, 0.5])),
        ("holm-sorted", lambda: holm_adjusted([0.01, 0.02, 0.03, 0.04])),
        ("holm-unsorted", lambda: holm_adjusted([0.04, 0.01, 0.03, 0.02])),
        ("holm-cap", lambda: holm_adjusted([0.5, 0.6, 0.7])),
        ("holm-running-max", lambda: holm_adjusted([0.01, 0.9, 0.02])),
        ("holm-small", lambda: holm_adjusted([0.001, 0.002])),
        ("holm-zero", lambda: holm_adjusted([0.0, 0.5])),
        ("holm-empty", lambda: holm_adjusted([])),
        ("holm-over-1", lambda: holm_adjusted([1.5])),
        ("holm-5-2", lambda: holm_adjusted([0.01, 0.02, 0.03, 0.04, 0.05])),
        ("setcov-all", lambda: set_coverage([{0}, {1}, {0, 1}], [0, 1, 1])),
        ("setcov-none", lambda: set_coverage([{1}, {0}], [0, 1])),
        ("setcov-half", lambda: set_coverage([{0}, {0}], [0, 1])),
        ("setcov-mismatch", lambda: set_coverage([{0}], [0, 1])),
        ("setcov-longer", lambda: set_coverage([{0}, {1}], [0])),
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
    import copy

    from textforensics._standalone_verify import _trust_map_check_errors
    from textforensics.trust import TRUST_DIMENSIONS

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
        (
            "v4-schema",
            _schema_map("v3", **{"schema": "textforensics.trust-map/v4"}),
            "textforensics.forensic-bundle/v2",
        ),
        ("v1-map", _schema_map("v1"), "textforensics.forensic-bundle/v1"),
        (
            "overall-mismatch",
            _schema_map("v3", **{"overall": "mixed"}),
            "textforensics.forensic-bundle/v2",
        ),
        (
            "overall-distinct",
            _schema_map("v3", **{"overall": "".join(["s", "t", "r", "o", "n", "g"])}),
            "textforensics.forensic-bundle/v2",
        ),
        (
            "overall-partial",
            _schema_map("v3", **{"overall": "partial"}),
            "textforensics.forensic-bundle/v2",
        ),
        (
            "missing-dim",
            _schema_map(
                "v3",
                dims=[{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
            "textforensics.forensic-bundle/v2",
        ),
        (
            "unknown-dim",
            _schema_map(
                "v3",
                dims=[{"dimension": "nope", "state": "supported", "reason": "ok"}]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
            "textforensics.forensic-bundle/v2",
        ),
        (
            "dup2",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "supported", "reason": "ok"}] * 2
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
            "textforensics.forensic-bundle/v2",
        ),
        (
            "dup3",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "supported", "reason": "ok"}] * 3
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
            "textforensics.forensic-bundle/v2",
        ),
        (
            "two-bad-dims",
            _schema_map(
                "v3",
                dims=[
                    {"dimension": dims[0], "state": "bogus", "reason": "ok"},
                    {"dimension": dims[1], "state": "bogus", "reason": "ok"},
                ]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[2:]],
            ),
            "textforensics.forensic-bundle/v2",
        ),
        (
            "reason-123",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "supported", "reason": 123}]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
            "textforensics.forensic-bundle/v2",
        ),
        (
            "reason-empty",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "supported", "reason": ""}]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
            "textforensics.forensic-bundle/v2",
        ),
        (
            "name-non-str",
            _schema_map(
                "v3",
                dims=[{"dimension": 123, "state": "supported", "reason": "ok"}]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
            "textforensics.forensic-bundle/v2",
        ),
        (
            "name-empty",
            _schema_map(
                "v3",
                dims=[{"dimension": "", "state": "supported", "reason": "ok"}]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
            "textforensics.forensic-bundle/v2",
        ),
        (
            "generated-none",
            _schema_map("v3", generated_at_utc=None),
            "textforensics.forensic-bundle/v2",
        ),
        ("coverage-bool", _schema_cov(base, supported=True), "textforensics.forensic-bundle/v2"),
        ("coverage-neg", _schema_cov(base, supported=-1), "textforensics.forensic-bundle/v2"),
        (
            "coverage-mismatch",
            _schema_cov(base, supported=len(dims) - 1, partial=1),
            "textforensics.forensic-bundle/v2",
        ),
        (
            "coverage-mismatch-up",
            _schema_cov(base, supported=len(dims) + 1),
            "textforensics.forensic-bundle/v2",
        ),
        ("pair-bad", base, "textforensics.forensic-bundle/v9"),
        ("empty-dims", _schema_map("v3", dims=[]), "textforensics.forensic-bundle/v2"),
        ("dims-not-list", _schema_map("v3", dims={"a": 1}), "textforensics.forensic-bundle/v2"),
        (
            "partial-unknown-mix",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "partial", "reason": "ok"}]
                + [{"dimension": d, "state": "unknown", "reason": "ok"} for d in dims[1:]],
                **{
                    "overall": "mixed",
                    "coverage": {
                        "supported": 0,
                        "partial": 1,
                        "unknown": 9,
                        "out_of_scope": 0,
                        "stale": 0,
                    },
                },
            ),
            "textforensics.forensic-bundle/v2",
        ),
    ]
    # _trust_map_check_errors extras (Batch 6b): continue-vs-break,
    # coverage key sets, generated_at_utc shapes, >256 counts
    _cov_missing = _schema_map("v3")
    _cov_missing["coverage"] = {k: v for k, v in _cov_missing["coverage"].items() if k != "stale"}
    cases.append(("coverage-missing-key", _cov_missing, "textforensics.forensic-bundle/v2"))
    cases.append(("coverage-extra", _schema_cov(base, bogus=1), "textforensics.forensic-bundle/v2"))
    cases.append(
        (
            "coverage-300",
            _schema_map(
                "v3",
                dims=[{"dimension": dims[0], "state": "supported", "reason": "ok"}] * 300,
                coverage={
                    "supported": 300,
                    "partial": 0,
                    "unknown": 0,
                    "out_of_scope": 0,
                    "stale": 0,
                },
            ),
            "textforensics.forensic-bundle/v2",
        )
    )
    cases.append(
        (
            "dim-nondict-then-bad",
            _schema_map(
                "v3",
                dims=[123, {"dimension": dims[0], "state": "bogus", "reason": "ok"}]
                + [{"dimension": d, "state": "supported", "reason": "ok"} for d in dims[1:]],
            ),
            "textforensics.forensic-bundle/v2",
        )
    )
    cases.append(
        (
            "generated-int",
            _schema_map("v3", generated_at_utc=123),
            "textforensics.forensic-bundle/v2",
        )
    )
    cases.append(
        (
            "generated-empty",
            _schema_map("v3", generated_at_utc=""),
            "textforensics.forensic-bundle/v2",
        )
    )
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
    import json
    import tempfile
    from pathlib import Path

    from textforensics.calibration import run_calibration_evaluation

    rows = []

    def write(path, texts):
        rows = [{"label": "human", "text": t} for t in texts[:4]] + [
            {"label": "ai", "text": t} for t in texts[4:]
        ]
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        cal = tmp / "cal.jsonl"
        ev = tmp / "ev.jsonl"
        same = tmp / "same.jsonl"
        bad = tmp / "bad.jsonl"
        write(
            cal,
            [f"cal human sentence {i}." for i in range(4)]
            + [f"cal ai sentence {i}." for i in range(4)],
        )
        write(
            ev,
            [f"ev human sentence {i}." for i in range(4)]
            + [f"ev ai sentence {i}." for i in range(4)],
        )
        write(same, [f"same human sentence {i}." for i in range(4)])
        bad.write_text(
            '{"label": "human", "text": "ok."}\nNOT JSON\n{"label": "ai", "text": "ok2."}\n',
            encoding="utf-8",
        )
        # Empty eval file: validation valid=False, contamination_detected
        # False -> the `elif not valid and not diagnostic` branch at 2138.
        # The diagnostic=False row kills Delete_Not:63 [2138,37], both Add_*
        # families [2142,12] + [2143,12] x11 each (all raise TypeError on
        # strings), and OrWithAnd:33 [2142,37].
        empty = tmp / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
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
            ("unknown", cal, empty, {}),
            ("unknown-diag", cal, empty, {"diagnostic": True}),
        ]:
            try:
                out = run_calibration_evaluation(c, e, **kwargs)
                er = out["evaluation_result"]
                rows.append(
                    (
                        name,
                        (
                            "ok",
                            er.get("evaluation_mode"),
                            er.get("contamination_detected"),
                            er.get("overlap_count"),
                            out["validation"].get("valid"),
                            out["validation"].get("contamination_detected"),
                        ),
                    )
                )
            except Exception as exc:  # noqa: BLE001
                rows.append(
                    (name, ("raise", type(exc).__name__, str(exc).replace(str(tmp), "TMP")))
                )
    return rows


# ---------------------------------------------------------------------------
# calibration.store / getters (new probe, W2-F kill tests)
# ---------------------------------------------------------------------------
def _cal_identity(**over):
    import test_calibration as T

    from textforensics.calibration import InferenceIdentity

    kw = dict(
        detector_id="det1",
        detector_version="1.0",
        provider="local",
        model="builtin-heuristic-0.1.0",
        config_hash=T.hex64(5),
        native_score_semantics="probability_higher_means_ai",
        regime="unedited",
        calibration_id="cal1",
    )
    kw.update(over)
    return InferenceIdentity(**kw)


def probe_cal_store():
    import tempfile

    import test_calibration as T

    from textforensics.calibration import CalibrationManager

    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        mgr = CalibrationManager(tmp)
        ident = _cal_identity()
        # valid store with identity
        try:
            art = mgr.store(
                detector_id="det1",
                detector_version="1.0",
                curve=T.platt_curve(),
                calibration_id="cal1",
                created_at="2024-01-01T00:00:00+00:00",
                identity=ident,
                **T.eligible_artifact_kwargs(),
            )
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
                mgr.store(
                    detector_id="det1",
                    detector_version="1.0",
                    curve=T.platt_curve(),
                    calibration_id="cal1",
                    created_at="2024-01-01T00:00:00+00:00",
                    identity=_cal_identity(**over),
                    **T.eligible_artifact_kwargs(),
                )
                rows.append((f"store-{name}", ("ok", "stored")))
            except Exception as exc:  # noqa: BLE001
                rows.append((f"store-{name}", ("raise", type(exc).__name__, str(exc))))
        # Distinct-but-equal identity fields: `!=` is False, `is not` is
        # True. The mismatch rows above use different VALUES ("aaa"/"zzz"),
        # where both agree. Kill NotEq_IsNot:9 [1229,36] (detector_id),
        # NotEq_IsNot:10 [1231,41] (detector_version) and NotEq_IsNot:11
        # [1233,70] (calibration_id). Each join builds a genuinely distinct
        # equal string (multi-element joins; a single-element join would
        # return the literal itself).
        for name, over in [
            ("id-distinct", {"detector_id": "".join(["d", "e", "t", "1"])}),
            ("ver-distinct", {"detector_version": "".join(["1", ".0"])}),
            ("cal-distinct", {"calibration_id": "".join(["c", "a", "l", "1"])}),
        ]:
            try:
                mgr.store(
                    detector_id="det1",
                    detector_version="1.0",
                    curve=T.platt_curve(),
                    calibration_id="cal1",
                    created_at="2024-01-01T00:00:00+00:00",
                    identity=_cal_identity(**over),
                    **T.eligible_artifact_kwargs(),
                )
                rows.append((f"store-{name}", ("ok", "stored")))
            except Exception as exc:  # noqa: BLE001
                rows.append((f"store-{name}", ("raise", type(exc).__name__, str(exc))))
        # calibration_id None vs set (identity carries cal1)
        try:
            art = mgr.store(
                detector_id="det1",
                detector_version="1.0",
                curve=T.platt_curve(),
                created_at="2024-01-01T00:00:00+00:00",
                identity=ident,
                **T.eligible_artifact_kwargs(),
            )
            rows.append(("store-cal-none", ("ok", art.calibration_id)))
        except Exception as exc:  # noqa: BLE001
            rows.append(("store-cal-none", ("raise", type(exc).__name__, str(exc))))
        # explicit identity-field mismatches (provider/model/config/semantics/regime)
        for name, field, value in [
            ("prov-aaa", "provider", "aaa"),
            ("prov-zzz", "provider", "zzz"),
            ("model-aaa", "model", "aaa"),
            ("model-zzz", "model", "zzz"),
            ("semantics-aaa", "native_score_semantics", "aaa"),
            ("semantics-zzz", "native_score_semantics", "zzz"),
            ("regime-aaa", "regime", "aaa"),
            ("regime-zzz", "regime", "zzz"),
        ]:
            try:
                mgr.store(
                    detector_id="det1",
                    detector_version="1.0",
                    curve=T.platt_curve(),
                    calibration_id="cal1",
                    created_at="2024-01-01T00:00:00+00:00",
                    identity=ident,
                    **{**T.eligible_artifact_kwargs(), field: value},
                )
                rows.append((f"store-{name}", ("ok", "stored")))
            except Exception as exc:  # noqa: BLE001
                rows.append((f"store-{name}", ("raise", type(exc).__name__, str(exc))))
        # getters on the stored artifact
        for name, fn in [
            ("score-match", lambda: mgr.get_calibrated_score("det1", 0.7, identity=ident)),
            ("score-id-zzz", lambda: mgr.get_calibrated_score("zzz", 0.7, identity=ident)),
            ("score-id-aaa", lambda: mgr.get_calibrated_score("aaa", 0.7, identity=ident)),
            (
                "score-id-distinct",
                lambda: mgr.get_calibrated_score(
                    "".join(["d", "e", "t", "1"]), 0.7, identity=ident
                ),
            ),
            ("score-no-identity", lambda: mgr.get_calibrated_score("det1", 0.7)),
            ("result-match", lambda: mgr.get_calibrated_result("det1", 0.7, identity=ident)),
            ("result-id-zzz", lambda: mgr.get_calibrated_result("zzz", 0.7, identity=ident)),
            # result-id-distinct: the detector_id arg is a DISTINCT object
            # equal to the identity's "det1". `!=` is False, `is not` is
            # True. Kills NotEq_IsNot:15 [1469,32] (get_calibrated_result).
            # (The existing "score-id-distinct" row exercises the same
            # check in get_calibrated_score [1442,42], a different
            # occurrence, so it cannot kill :15.)
            (
                "result-id-distinct",
                lambda: mgr.get_calibrated_result(
                    "".join(["d", "e", "t", "1"]), 0.7, identity=ident
                ),
            ),
            # result-id-aaa: the identity's "det1" sorts AFTER "aaa".
            # `!=` is True (raises); `<` is False (proceeds). Kills
            # NotEq_Lt:19 [1469,32]. (The "result-id-zzz" row agrees under
            # both: "det1" < "zzz" is True, so the mutant raises too.)
            ("result-id-aaa", lambda: mgr.get_calibrated_result("aaa", 0.7, identity=ident)),
            (
                "result-unvalidated",
                lambda: mgr.get_calibrated_score(
                    "det1", 0.7, identity=ident, allow_unvalidated=True
                ),
            ),
            ("score-for-identity", lambda: mgr.get_calibrated_score_for_identity(ident, 0.7)),
            (
                "score-for-identity-zzz",
                lambda: mgr.get_calibrated_score_for_identity(
                    _cal_identity(detector_id="zzz"), 0.7
                ),
            ),
            ("result-for-identity", lambda: mgr.get_calibrated_result_for_identity(ident, 0.7)),
        ]:
            rows.append((name, outcome(fn)))
        # Ineligible artifact: stored WITHOUT any eligibility provenance
        # (no fit/evaluation datasets, disjointness, metrics, code version
        # or run hash), so validation_issues() is non-empty and
        # eligible_for_probability is False. get_calibrated_score_for_identity
        # without the flag raises (original); with the allow_unvalidated
        # DEFAULT flipped to True the mutant returns the score. Kills
        # ReplaceFalseWithTrue:7 [1384,34] (the default, not the call site:
        # the existing "result-unvalidated" row passes the flag explicitly).
        # A distinct identity (det2/cal2) keeps the eligible det1 artifact
        # intact for the getter rows above.
        ident2 = _cal_identity(detector_id="det2", calibration_id="cal2")
        try:
            art2 = mgr.store(
                detector_id="det2",
                detector_version="1.0",
                curve=T.platt_curve(),
                calibration_id="cal2",
                created_at="2024-01-01T00:00:00+00:00",
                identity=ident2,
            )
            rows.append(
                ("store-ineligible", ("ok", art2.calibration_id, art2.eligible_for_probability))
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(("store-ineligible", ("raise", type(exc).__name__, str(exc))))
        rows.append(
            (
                "score-for-identity-ineligible",
                outcome(lambda: mgr.get_calibrated_score_for_identity(ident2, 0.7)),
            )
        )
        rows.append(
            (
                "score-for-identity-ineligible-allow",
                outcome(
                    lambda: mgr.get_calibrated_score_for_identity(
                        ident2, 0.7, allow_unvalidated=True
                    )
                ),
            )
        )
    return rows


# ---------------------------------------------------------------------------
# calibration InferenceIdentity / content hash / EvaluationResult (new probe)
# ---------------------------------------------------------------------------
def probe_cal_identity():
    import dataclasses

    import test_calibration as T

    from textforensics.calibration import EvaluationResult, InferenceIdentity

    rows = []
    # from_dict as a classmethod (called on the class, not an instance)
    rows.append(
        (
            "from-dict-class",
            outcome(
                InferenceIdentity.from_dict,
                {
                    "detector_id": "det1",
                    "detector_version": "1.0",
                    "provider": "local",
                    "model": "m",
                    "config_hash": T.hex64(5),
                    "native_score_semantics": "probability_higher_means_ai",
                    "regime": "unedited",
                    "calibration_id": "cal1",
                },
            ),
        )
    )
    rows.append(("from-dict-nonmapping", outcome(InferenceIdentity.from_dict, ["x"])))
    ident = _cal_identity()

    # frozen: assignment must raise
    def _assign():
        ident.provider = "other"
        return ident.provider

    rows.append(("frozen-assign", outcome(_assign)))
    rows.append(("slots-no-dict", outcome(lambda: hasattr(ident, "__dict__"))))
    # EvaluationResult default overlap_count
    rows.append(
        (
            "evalresult-default",
            outcome(
                lambda: (
                    EvaluationResult(
                        threshold=0.5,
                        tp=4,
                        fp=0,
                        tn=4,
                        fn=0,
                        accuracy=1.0,
                        fpr=0.0,
                        fnr=0.0,
                        tpr=1.0,
                        specificity=1.0,
                        precision=1.0,
                        evaluated=8,
                        test_dataset_hash="a" * 64,
                        calibration_dataset_hash="b" * 64,
                    ).overlap_count
                )
            ),
        )
    )
    # content hash: valid, then tampered stored hash (either side + distinct object)
    art = T.eligible_artifact()
    rows.append(("hash-valid", outcome(art.check_content_hash)))
    computed = art.compute_content_hash()
    rows.append(("hash-computed", ("ok", computed == art.content_hash)))
    for name, value in [
        ("stored-less", "0" * 64),
        ("stored-greater", "f" * 64),
        ("stored-distinct", "".join(computed)),
    ]:
        tampered = dataclasses.replace(art)
        object.__setattr__(tampered, "content_hash", value)
        rows.append((f"hash-{name}", outcome(tampered.check_content_hash)))

    # Construction with a tampered stored hash: __post_init__ raises iff
    # stored != computed. "f"*64 is the maximum 64-hex string, so it is
    # greater than any computed digest: the original raises, the `<`
    # mutant (NotEq_Lt:10 [780,33]) does not. The hash-* rows above swap
    # the hash AFTER construction, so they never exercise __post_init__.
    def _construct_tampered():
        dataclasses.replace(art, content_hash="f" * 64)
        return "constructed"

    rows.append(("hash-construct-greater", outcome(_construct_tampered)))
    # _content_payload: all identity fields None vs some set
    art_no_ident = dataclasses.replace(art)
    for _f in ("provider", "model", "config_hash", "native_score_semantics", "regime"):
        object.__setattr__(art_no_ident, _f, None)
    rows.append(
        ("payload-all-none", outcome(lambda: sorted(art_no_ident._content_payload().keys())))
    )
    rows.append(("payload-some-set", outcome(lambda: sorted(art._content_payload().keys()))))
    rows.append(
        ("payload-missing-field", outcome(lambda: "provider" in art_no_ident._content_payload()))
    )
    # inference_identity(): exactly one identity field None. The original
    # `or` chain returns None; each OrWithAnd:12-15 mutant turns one `or`
    # into `and`, so with exactly one None the mutant falls through and
    # tries to construct an InferenceIdentity with a None field (raising),
    # except when the None field is on the True side of the surviving `or`s.
    # Five rows (one per field) kill all four mutants.
    for _f in ("provider", "model", "config_hash", "native_score_semantics", "regime"):
        _a = dataclasses.replace(art)
        object.__setattr__(_a, _f, None)
        rows.append((f"identity-only-{_f}-none", outcome(_a.inference_identity)))
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

    expl4 = _CE(
        lambda t: sum(
            0.5
            if w in ("ai", "machine", "robot")
            else -0.5
            if w in ("human", "person", "hand")
            else 0.0
            for w in t.split()
        ),
        detector_id="d",
        detector_version="1",
    )
    text4 = (
        ("ai machine robot " * 12).strip()
        + ". "
        + ("ai robot machine " * 12).strip()
        + ". "
        + ("human person hand " * 12).strip()
        + ". "
        + ("the quick brown fox jumps over the lazy dog " * 3).strip()
        + "."
    )
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
    # 2-human-segment report: kills NumberReplacer:9 [193,43]
    # (top_human_driving[0] -> [-1]). The 4-seg report has only 1
    # human-driving segment, so [0] == [-1] there; with 2 the first and
    # last differ (index + sha256).
    text2h = (
        ("human person hand " * 12).strip()
        + ". "
        + ("human hand person " * 12).strip()
        + ". "
        + ("ai machine robot " * 12).strip()
        + "."
    )
    rep2h = expl4.explain(text2h)
    for name, fn in [
        ("summary-2human", lambda: rep2h.summary()),
        ("summary-2human-raw", lambda: rep2h.summary(include_raw_text=True)),
        ("dict-2human", lambda: rep2h.to_dict()),
    ]:
        rows.append((name, outcome(lambda fn=fn: _scrub_report(fn()))))
    return rows


# ---------------------------------------------------------------------------
# benchmark._sample_and_group_hashes / check_disjointness (new probes)
# ---------------------------------------------------------------------------
def probe_bm_sample_hashes():
    import json
    import tempfile
    from pathlib import Path

    from textforensics.benchmark import _sample_and_group_hashes

    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        files = {
            "valid": [
                {"label": "human", "text": "Alpha sentence."},
                {"label": "ai", "text": "Beta sentence."},
                {"label": "human", "text": "Gamma sentence.", "source_document_id": "doc1"},
                {"label": "ai", "text": "Delta sentence.", "document_id": "doc1"},
                {"label": "human", "text": "Epsilon sentence.", "group_id": "g7"},
                {"label": "ai", "text": "Zeta sentence.", "source_id": "s9"},
            ],
            "nonascii": [
                {"label": "human", "text": "Café naïve façade."},
                {"label": "ai", "text": "Über résumé."},
            ],
            "nontext": [{"label": "human", "text": 123}, {"label": "ai", "text": ["a", "b"]}],
            "empty": [],
        }
        for name, data in files.items():
            p = tmp / f"{name}.jsonl"
            p.write_text("".join(json.dumps(r) + "\n" for r in data), encoding="utf-8")
            rows.append((name, outcome(_sample_and_group_hashes, p)))
        # malformed lines (strict True/False), non-dict rows, blank lines
        bad = tmp / "bad.jsonl"
        bad.write_text(
            '{"label": "human", "text": "Good one."}\nNOT JSON\n[1, 2]\n{"label": "ai", "text": "After bad."}\n\n',
            encoding="utf-8",
        )
        rows.append(("bad-strict", outcome(_sample_and_group_hashes, bad, strict=True)))
        rows.append(("bad-lenient", outcome(_sample_and_group_hashes, bad, strict=False)))
        missing = tmp / "nope.jsonl"
        try:
            _sample_and_group_hashes(missing)
            rows.append(("missing", ("ok", "no-raise")))
        except Exception as exc:  # noqa: BLE001
            rows.append(
                ("missing", ("raise", type(exc).__name__, str(exc).replace(str(tmp), "TMP")))
            )
        # group-id precedence: first non-empty group field wins
        prec = tmp / "prec.jsonl"
        prec.write_text(
            json.dumps(
                {"label": "human", "text": "T.", "source_document_id": " ", "document_id": "d2"}
            )
            + "\n",
            encoding="utf-8",
        )
        rows.append(("group-precedence", outcome(_sample_and_group_hashes, prec)))
        # same text, different case/whitespace -> same group hash
        norm = tmp / "norm.jsonl"
        norm.write_text(
            json.dumps({"label": "human", "text": "  Hello   WORLD. "})
            + "\n"
            + json.dumps({"label": "ai", "text": "hello world."})
            + "\n",
            encoding="utf-8",
        )
        rows.append(("group-normalized", outcome(_sample_and_group_hashes, norm)))
        # --- strict default (no strict arg) on a bad file ------------------
        rows.append(("bad-default-strict", outcome(_sample_and_group_hashes, bad)))
        # --- blank line in the middle (continue vs break) ------------------
        mid_blank = tmp / "midblank.jsonl"
        mid_blank.write_text(
            '{"label": "human", "text": "First."}\n\n{"label": "ai", "text": "Second."}\n',
            encoding="utf-8",
        )
        rows.append(("blank-middle", outcome(_sample_and_group_hashes, mid_blank)))
        # --- dict text (sort_keys) + non-ASCII dict text (ensure_ascii) ---
        dicttext = tmp / "dicttext.jsonl"
        dicttext.write_text(
            json.dumps({"label": "human", "text": {"b": 1, "a": 2}})
            + "\n"
            + json.dumps({"label": "ai", "text": {"k": "café", "a": "x"}})
            + "\n",
            encoding="utf-8",
        )
        rows.append(("dict-text", outcome(_sample_and_group_hashes, dicttext)))
        # --- two group fields set (break vs continue in the field loop) ---
        two_groups = tmp / "twogroups.jsonl"
        two_groups.write_text(
            json.dumps(
                {"label": "human", "text": "T1.", "source_document_id": "d1", "document_id": "d2"}
            )
            + "\n"
            + json.dumps({"label": "ai", "text": "T2.", "group_id": "g1", "source_id": "s1"})
            + "\n",
            encoding="utf-8",
        )
        rows.append(("two-group-fields", outcome(_sample_and_group_hashes, two_groups)))
    return rows


def probe_bm_check_disjointness():
    import tempfile
    from pathlib import Path

    import test_benchmark as TB

    from textforensics.benchmark import check_disjointness, fingerprint_dataset

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
                rows.append(
                    (
                        name,
                        (
                            "ok",
                            out["disjoint"],
                            out["shared_samples"],
                            sorted(out["shared_hashes"]),
                            out["verified"],
                            sorted(e.replace(str(tmp), "TMP") for e in out["errors"]),
                            sorted(w.replace(str(tmp), "TMP") for w in out["warnings"]),
                            out["proof"]["status"],
                            out["proof"]["overlap_count"],
                            out["proof"]["training_count"],
                            out["proof"]["evaluation_count"],
                            out["proof"]["group_overlap_count"],
                        ),
                    )
                )
            except Exception as exc:  # noqa: BLE001
                rows.append(
                    (name, ("raise", type(exc).__name__, str(exc).replace(str(tmp), "TMP")))
                )
    return rows


# ---------------------------------------------------------------------------
# observatory._normalize_observation / _validate_score_range /
# _validate_snapshot_schema / _observation_from_prediction (new probe)
# ---------------------------------------------------------------------------
def _obs_corpus():
    from textforensics.observatory import DriftObservatory

    corpus = {
        "schema": "textforensics.drift-corpus/v1",
        "samples": [
            {"id": "s1", "text": "synthetic probe sentence one."},
            {"id": "s2", "text": "synthetic probe sentence two."},
        ],
    }
    return DriftObservatory(corpus=corpus)


def _obs_valid(obs, **over):
    base = {
        "sample_id": "s1",
        "detector_id": "d",
        "detector_version": "0.1.0",
        "detector_family": "f",
        "execution": "local",
        "score": 0.1,
        "score_semantics": "lower means more machine-like",
        "verdict": "ai_like",
        "threshold": 0.2,
        "native_score_direction": "lower_means_ai",
        "score_range": [-5.0, 5.0],
        "observed_at": "2026-01-01T00:00:00+00:00",
    }
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
    from textforensics.observatory import DRIFT_SNAPSHOT_SCHEMA, _validate_score_range

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
        ("score-below-range", _obs_valid(obs, score_range=[0.2, 1.0])),
        ("score-eq-lo", _obs_valid(obs, score_range=[0.1, 1.0])),
        ("score-eq-hi", _obs_valid(obs, score_range=[-5.0, 0.1])),
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
        ("range-none", None),
        ("range-ok", [0.0, 1.0]),
        ("range-len1", [0.0]),
        ("range-len3", [0.0, 0.5, 1.0]),
        ("range-not-list", "x"),
        ("range-lo-none", [None, 1.0]),
        ("range-hi-none", [0.0, None]),
        ("range-eq", [1.0, 1.0]),
        ("range-eq-distinct", [float("1.0"), float("1.0")]),
        ("range-reversed", [1.0, 0.0]),
        ("range-bool", [True, 1.0]),
        ("range-str", ["0", "1"]),
        ("range-nan", [float("nan"), 1.0]),
    ]:
        rows.append((name, outcome(_validate_score_range, value)))
    # _validate_snapshot_schema
    for name, snap in [
        ("snap-valid", {"schema": DRIFT_SNAPSHOT_SCHEMA, "records": [], "failures": []}),
        (
            "snap-records",
            {
                "schema": DRIFT_SNAPSHOT_SCHEMA,
                "records": [
                    {"native_score_direction": "higher_means_ai", "score_range": [0.0, 1.0]}
                ],
                "failures": [],
            },
        ),
        (
            "snap-no-direction",
            {
                "schema": DRIFT_SNAPSHOT_SCHEMA,
                "records": [{"score_range": [0.0, 1.0]}],
                "failures": [],
            },
        ),
        (
            "snap-no-range",
            {
                "schema": DRIFT_SNAPSHOT_SCHEMA,
                "records": [{"native_score_direction": "lower_means_ai"}],
                "failures": [],
            },
        ),
        ("snap-bad-schema", {"schema": "textforensics.drift-snapshot/v9", "records": []}),
        ("snap-old-schema", {"schema": "textforensics.drift-snapshot/v1", "records": []}),
        ("snap-schema-a", {"schema": "a", "records": []}),
        ("snap-schema-v0", {"schema": "textforensics.drift-snapshot/v0", "records": []}),
        ("snap-records-not-list", {"schema": DRIFT_SNAPSHOT_SCHEMA, "records": "x"}),
        ("snap-record-not-obj", {"schema": DRIFT_SNAPSHOT_SCHEMA, "records": ["x"]}),
        (
            "snap-bad-direction",
            {"schema": DRIFT_SNAPSHOT_SCHEMA, "records": [{"native_score_direction": "sideways"}]},
        ),
        (
            "snap-bad-range",
            {"schema": DRIFT_SNAPSHOT_SCHEMA, "records": [{"score_range": [1.0, 0.0]}]},
        ),
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
        pred = DetectorPrediction(
            schema="textforensics.detector-result/v2",
            detector_id="d",
            detector_version="0.1.0",
            detector_family="f",
            execution="local",
            score=0.1,
            score_semantics="s",
            verdict="ai_like",
            threshold=0.2,
        )
        object.__setattr__(pred, "native_score_direction", direction)
        object.__setattr__(pred, "score_range", score_range)
        rows.append(
            (
                name,
                outcome(
                    lambda p=pred: _scrub_time(obs._observation_from_prediction(sample, det, p))
                ),
            )
        )
    return rows


# ---------------------------------------------------------------------------
# model_card from_dict helpers / to_json / to_markdown / load (new probe)
# ---------------------------------------------------------------------------
def _mc_full_card():
    import test_model_card as T

    return T.TestModelCardLoad()._full_card()


def probe_mc_from_dict():
    import copy
    import tempfile
    from pathlib import Path

    from textforensics.model_card import (
        ModelCard,
        _evaluation_dataset_from_dict,
        _mc_int,
        _mc_number,
        _mc_opt_number,
        _metric_from_dict,
        _quantitative_analysis_from_dict,
        _training_data_from_dict,
        load_model_card,
    )

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
        ("eval-sum-2.0", {"train": 1.0, "val": 1.0, "test": 0.0}),
        ("eval-sum-0.0", {"train": 0.0, "test": 0.0}),
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
    # _training_data_from_dict: optional lists ABSENT (required=False -> True raises)
    for name, pop in [
        ("train-missing-aug", ["augmentation_techniques"]),
        ("train-missing-biases", ["known_biases"]),
        ("train-missing-both", ["augmentation_techniques", "known_biases"]),
    ]:
        m = copy.deepcopy(train_d)
        for key in pop:
            m.pop(key, None)
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
    for name, ver in [
        ("fromdict-100", "1.0.0"),
        ("fromdict-090", "0.9.0"),
        ("fromdict-200", "2.0.0"),
        ("fromdict-missing", None),
    ]:
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
    card_nom = dataclasses.replace(
        card,
        metrics=[],
        ethical_considerations=[],
        caveats_and_recommendations=[],
        eu_ai_act_transparency_notes={},
    )
    rows.append(("md-stripped", outcome(card_nom.to_markdown)))
    card_noci = dataclasses.replace(
        card, metrics=[dataclasses.replace(card.metrics[0], confidence_interval=None)]
    )
    rows.append(("md-no-ci", outcome(card_noci.to_markdown)))
    # load: missing file (scrub the tmp path from the error message)
    with tempfile.TemporaryDirectory() as tmp:
        rows.append(
            ("load-missing", _scrub_path(outcome(load_model_card, Path(tmp) / "nope.json"), tmp))
        )
        p = Path(tmp) / "card.json"
        p.write_text(card.to_json(), encoding="utf-8")
        rows.append(("load-valid", outcome(lambda: load_model_card(p).model_details.name)))
        bad = Path(tmp) / "bad.json"
        bad.write_text("not json {", encoding="utf-8")
        rows.append(("load-badjson", _scrub_path(outcome(load_model_card, bad), tmp)))
        nan = Path(tmp) / "nan.json"
        nan.write_text('{"schema_version": "1.0.0", "x": NaN}', encoding="utf-8")
        rows.append(("load-nan", _scrub_path(outcome(load_model_card, nan), tmp)))
        rows.append(("load-dir", _scrub_path(outcome(load_model_card, Path(tmp)), tmp)))
    return rows


# ---------------------------------------------------------------------------
# evidence._verification_row_ok / _record_candidate / _worst_fpr_dimension /
# records_for / InferenceIdentity+DisjointnessProof / coverage_for_predictions
# (new probes)
# ---------------------------------------------------------------------------
def probe_ev_row_ok():
    from textforensics.evidence import RegistryVerification, _verification_row_ok

    ver = RegistryVerification(
        verified=True,
        errors=(),
        records={
            "ev1": {"ok": True},
            "ev2": {"ok": False, "errors": ["bad sha"]},
            "ev3": {"ok": False},
            "ev4": True,
            "ev5": False,
            "ev6": "not-a-row",
            "ev7": {"ok": True, "errors": ["ignored"]},
            # errors as a string, not a list:
            # `isinstance(errors, list) and errors`
            # is False, but `or` makes it truthy
            # and joins the characters. Kills
            # AndWithOr:18 [1036,63].
            "ev8": {"ok": False, "errors": "ab"},
        },
        checked_at_utc="2026-01-01T00:00:00+00:00",
    )
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
        ("ver-fail-errors-str", ver, "ev8"),
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
    from datetime import UTC, datetime

    from textforensics.evidence import SliceMatch, _record_candidate

    now = datetime(2026, 11, 11, tzinfo=UTC)
    rows = []
    match_all = SliceMatch(
        language="match", length="match", domain="match", editing="match", applicable=True
    )
    match_mix = SliceMatch(
        language="match", length="mismatch", domain="unknown", editing="match", applicable=True
    )
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
        kwargs = dict(
            record=record,
            slice_=slice_,
            match=match,
            now=now,
            max_age_days=30,
            dimension=dim,
            fpr_ceiling=0.05,
        )
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
    nomatch = SliceMatch(
        language="mismatch",
        length="mismatch",
        domain="mismatch",
        editing="mismatch",
        applicable=False,
    )
    try:
        cand = _record_candidate(
            record=record,
            slice_=slice_,
            match=nomatch,
            now=now,
            max_age_days=30,
            dimension="language",
            fpr_ceiling=0.05,
            eligible=False,
            ineligibility_reasons=("stale",),
        )
        rows.append(("none-ineligible", ("ok", None if cand is None else cand.state)))
    except Exception as exc:  # noqa: BLE001
        rows.append(("none-ineligible", ("raise", type(exc).__name__, str(exc))))

    # Unknown-state candidate + ineligible: the FPR dimension with domain
    # "unknown" (but language/length matching, so the candidate exists with
    # state "unknown"). Kills NotEq_Lt:12 [1636,56] (`state != "supported"`
    # -> `<`): "unknown" < "supported" is False, so the mutant falls to the
    # capped partial candidate instead of returning the unknown one. (The
    # existing "unknown-ineligible" row yields candidate None because its
    # match has length "mismatch", so it never reaches the comparison.)
    def _extra(name, dim, match, rec_age, eligible, reasons):
        rec = _ev_record(evaluated_at=rec_age, n_human=120, n_ai=120)
        sl = _ev_slice(n_human=120, n_ai=120)
        try:
            cand = _record_candidate(
                record=rec,
                slice_=sl,
                match=match,
                now=now,
                max_age_days=30,
                dimension=dim,
                fpr_ceiling=0.05,
                eligible=eligible,
                ineligibility_reasons=reasons,
            )
            if cand is None:
                rows.append((name, ("ok", None)))
            else:
                rows.append((name, ("ok", cand.state, cand.reason, cand.limitations)))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))

    _extra(
        "unknown-state-ineligible",
        "human_false_positive_evidence",
        SliceMatch(
            language="match", length="match", domain="unknown", editing="match", applicable=True
        ),
        "2026-11-01T00:00:00Z",
        False,
        ("stale",),
    )
    # Partial-state candidate + ineligible (fresh partial, 41 days old):
    # kills NotEq_Gt:12 [1636,56] (`state != "supported"` -> `>`):
    # "partial" > "supported" is False, so the mutant falls to the capped
    # partial candidate (reason prefixed) instead of returning the partial
    # candidate itself.
    _extra(
        "partial-state-ineligible", "language", match_all, "2026-10-01T00:00:00Z", False, ("stale",)
    )
    # Eligible + non-empty reasons (contradictory kwargs, constructible):
    # kills Delete_Not:32 [1637,37] (`not eligible` -> `eligible`): the
    # original appends nothing, the mutant appends the "ineligible for
    # support" limitations to an eligible candidate. (The existing
    # "supported-eligible" row has empty reasons, so the mutant's append is
    # an empty tuple there and invisible.)
    _extra("eligible-with-reasons", "language", match_all, "2026-11-01T00:00:00Z", True, ("stale",))
    return rows


def probe_ev_worst_fpr():
    from types import SimpleNamespace

    import test_audit_w2_worker_a as A

    from textforensics.evidence import DimensionCoverage, MetricEstimate, _worst_fpr_dimension

    rec = A._v2_record()
    slice_ = rec.slices[0]
    rows = []

    def _dim(state):
        return DimensionCoverage(
            dimension="human_false_positive_evidence",
            state=state,
            reason="base reason",
            evidence_refs=("ev-a-1-test",),
            observed={},
        )

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
        (
            "supported-two-worst-second",
            _dim("supported"),
            [(rec, slice_, _fpr(0.02)), (rec, slice2, _fpr(0.04))],
            0.05,
        ),
        (
            "supported-two-worst-first",
            _dim("supported"),
            [(rec, slice_, _fpr(0.04)), (rec, slice2, _fpr(0.02))],
            0.05,
        ),
        ("supported-no-ci", _dim("supported"), [(rec, slice_, _fpr(None))], 0.05),
        (
            "supported-no-ci-flag",
            _dim("supported"),
            [(rec, slice_, SimpleNamespace(has_ci=False, ci_upper=0.04))],
            0.05,
        ),
        (
            "supported-ci-upper-none",
            _dim("supported"),
            [(rec, slice_, SimpleNamespace(has_ci=True, ci_upper=None))],
            0.05,
        ),
        ("supported-none-fpr", _dim("supported"), [(rec, slice_, None)], 0.05),
        ("supported-empty", _dim("supported"), [], 0.05),
        ("partial-one-above", _dim("partial"), [(rec, slice_, _fpr(0.09))], 0.05),
        ("unknown-one-above", _dim("unknown"), [(rec, slice_, _fpr(0.09))], 0.05),
        ("partial-empty", _dim("partial"), [], 0.05),
        (
            "supported-missing-plus-ok",
            _dim("supported"),
            [(rec, slice_, _fpr(0.02)), (rec, slice2, None)],
            0.05,
        ),
    ]
    for name, dim, pairs, ceiling in cases:
        try:
            out = _worst_fpr_dimension(dim, pairs, fpr_ceiling=ceiling)
            rows.append(
                (
                    name,
                    (
                        "ok",
                        out.state,
                        out.reason,
                        sorted(out.observed.items(), key=lambda kv: str(kv[0])),
                    ),
                )
            )
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
        # Distinct-but-equal objects (multi-item joins build fresh strings;
        # the existing "aaa-v1-distinct" row uses "".join("1"), a single-item
        # join that returns the interned literal, so `is` still holds).
        # Kills Eq_Is:62 [1967,77] (detector_id == -> is) and Eq_Is:63
        # [1973,73] (detector_version == -> is).
        ("aaa-distinct-obj", "".join(["a", "a", "a"]), None),
        ("aaa-v1-distinct-obj", "aaa", "".join(["", "1"])),
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
    rows.append(
        (
            "ident-fromdict-class",
            outcome(InferenceIdentity.from_dict, {"detector_id": "d", "detector_version": "1"}),
        )
    )
    rows.append(
        (
            "proof-fromdict-class",
            outcome(
                DisjointnessProof.from_dict,
                {
                    "status": "verified",
                    "overlap_count": 0,
                    "training_count": 10,
                    "evaluation_count": 10,
                    "training_hash": "a" * 64,
                    "evaluation_hash": "b" * 64,
                },
            ),
        )
    )
    rows.append(("ident-fromdict-nonmap", outcome(InferenceIdentity.from_dict, ["x"])))
    rows.append(("proof-fromdict-nonmap", outcome(DisjointnessProof.from_dict, "x")))
    # frozen / slots
    ident = InferenceIdentity(detector_id="d", detector_version="1")
    rows.append(("ident-frozen", outcome(lambda: setattr(ident, "detector_id", "e"))))
    rows.append(("ident-slots", ("ok", hasattr(ident, "__dict__"))))
    proof = DisjointnessProof(
        status="unknown",
        overlap_count=0,
        training_count=0,
        evaluation_count=0,
        training_hash=None,
        evaluation_hash=None,
    )
    rows.append(("proof-frozen", outcome(lambda: setattr(proof, "status", "verified"))))
    rows.append(("proof-slots", ("ok", hasattr(proof, "__dict__"))))
    # EligibilityVerdict is also frozen + slots (line 984); the probe only
    # exercised InferenceIdentity and DisjointnessProof. Kills
    # TrueWithFalse:25 [984,18] (frozen=True -> False) and :26 [984,30]
    # (slots=True -> False).
    from textforensics.evidence import EligibilityVerdict

    verdict = EligibilityVerdict(eligible=True, reasons=(), unbound_identity_fields=())
    rows.append(("verdict-frozen", outcome(lambda: setattr(verdict, "eligible", False))))
    rows.append(("verdict-slots", ("ok", hasattr(verdict, "__dict__"))))
    # __post_init__ validation
    for name, fn in [
        ("ident-empty-id", lambda: InferenceIdentity(detector_id="", detector_version="1")),
        ("ident-empty-ver", lambda: InferenceIdentity(detector_id="d", detector_version="")),
        (
            "ident-empty-provider",
            lambda: InferenceIdentity(detector_id="d", detector_version="1", provider=""),
        ),
        (
            "ident-provider-set",
            lambda: InferenceIdentity(detector_id="d", detector_version="1", provider="p"),
        ),
        (
            "proof-bad-status",
            lambda: DisjointnessProof(
                status="maybe",
                overlap_count=0,
                training_count=0,
                evaluation_count=0,
                training_hash=None,
                evaluation_hash=None,
            ),
        ),
        (
            "proof-neg-overlap",
            lambda: DisjointnessProof(
                status="unknown",
                overlap_count=-1,
                training_count=0,
                evaluation_count=0,
                training_hash=None,
                evaluation_hash=None,
            ),
        ),
        (
            "proof-neg-training",
            lambda: DisjointnessProof(
                status="unknown",
                overlap_count=0,
                training_count=-1,
                evaluation_count=0,
                training_hash=None,
                evaluation_hash=None,
            ),
        ),
        (
            "proof-empty-hash",
            lambda: DisjointnessProof(
                status="unknown",
                overlap_count=0,
                training_count=0,
                evaluation_count=0,
                training_hash="",
                evaluation_hash=None,
            ),
        ),
        (
            "proof-hash-set",
            lambda: DisjointnessProof(
                status="unknown",
                overlap_count=0,
                training_count=0,
                evaluation_count=0,
                training_hash="a" * 64,
                evaluation_hash=None,
            ),
        ),
    ]:
        rows.append((name, outcome(fn)))
    return rows


def probe_ev_coverage_preds():
    from types import SimpleNamespace

    import test_audit_w2_worker_a as A

    from textforensics.evidence import EvidenceRegistry, coverage_for_predictions

    rec = A._v2_record()
    reg = EvidenceRegistry([rec])
    cond = A._v2_conditions()
    rows = []

    def _pred(**over):
        base = dict(
            detector_id="a",
            detector_version="1",
            detector_family="fam1",
            supported_length={"min_words": 100, "max_words": 1000},
            min_words=None,
            max_words=None,
        )
        base.update(over)
        return SimpleNamespace(**base)

    def _summarize(covs):
        out = []
        for cov in covs:
            out.append(
                (
                    cov.detector_id,
                    tuple((dim, dc.state) for dim, dc in sorted(cov.dimensions.items())),
                )
            )
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
    import copy
    import json
    from unittest import mock

    import test_result_codec as T

    import textforensics.result_codec as rc
    from textforensics.result_codec import CodecConfig, ResultCodec

    _validate = ResultCodec()._validate
    rows = []
    bundle = copy.deepcopy(T.MINIMAL_BUNDLE)
    # encode: canonical vs non-canonical, sort_keys, ensure_ascii
    codec = ResultCodec()
    rows.append(("encode-canonical", outcome(codec.encode, bundle, "forensic-bundle")))
    codec_nc = ResultCodec(CodecConfig(canonical_json=False))
    rows.append(("encode-noncanonical", outcome(codec_nc.encode, bundle, "forensic-bundle")))
    rows.append(
        (
            "encode-ascii-canonical",
            outcome(codec.encode, {"b": 1, "a": "café"}, "forensic-bundle", validate=False),
        )
    )
    rows.append(
        (
            "encode-ascii-noncanonical",
            outcome(codec_nc.encode, {"b": 1, "a": "café"}, "forensic-bundle", validate=False),
        )
    )
    rows.append(
        (
            "encode-keys-out-of-order",
            outcome(codec.encode, {"z": 1, "a": 2, "m": 3}, "forensic-bundle", validate=False),
        )
    )
    rows.append(
        (
            "encode-inf",
            outcome(codec.encode, {"x": float("inf")}, "forensic-bundle", validate=False),
        )
    )
    rows.append(
        (
            "encode-nan",
            outcome(codec.encode, {"x": float("nan")}, "forensic-bundle", validate=False),
        )
    )
    # decode: validate override (config False, explicit True, invalid payload)
    codec_nv = ResultCodec(CodecConfig(validate_on_decode=False))
    bad = copy.deepcopy(bundle)
    del bad["content_sha256"]  # required property: fails validation when validated
    rows.append(
        (
            "decode-validate-override",
            outcome(codec_nv.decode, json.dumps(bad), "forensic-bundle", validate=True),
        )
    )
    rows.append(
        ("decode-validate-off", outcome(codec_nv.decode, json.dumps(bad), "forensic-bundle"))
    )
    rows.append(("decode-validate-on", outcome(codec.decode, json.dumps(bad), "forensic-bundle")))
    # decode: version comparisons under strict_version
    codec_strict = ResultCodec(CodecConfig(strict_version=True))
    v3 = copy.deepcopy(bundle)
    v3["schema"] = "textforensics.forensic-bundle/v3"
    rows.append(
        ("decode-version-greater", outcome(codec_strict.decode, json.dumps(v3), "forensic-bundle"))
    )
    rows.append(
        (
            "decode-version-equal",
            outcome(codec_strict.decode, json.dumps(bundle), "forensic-bundle"),
        )
    )
    noschema = copy.deepcopy(bundle)
    del noschema["schema"]
    rows.append(
        (
            "decode-version-none",
            outcome(codec_strict.decode, json.dumps(noschema), "forensic-bundle"),
        )
    )
    v1 = copy.deepcopy(bundle)
    v1["schema"] = "textforensics.forensic-bundle/v1"
    rows.append(
        ("decode-version-lower", outcome(codec_strict.decode, json.dumps(v1), "forensic-bundle"))
    )
    # decode: nonfinite literal + non-object + invalid JSON
    rows.append(("decode-infinity", outcome(codec.decode, b'{"x": Infinity}', "forensic-bundle")))
    rows.append(("decode-nan-literal", outcome(codec.decode, b'{"x": NaN}', "forensic-bundle")))
    rows.append(("decode-list", outcome(codec.decode, b"[1, 2]", "forensic-bundle")))
    rows.append(("decode-bad-json", outcome(codec.decode, b"{oops", "forensic-bundle")))
    rows.append(("decode-str-input", outcome(codec.decode, json.dumps(bundle), "forensic-bundle")))
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

    from textforensics.validation import _common_support_blockers, _fpr_blockers, worst_fpr_upper

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
        rows.append(
            (
                name,
                outcome(
                    _common_support_blockers, _rec(**kw), detector_version=A.V3_VERSION, now=A.NOW
                ),
            )
        )
    # split_role values rejected by from_dict ("train"/"validation") via
    # object.__setattr__ on the frozen data object (bypasses validation)
    for name, role in [("split-train", "train"), ("split-validation", "validation")]:
        rec = _rec()
        object.__setattr__(rec.data, "split_role", role)
        rows.append(
            (name, outcome(_common_support_blockers, rec, detector_version=A.V3_VERSION, now=A.NOW))
        )
    # tampered signature (change n_human after sealing)
    tampered = A._v3_record_dict()
    tampered["data"]["n_human"] = 121
    rows.append(
        (
            "bad-signature",
            outcome(
                _common_support_blockers,
                A.ValidationRecord.from_dict(tampered),
                detector_version=A.V3_VERSION,
                now=A.NOW,
            ),
        )
    )

    # worst_fpr_upper / _fpr_blockers via fpr_slices
    def _fpr_rec(slices):
        return A.ValidationRecord.from_dict(A._v3_record_dict(fpr_slices=slices))

    fpr_cases = [
        ("fpr-one-below", [{"slice_id": "s1", "value": 0.02, "ci": (0.0, 0.03)}]),
        ("fpr-one-eq", [{"slice_id": "s1", "value": 0.02, "ci": (0.0, 0.05)}]),
        ("fpr-one-above", [{"slice_id": "s1", "value": 0.02, "ci": (0.0, 0.06)}]),
        (
            "fpr-two-worst",
            [
                {"slice_id": "s1", "value": 0.02, "ci": (0.0, 0.03)},
                {"slice_id": "s2", "value": 0.02, "ci": (0.0, 0.04)},
            ],
        ),
        ("fpr-no-ci", [{"slice_id": "s1", "value": 0.02, "ci": None}]),
        (
            "fpr-mixed",
            [
                {"slice_id": "s1", "value": 0.02, "ci": (0.0, 0.03)},
                {"slice_id": "s2", "value": 0.02, "ci": None},
            ],
        ),
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
    from datetime import date, datetime, timedelta, timezone

    import test_trust as TT

    from textforensics.policy import (
        CapabilityClaim,
        CapabilityLedger,
        EvidenceLabel,
        EvidenceRef,
        EvidenceTier,
        _coerce_today,
        _resolver_verifies,
        ledger_to_trust_dimension,
    )

    rows = []
    # _coerce_today
    for name, value in [
        ("today-none", None),
        ("today-date", date(2026, 1, 15)),
        ("today-naive", datetime(2026, 1, 15, 12, 30)),
        ("today-aware-utc", datetime(2026, 1, 15, 12, 30, tzinfo=UTC)),
        ("today-aware-plus5", datetime(2026, 1, 1, 2, 0, tzinfo=timezone(timedelta(hours=5)))),
        ("today-aware-minus5", datetime(2026, 1, 1, 2, 0, tzinfo=timezone(timedelta(hours=-5)))),
        (
            "today-aware-plus5-midnight",
            datetime(2026, 1, 1, 0, 30, tzinfo=timezone(timedelta(hours=5))),
        ),
    ]:
        rows.append((name, outcome(_coerce_today, value)))
    # _resolver_verifies
    ref = EvidenceRef(
        label=EvidenceLabel.EXECUTED, tier=EvidenceTier.VALIDATED, artifact="runs/1.json"
    )

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
    no_evidence = CapabilityClaim(
        detector_id="a", capability="language", tier=EvidenceTier.READABLE, evidence=[]
    )
    validated_no_exec = CapabilityClaim(
        detector_id="a",
        capability="language",
        tier=EvidenceTier.VALIDATED,
        evidence=[
            EvidenceRef(
                label=EvidenceLabel.REPORTED, tier=EvidenceTier.VALIDATED, artifact="runs/1.json"
            )
        ],
    )
    expired = TT._ledger_claim(valid_until="2020-01-01")
    for name, claim in [
        ("register-valid", valid),
        ("register-no-evidence", no_evidence),
        ("register-validated-no-exec", validated_no_exec),
        ("register-expired", expired),
    ]:
        ledger = CapabilityLedger()
        rows.append(
            (
                name,
                outcome(
                    lambda c=claim, led=ledger: (led.register(c), len(led.claims().get("a", [])))
                ),
            )
        )
    # register: the warning is logged iff issues are non-empty (AddNot:12)
    import logging

    def _register_with_logs(claim):
        logger = logging.getLogger("textforensics.policy")
        captured = []

        class _H(logging.Handler):
            def emit(self, record):
                captured.append(record.getMessage())

        handler = _H()
        logger.addHandler(handler)
        try:
            ledger = CapabilityLedger()
            issues = ledger.register(claim)
        finally:
            logger.removeHandler(handler)
        return (issues, captured)

    rows.append(("register-log-valid", outcome(lambda: _register_with_logs(valid))))
    rows.append(("register-log-invalid", outcome(lambda: _register_with_logs(no_evidence))))
    # ledger_to_trust_dimension: valid_until limitation present/absent
    for name, claim in [
        ("ltd-no-expiry", TT._ledger_claim()),
        ("ltd-with-expiry", TT._ledger_claim(valid_until="2027-01-01")),
        ("ltd-expired", TT._ledger_claim(valid_until="2020-01-01")),
    ]:
        ledger = TT._ledger_with(claim)
        try:
            dim = ledger_to_trust_dimension(ledger, "a", "language", today=date(2026, 11, 11))
            rows.append((name, ("ok", dim.state, dim.reason, dim.limitations)))
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    ledger_empty = CapabilityLedger()
    rows.append(
        (
            "ltd-no-claims",
            outcome(
                lambda: (
                    ledger_to_trust_dimension(
                        ledger_empty, "a", "language", today=date(2026, 11, 11)
                    ).state
                )
            ),
        )
    )
    return rows


# ---------------------------------------------------------------------------
# trust.build_trust_map (new probe)
# ---------------------------------------------------------------------------
def probe_trust_build():
    from textforensics.detectors import DetectorPrediction
    from textforensics.evidence import InputConditions
    from textforensics.trust import build_trust_map

    rows = []

    def _cond(wc):
        return InputConditions(
            schema="textforensics.input-conditions/v1",
            language="en",
            language_confidence="declared",
            script="latin",
            word_count=wc,
            char_count=1000,
            length_band="medium",
            domain_genre="general",
            domain_confidence="declared",
            editing_regime="human_only",
            generator=None,
            human_population="unknown",
        )

    pred = DetectorPrediction(
        schema="textforensics.detector-result/v2",
        detector_id="detector",
        detector_version="1",
        detector_family="family",
        execution="local",
        score=0.8,
        score_semantics="test",
        verdict="ai_like",
        threshold=0.5,
    )

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
            tm = (
                build_trust_map([pred], word_count=wc, conditions=cond)
                if cond is not None
                else build_trust_map([pred], word_count=wc)
            )
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
    v3_one = {
        "schema": "textforensics.trust-map/v3",
        "overall": "strong",
        "dimensions": [
            {"dimension": "language", "state": "supported", "reason": "ok", "evidence_refs": []}
        ],
        "limitations": [],
        "generated_at_utc": "2024-01-01T00:00:00+00:00",
    }
    v3_full = {
        "schema": "textforensics.trust-map/v3",
        "overall": "unknown",
        "dimensions": [
            {"dimension": d, "state": "unknown", "reason": "ok", "evidence_refs": []}
            for d in (
                "language",
                "text_length",
                "domain_genre",
                "editing_revision",
                "generator_scope",
                "human_population",
                "human_false_positive_evidence",
                "temporal_version_stability",
            )
        ],
        "limitations": [],
        "generated_at_utc": "2024-01-01T00:00:00+00:00",
    }
    for name, bundle in [
        ("v3-one-dim", {**base, "trust_map": v3_one}),
        ("v3-full", {**base, "trust_map": v3_full}),
        ("v2-map", base),
        (
            "no-input-conditions",
            {k: v for k, v in {**base, "trust_map": v3_one}.items() if k != "input_conditions"},
        ),
        (
            "input-conditions-str",
            {**base, "trust_map": v3_one, "input_conditions": "not-a-mapping"},
        ),
        ("no-trust-map", {k: v for k, v in base.items() if k != "trust_map"}),
    ]:
        rows.append((name, outcome(_replay_trust_map, bundle, None)))
    # _validate_portable_bundle: pair errors are a single-element list,
    # so pair_errors[0] == pair_errors[-1] (see report).
    for name, bundle in [
        ("validate-v2-v3", {**base, "trust_map": v3_one}),
        ("validate-v2-v2", base),
        (
            "validate-v1-v3",
            {**base, "schema": "textforensics.forensic-bundle/v1", "trust_map": v3_one},
        ),
        (
            "validate-v1-v1",
            {
                **base,
                "schema": "textforensics.forensic-bundle/v1",
                "trust_map": {"schema": "textforensics.trust-map/v1"},
            },
        ),
        ("validate-no-tm-schema", {**base, "trust_map": {"overall": "strong"}}),
        ("validate-bad-bundle-schema", {**base, "schema": "textforensics.forensic-bundle/v9"}),
    ]:
        rows.append((name, outcome(_validate_portable_bundle, bundle)))
    return rows


# ---------------------------------------------------------------------------
# probe_runs._score / _series_from_records / build_run_manifest (new probe)
# ---------------------------------------------------------------------------
def probe_pr_score_series():
    from textforensics.probe_runs import _score, _series_from_records, build_run_manifest

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
        return {
            "sample_id": sid,
            "score": score,
            "verdict": "ai_like",
            "native_score_direction": "higher_means_ai",
            "score_range": [0.0, 1.0],
        }

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
    kw = dict(
        scope="full",
        corpus_version="1.0.0",
        corpus_fingerprint="a" * 64,
        corpus_manifest_sha256="b" * 64,
        detector_id="d",
        detector_version="1",
        metrics={},
        alerts=[],
        breaches=[],
        baseline_run_id=None,
        is_baseline=True,
        previous_run_id=None,
    )
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
            rows.append(
                (
                    name,
                    (
                        "ok",
                        m["provider_metadata"],
                        m["code_sha"],
                        m["run_id"] if "run_id" in over else "auto",
                        m["run_at_utc"] if "run_at_utc" in over else "auto",
                    ),
                )
            )
        except Exception as exc:  # noqa: BLE001
            rows.append((name, ("raise", type(exc).__name__, str(exc))))
    return rows


# ---------------------------------------------------------------------------
# benchmark.DisjointnessProof from_dict / frozen / slots (new probe)
# ---------------------------------------------------------------------------
def probe_bm_proof_dict():
    from textforensics.benchmark import DisjointnessProof

    rows = []
    base = {
        "status": "verified",
        "overlap_count": 0,
        "training_count": 10,
        "evaluation_count": 10,
        "training_hash": "a" * 64,
        "evaluation_hash": "b" * 64,
    }
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
    proof = DisjointnessProof(
        status="verified",
        overlap_count=0,
        training_count=10,
        evaluation_count=10,
        training_hash="a" * 64,
        evaluation_hash="b" * 64,
    )
    rows.append(("proof-frozen", outcome(lambda: setattr(proof, "status", "unknown"))))
    rows.append(("proof-slots", ("ok", hasattr(proof, "__dict__"))))
    rows.append(("proof-default-group", ("ok", proof.group_overlap_count)))
    rows.append(("proof-default-errors", ("ok", proof.errors)))
    rows.append(("proof-to-dict", outcome(lambda: proof.to_dict()["group_overlap_count"])))
    return rows
