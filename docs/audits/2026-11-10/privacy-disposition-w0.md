# Privacy disposition (W0)

Classification of the four disclosed historical path-candidate files
and their seven occurrences, per the plan's privacy disposition gate
(W0) and the audit evidence key `privacy_candidate_locations`
(`docs/audits/2026-11-10/evidence.json`, kind
`host-specific-home-path` for all four).

## Hard rule

This file records **only** file locations, line numbers, categories
and generic context. The matched path values are **not** copied,
quoted or reproduced anywhere in this file, in any commit message,
test fixture or report. The classification was performed with
redacting probes: matched values were replaced before inspection,
and attribution was decided from structural properties only (presence
or absence of hosted-runner markers, file purpose, surrounding
context).

## Classification table

| # | File | Line(s) | Occurrences | Category | Reason (generic context only) |
| --- | --- | --- | --- | --- | --- |
| 1 | `docs/evidence/runs/EV-20261106-suite.json` | 4 | 1 | `actual-personal-path` | Occurs in the recorded `command` field of a run artifact: the executing account's local virtual-environment interpreter path under its home directory. No hosted-runner markers are present; it is not a test fixture. |
| 2 | `docs/evidence/runs/EV-20261107-suite.json` | 4 | 1 | `actual-personal-path` | Same as #1: recorded `command` field of a run artifact holding the executing account's local virtual-environment interpreter path under its home directory. No hosted-runner markers; not a fixture. |
| 3 | `docs/live-host-api/fullsuite2.log` | 33, 35 | 2 | `actual-personal-path` | Occurs in Python traceback frames of a committed live-host run log: the absolute path of a checked-out test file under the operator account's home directory. Not a runner path; not a fixture. |
| 4 | `docs/live-host-api/fullsuite2.log` | 1472, 1474 | 2 | `actual-personal-path` | Same as #3: traceback frames in the same committed live-host run log, recording the same checked-out test file's absolute path under the operator account's home directory. |
| 5 | `tests/fuzz/generate_corpus.py` | 99 | 1 | `intentional-test-fixture` | Occurs in a synthetic example string in the fuzz corpus generator's sample list, alongside other placeholder examples (placeholder email, URL, SQL and JSON-like strings). The home-directory component is a generic placeholder account name, not a real account. No real path is recorded. |

## Totals

- Files: 4. Occurrences: 7 (1 + 1 + 4 + 1) — all seven accounted for.
- `hosted-runner-output`: 0. No occurrence carries hosted-runner
  markers (no runner service-account component, no runner work
  directory, no CI action paths).
- `intentional-test-fixture`: 1 (occurrence #5).
- `actual-personal-path`: 6 (occurrences #1–#4).
- `indeterminate`: 0.

## What `actual-personal-path` means here — and what it does not

A candidate is **not** automatically a verified personal-data leak.
The six occurrences classified `actual-personal-path` are real,
host-specific home-directory paths of the account that produced the
artifacts — they are neither hosted-runner output nor fixtures.
Attribution evidence: in all six cases the path sits under the home
directory of the runtime service account that executed the run (not
under a hosted-runner account, and the home-directory component is a
generic service-account name, not a natural person's name). The
exposure is therefore limited to host filesystem layout — the
account's home directory and the layout of its virtual environment
and checkout — not a natural person's name, address, or credentials.
No credentials, tokens, keys, account numbers or real user text were
found in any of the seven occurrences; the classification concerns
home-directory paths only.

## Consequences and open owner decisions

- **No file was edited and no history was rewritten.** This
  disposition changes nothing in the four files; removing old
  material from public Git history is a separate owner-authorized
  operation with a recovery/provenance plan, and this audit
  authorizes no rewrite. Whether the six host-layout paths warrant
  such a rewrite is an **open owner decision**.
- The two suite JSONs (#1, #2) are registry-pinned evidence
  artifacts: their digests are bound by the claims gate. Any
  sanitized successor must be a provenance-linked replacement that
  keeps the old source commit/digest as lineage and must not pretend
  to be the original signed artifact (plan privacy gate, W7).
- The log (#3, #4) is a raw operational log committed as evidence;
  W7 must replace raw current-tree operational logs/evidence with
  minimized, provenance-linked successors where needed.
- The fixture (#5) needs no action: it is already host-neutral (a
  generic placeholder) and is intentional test data.
- W10 must re-scan the candidate source archive, wheel/sdist, image
  contents and published evidence for personal paths/accounts/text/
  keys. Unresolved actual personal data or unexamined candidates
  block qualification.
