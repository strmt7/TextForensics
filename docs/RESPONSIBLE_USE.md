# Responsible use

TextForensics is a forensic and research tool for understanding AI-text detector evidence. Detector outputs are probabilistic/instrumental evidence, not proof of authorship.

## High-stakes use

Do not use a TextForensics result as the sole basis for:
- academic discipline,
- employment action,
- legal accusation,
- fraud accusation,
- benefit/eligibility denial,
- publication sanctions.

Use process evidence, policy, drafts, citations and human review alongside detector observations.

## False positives

False positives can cluster by language, writing style, domain, length and other conditions. This is why the project prioritizes:
- human false-positive rates,
- slice-level evaluation,
- abstention,
- nearest-slice validation evidence,
- transparent disagreement,
- Trust Map coverage.

Do not infer demographic traits from writing in order to "correct" a score.

## Editing assistance

TextForensics may identify formulaic or unclear writing and may later support quality-oriented editing.

Appropriate objectives:
- clearer meaning,
- concrete specificity,
- author voice,
- semantic preservation,
- explaining features associated with false-positive risk.

The project should not promise that edited text becomes "undetectable" or guarantee a particular third-party detector outcome.

## Privacy

The core is local-first.

Remote adapters:
- require explicit user configuration,
- disclose that text leaves the machine,
- use official/authorized APIs,
- avoid retaining secrets or raw input in reports/logs,
- expose provider/version/timestamp metadata when available.

Portable case files omit raw text by default.

## Communication

Prefer language such as:
- "machine-like detector signal",
- "detector observation",
- "evidence coverage",
- "insufficient evidence",
- "supported/unsupported operating regime".

Avoid:
- "caught cheating",
- "proved AI",
- "definitely human",
- "truth score".

