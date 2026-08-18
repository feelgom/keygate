# Scan corpus

Labeled synthetic *shapes* for the shared detector in `key_amnesia.detect`.
No harvested transcripts. No live keys. Tests must never print fixture values.

## Categories

**`negatives/`** — not credentials. Scan `leak_count` must be 0. Classifier
must not return `likely` or `prefix`. May be `none` (function-call, type
annotation, placeholder) or `possible` (camelCase identifiers the hook still
denies). The label means “must not be high-confidence,” not “the hook allows.”

**`demoted/`** — plausible credentials **intentionally** classified below
`likely` (named weakening 3: word-shaped passphrase, ≥2 vowel-bearing
segments, no digits). Must be `possible`, not `none`, not `likely`. The hook
still denies. Not in `leak_count`. `--fail-on possible` is the CI opt-in.
Every file here must appear in the named-weakening list.

**`positives/`** — on-disk prefix samples only, constructed like
`KNOWN_PREFIX_SAMPLES` (repeated `a` / `0`). Must classify as `prefix` /
high. Stripe `sk_live_` / `rk_live_` prefixes are **not** on disk: GitHub
push protection flags even the repeated-`a` construction. Cover them in
hook tests via concatenation. Unprefixed `likely` values are **generated at
test time** into pytest tmp (`.env` / JSON / YAML / TOML / `export`), not
committed, so GitHub secret scanning does not block the PR.

## Order

A “before” measurement using the 0.4.9 assignment heuristic is recorded in
`tests/test_scan_corpus.py`. Thresholds were frozen only after that.
