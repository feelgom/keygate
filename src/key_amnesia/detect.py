"""Shared secret-shape detector for the PreToolUse hook and ``ka scan``.

Tiers (not a score)::

    none      placeholder, too short, function-call, type-annotation
    possible  name matched; 0.4.9 mixed-class + Shannon gate; identifier
              or word-shaped passphrase
    likely    stricter value signals (transition floor / hex exception)
    prefix    vendor prefix (always high), or Bearer whose value is likely

Both consumers import this module. The hook denies on possible|likely|prefix.
``ka scan`` ``leak_count`` / default exit count likely + prefix + filename
hits only.

Never returns or logs secret *values*.

Measured evidence (reconstructed shapes, not harvested content)
---------------------------------------------------------------
Against 0.4.9 ``_assignment_is_secret`` (length ≥ 8, ≥2 of upper/lower/digit,
Shannon ≥ 3.0):

Shannon (raw bits):
    GetTokenFromCache()            3.89
    hook fixture Zk9pL2xQ7mN4vB8w  4.17
    hex-32                         3.81
Hex sits *inside* the identifier band. Shannon ≥ 3.0 cannot split identifiers
from random tokens; it remains the *possible* gate (``SHANNON_POSSIBLE_FLOOR``),
not the likely-floor.

Normalized entropy (H / log2(|alphabet|)):
    identifiers     0.95–1.00
    random strings  0.94–1.00
Completely overlapping. Not adopted.

Character-class transition rate (adjacent pairs that change class among
{upper, lower, digit, other}):
    identifiers         0.18–0.45  (mostly camelCase boundaries)
    random fixtures     1.00
    JWT-shaped          0.71
    hex-32              0.42
``LIKELY_TRANSITION_FLOOR = 0.50`` is the lowest floor that excludes the
entire measured identifier band (ceiling 0.45) while still admitting
JWT-shaped (0.71) and random fixtures (1.00). 0.60 would still pass those
positives but sits farther from the identifier ceiling without additional
evidence. Hex-32 at 0.42 is *below* 0.50, which is why ``HEX_LIKELY`` is an
explicit exception rather than a reason to lower the floor: hex does not
alternate classes the way base62 does.

Length ≥ 20 as a likely-floor: rejected — the 16-char hook fixture
``Zk9pL2xQ7mN4vB8w`` must remain likely.

English-segment demotion: ≥2 vowel-bearing CamelCase/Pascal segments and
*no digits* → possible. Must not apply when digits are present (JWT
``eyJhbGciOi…`` would otherwise demote via ``Gci`` / ``Ikp``).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Iterable, Iterator, Literal

Confidence = Literal["none", "possible", "likely"]

# --- length / possible-gate (0.4.9 assignment heuristic) -------------------
# Inherited as the *possible* gate, not the likely-floor. Shannon 3.0 is why
# identifiers over-block today; likely uses transition rate instead.
MIN_VALUE_LEN = 8
SHANNON_POSSIBLE_FLOOR = 3.0  # GetTokenFromCache() 3.89; fixture 4.17; hex-32 3.81

# --- likely-floor ----------------------------------------------------------
# Identifiers 0.18–0.45; JWT-shaped 0.71; random fixtures 1.00; hex-32 0.42.
# 0.50 is the lowest floor that excludes the measured identifier band.
LIKELY_TRANSITION_FLOOR = 0.50

# Hex-32 transition 0.42 is below LIKELY_TRANSITION_FLOOR, so hex is an
# explicit likely exception rather than a lowered floor.
HEX_LIKELY_MIN_LEN = 16
_HEX_LIKELY = re.compile(rf"[0-9a-fA-F]{{{HEX_LIKELY_MIN_LEN},}}$")

# Word-shaped passphrase / identifier demotion: ≥2 vowel-bearing segments
# and no digits → possible, not likely (named weakening 3).
MIN_VOWEL_SEGMENTS_FOR_POSSIBLE = 2

# Named weakenings. Hook recall drops only 1–2. Weakening 3 is scan-only
# (hook still denies). Everything under tests/fixtures/scan_corpus/demoted/
# must map to weakening 3.
NAMED_WEAKENING_FUNCTION_CALL = "function-call"
NAMED_WEAKENING_TYPE_ANNOTATION = "type-annotation"
NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE = "word-shaped-passphrase"
NAMED_WEAKENINGS: tuple[str, ...] = (
    NAMED_WEAKENING_FUNCTION_CALL,
    NAMED_WEAKENING_TYPE_ANNOTATION,
    NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE,
)

# Well-known API key / token prefixes (value starts immediately after).
# Anthropic-style checked before the more general OpenAI-style pattern so the
# reported "kind" is the more specific one.
PREFIX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic-style key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("GitHub PAT", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("GitLab PAT", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    ("Stripe secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("Stripe restricted key", re.compile(r"\brk_live_[A-Za-z0-9]{20,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b")),
]

BEARER = re.compile(r"\bBearer\s+([A-Za-z0-9._\-+=/]{16,})", re.IGNORECASE)

# ENV-style / JSON / YAML / TOML assignments. Optional dotted prefix
# (secrets.api_key) is not part of the captured name. Optional matching
# quotes around the name so `"api_key": "…"` matches.
ASSIGN = re.compile(
    r"""(?ix)
    (?:[A-Za-z_][A-Za-z0-9_]*\.)*
    (?P<nq>['"]?)
    (?P<name>(?:[a-z0-9]+[_-])*(?:api[_-]?key|token|secret|password|passwd|private[_-]?key))
    (?P=nq)
    \s*[:=]\s*
    (?P<q>['"]?)
    (?P<value>[^\s'"]{8,})
    (?P=q)
    """
)

_SECRET_NAME = re.compile(
    r"(?ix)^(?:[a-z0-9]+[_-])*(?:api[_-]?key|token|secret|password|passwd|private[_-]?key)$"
)

_PLACEHOLDER_VALUES = {
    "test123",
    "test1234",
    "changeme",
    "change_me",
    "changethis",
    "password",
    "password123",
    "secret",
    "yourkey",
    "your_api_key",
    "your-api-key",
    "placeholder",
    "example",
    "dummy",
    "fake",
    "sample",
    "xxxxxxxx",
    "12345678",
}

# ident(...) / dotted.attr(...) — named weakening 1 → none
_FUNC_CALL = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(.*\)$"
)

# Name[...] — named weakening 2 → none
_TYPE_ANN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\[.+\]$")

_VOWELS = set("aeiouAEIOU")
_CAMEL_SEGS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_placeholder(value: str) -> bool:
    v = value.strip("'\"").lower()
    if v in _PLACEHOLDER_VALUES:
        return True
    if re.fullmatch(r"x{6,}", v):
        return True
    if re.fullmatch(r"0{6,}|1{6,}", v):
        return True
    return False


def is_secret_name(name: str) -> bool:
    """True if a dict/JSON key matches the assignment name vocabulary."""
    return bool(_SECRET_NAME.fullmatch(name.strip().strip("'\"")))


def _char_class(c: str) -> str:
    if c.isupper():
        return "U"
    if c.islower():
        return "L"
    if c.isdigit():
        return "D"
    return "O"


def transition_rate(s: str) -> float:
    """Fraction of adjacent pairs that change character class.

    Identifiers 0.18–0.45; random fixtures 1.00; JWT-shaped 0.71; hex-32 0.42.
    """
    if len(s) < 2:
        return 0.0
    changes = sum(
        1 for a, b in zip(s, s[1:]) if _char_class(a) != _char_class(b)
    )
    return changes / (len(s) - 1)


def _word_segments(value: str) -> list[str]:
    parts = re.split(r"[^A-Za-z0-9]+", value)
    segs: list[str] = []
    for part in parts:
        if not part:
            continue
        found = _CAMEL_SEGS.findall(part)
        segs.extend(found if found else [part])
    return segs


def _has_vowel(seg: str) -> bool:
    return any(c in _VOWELS or c in "yY" for c in seg)


def _vowel_bearing_segments(value: str) -> int:
    return sum(1 for seg in _word_segments(value) if _has_vowel(seg))


def classify_value(value: str) -> Confidence:
    """Classify a captured assignment/Bearer *value* (never logged)."""
    v = value.strip("'\"")
    if len(v) < MIN_VALUE_LEN:
        return "none"
    if is_placeholder(v):
        return "none"
    if _FUNC_CALL.fullmatch(v):
        return "none"
    if _TYPE_ANN.fullmatch(v):
        return "none"

    has_upper = any(c.isupper() for c in v)
    has_lower = any(c.islower() for c in v)
    has_digit = any(c.isdigit() for c in v)
    mixed = sum([has_upper, has_lower, has_digit]) >= 2
    if not mixed:
        return "none"
    if entropy(v) < SHANNON_POSSIBLE_FLOOR:
        return "none"

    # Named weakening 3: word-shaped, no digits → possible (hook still denies).
    if not has_digit and _vowel_bearing_segments(v) >= MIN_VOWEL_SEGMENTS_FOR_POSSIBLE:
        return "possible"

    if _HEX_LIKELY.fullmatch(v):
        return "likely"

    if transition_rate(v) >= LIKELY_TRANSITION_FLOOR:
        return "likely"
    return "possible"


def assignment_is_secret(value: str) -> bool:
    """0.4.9 hook meaning: possible or likely (not none)."""
    return classify_value(value) in ("possible", "likely")


def find_prefix_kind(text: str) -> str | None:
    for kind, pattern in PREFIX_PATTERNS:
        if pattern.search(text):
            return kind
    return None


def classify_bearer_capture(text: str) -> Confidence:
    match = BEARER.search(text)
    if not match:
        return "none"
    return classify_value(match.group(1))


def find_secret_kind(text: str) -> str | None:
    """Human-readable kind if possible|likely|prefix, else None. No values."""
    prefix = find_prefix_kind(text)
    if prefix:
        return prefix

    bearer_tier = classify_bearer_capture(text)
    if bearer_tier in ("possible", "likely"):
        return "Bearer token"

    for match in ASSIGN.finditer(text):
        if classify_value(match.group("value")) in ("possible", "likely"):
            return f"{match.group('name').upper()} assignment"
    return None


def iter_assignment_matches(text: str) -> Iterator[re.Match[str]]:
    yield from ASSIGN.finditer(text)


def collect_strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from collect_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from collect_strings(item)


def iter_secret_keyed_strings(obj: Any) -> Iterator[tuple[str, str]]:
    """Yield (key, string_value) where key matches the secret-name vocabulary."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and is_secret_name(k) and isinstance(v, str):
                yield k, v
            yield from iter_secret_keyed_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_secret_keyed_strings(item)


def scan_text_hits(
    text: str,
) -> tuple[list[str], list[str], str | None, bool]:
    """Assignment names (likely, possible), prefix kind, bearer-possible flag.

    Prefix kind is high-confidence. Bearer whose value is likely is returned
    as prefix kind ``Bearer token``. Bearer of an identifier sets the
    possible flag instead. Never returns values.
    """
    if not text:
        return [], [], None, False

    prefix = find_prefix_kind(text)
    bearer_tier = classify_bearer_capture(text)
    bearer_possible = False
    if prefix is None and bearer_tier == "likely":
        prefix = "Bearer token"
    elif prefix is None and bearer_tier == "possible":
        bearer_possible = True

    likely_names: list[str] = []
    possible_names: list[str] = []
    seen: set[str] = set()
    for match in ASSIGN.finditer(text):
        name = match.group("name")
        key = name.upper()
        if key in seen:
            continue
        tier = classify_value(match.group("value"))
        if tier == "likely":
            seen.add(key)
            likely_names.append(name)
        elif tier == "possible":
            seen.add(key)
            possible_names.append(name)

    return likely_names, possible_names, prefix, bearer_possible


def looks_like_json_container(s: str) -> bool:
    t = s.lstrip()
    return t.startswith("{") or t.startswith("[")
