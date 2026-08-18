"""``ka scan`` — LEAK (Locally Exposed Agent Keys) discovery.

Walks a project tree (and optionally ``--deep`` home/shell/MCP locations
plus known agent session transcript JSONL trees) looking for plaintext
secret *files* and light assignment / prefix patterns. Reports **names,
paths, counts, and (for transcripts) line numbers only** — never prints,
logs, or copies secret values.

Detection is **advisory**. The headline and default exit count
high-confidence findings only (``likely`` / prefix / filename). Identifier-
and passphrase-shaped hits are ``possible`` (``--fail-on possible`` to
gate). Policy classification: Scan LEAK report is **advisory** (not
cryptography).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from key_amnesia.detect import (
    classify_value,
    collect_strings,
    iter_secret_keyed_strings,
    looks_like_json_container,
    scan_text_hits,
)
from key_amnesia.dotenv_import import parse_dotenv

# Directory basenames skipped by default (B4). ``.git`` skips all git
# internals — git-*history* secret scanning is intentionally out of scope.
DEFAULT_EXCLUDE_DIR_NAMES: frozenset[str] = frozenset(
    {
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".git",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "target",
        ".next",
        ".nuxt",
        "coverage",
        ".eggs",
        ".amnesia",  # vault ciphertext — not agent-readable plaintext
        ".hg",
        ".svn",
    }
)

# Filename suffixes / exact names that are build/cache artifacts even when
# the parent dir isn't excluded.
_SKIP_SUFFIXES = (".pyc", ".pyo", ".egg-info")

# Max bytes to read when content-scanning a non-dotenv file.
_MAX_CONTENT_BYTES = 256_000

# Skip oversized session transcripts (line-iter still; refuse open if huge).
_MAX_TRANSCRIPT_BYTES = 100 * 1024 * 1024

# Cap human-report line lists; full list remains in ``--json``.
_HIT_LINES_DISPLAY_CAP = 20

# Text-ish extensions worth content-scanning for assignment patterns.
_CONTENT_SCAN_SUFFIXES = frozenset(
    {
        "",
        ".env",
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".mjs",
        ".cjs",
        ".json",
        ".toml",
        ".yaml",
        ".yml",
        ".ini",
        ".cfg",
        ".conf",
        ".config",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".bat",
        ".cmd",
        ".txt",
        ".md",
        ".properties",
        ".xml",
        ".rb",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".php",
        ".cs",
    }
)

_SSH_PRIVATE_NAMES = frozenset({"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"})

_MCP_BASENAMES = frozenset(
    {
        "mcp.json",
        "claude_desktop_config.json",
    }
)

_HISTORY_BASENAMES = frozenset(
    {
        ".bash_history",
        ".zsh_history",
        ".zhistory",
        ".python_history",
        ".node_repl_history",
        ".lesshst",
    }
)


@dataclass
class Finding:
    """One LEAK finding. Never carries secret *values*."""

    path: str
    kind: str
    secret_names: list[str] = field(default_factory=list)
    secret_count: int = 0
    reason: str = ""
    importable: bool = False
    scope: str = "project"  # "project" | "deep"
    # 1-based JSONL line numbers (agent transcripts only).
    hit_lines: list[int] = field(default_factory=list)
    # "high" = leak_count / default exit; "possible" = identifier/passphrase.
    confidence: str = "high"


def _is_dotenv_filename(name: str) -> bool:
    """``.env``, ``.env.local``, ``.env.production``, etc. — not ``.environment``."""
    if name == ".env":
        return True
    if name.startswith(".env."):
        # Skip already-imported leftovers.
        return not name.endswith(".imported")
    return False


def _filename_kind(path: Path) -> str | None:
    name = path.name
    if _is_dotenv_filename(name):
        return "dotenv"
    if name == "credentials.json":
        return "credentials.json"
    if name == ".npmrc":
        return ".npmrc"
    if name == ".pypirc":
        return ".pypirc"
    if name in _SSH_PRIVATE_NAMES:
        return "ssh_private_key"
    if name in _MCP_BASENAMES or (
        name == "mcp.json" or path.as_posix().endswith("/mcp.json")
    ):
        return "mcp_config"
    if name in _HISTORY_BASENAMES or name.endswith("_history"):
        return "shell_history"
    if name == ".gitconfig" or name == ".git-credentials":
        return "git_config"
    return None


def _safe_read_text(path: Path, *, limit: int = _MAX_CONTENT_BYTES) -> str | None:
    try:
        data = path.read_bytes()[:limit]
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return None


def _dotenv_finding(path: Path, *, scope: str) -> Finding | None:
    try:
        entries = parse_dotenv(path)
    except OSError:
        return None
    # Names only; drop empty values from the count (placeholders often empty).
    names = [n for n, v in entries.items() if v.strip()]
    if not names and not entries:
        # Empty / comment-only .env — still a LEAK *file* if it exists and
        # looks like a dotenv path agents will open; count 0 secrets.
        return Finding(
            path=str(path),
            kind="dotenv",
            secret_names=[],
            secret_count=0,
            reason="dotenv file (no KEY=VALUE entries)",
            importable=False,
            scope=scope,
        )
    if not names:
        return Finding(
            path=str(path),
            kind="dotenv",
            secret_names=list(entries.keys()),
            secret_count=0,
            reason="dotenv file (empty values only)",
            importable=False,
            scope=scope,
        )
    return Finding(
        path=str(path),
        kind="dotenv",
        secret_names=names,
        secret_count=len(names),
        reason=f"dotenv file with {len(names)} secret name(s)",
        importable=True,
        scope=scope,
    )


def _json_key_names(path: Path) -> list[str]:
    """Top-level JSON object keys only — never values."""
    text = _safe_read_text(path)
    if text is None:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return [str(k) for k in data.keys()]
    return []


def scan_text_for_leaks(text: str) -> tuple[list[str], str | None]:
    """High-confidence assignment *names* + optional prefix/Bearer kind.

    Never returns secret values. Possible-tier hits are omitted here;
    use ``scan_text_hits`` for the split.
    """
    if not text:
        return [], None
    likely, _possible, prefix, _bp = scan_text_hits(text)
    return likely, prefix


def _strings_from_decoded_json(obj: Any) -> list[str]:
    """Collect strings from a decoded JSON value; unwrap one nested JSON string."""
    out: list[str] = []
    for s in collect_strings(obj):
        out.append(s)
        if not looks_like_json_container(s):
            continue
        try:
            nested = json.loads(s)
        except json.JSONDecodeError:
            continue
        if isinstance(nested, (dict, list)):
            out.extend(collect_strings(nested))
    return out


def _merge_hits(
    likely: list[str],
    possible: list[str],
    prefix: str | None,
    bearer_possible: bool,
    extra_likely: list[str],
    extra_possible: list[str],
    extra_prefix: str | None,
    extra_bp: bool,
) -> tuple[list[str], list[str], str | None, bool]:
    seen_l = {n.upper() for n in likely}
    seen_p = {n.upper() for n in possible}
    for name in extra_likely:
        key = name.upper()
        if key in seen_l:
            continue
        seen_l.add(key)
        likely.append(name)
        seen_p.discard(key)
        possible[:] = [n for n in possible if n.upper() != key]
    for name in extra_possible:
        key = name.upper()
        if key in seen_l or key in seen_p:
            continue
        seen_p.add(key)
        possible.append(name)
    if extra_prefix and prefix is None:
        prefix = extra_prefix
    if extra_bp:
        bearer_possible = True
    return likely, possible, prefix, bearer_possible


def _scan_transcript_payload(
    obj: Any,
) -> tuple[list[str], list[str], str | None, bool]:
    """Run detectors on string payloads and secret-named JSON keys.

    Returns likely names, possible names, prefix kind, bearer-possible.
    Never returns values.
    """
    likely: list[str] = []
    possible: list[str] = []
    prefix: str | None = None
    bearer_possible = False

    def _apply_obj(node: Any) -> None:
        nonlocal likely, possible, prefix, bearer_possible
        for s in _strings_from_decoded_json(node):
            ln, pn, pref, bp = scan_text_hits(s)
            likely, possible, prefix, bearer_possible = _merge_hits(
                likely, possible, prefix, bearer_possible, ln, pn, pref, bp
            )
        for key, val in iter_secret_keyed_strings(node):
            tier = classify_value(val)
            if tier == "likely":
                likely, possible, prefix, bearer_possible = _merge_hits(
                    likely, possible, prefix, bearer_possible, [key], [], None, False
                )
            elif tier == "possible":
                likely, possible, prefix, bearer_possible = _merge_hits(
                    likely, possible, prefix, bearer_possible, [], [key], None, False
                )
            if looks_like_json_container(val):
                try:
                    nested = json.loads(val)
                except json.JSONDecodeError:
                    continue
                if isinstance(nested, (dict, list)):
                    _apply_obj(nested)

    _apply_obj(obj)
    return likely, possible, prefix, bearer_possible


def iter_agent_transcript_files(home: Path | None = None) -> Iterable[Path]:
    """Yield known agent session JSONL transcript paths under ``home``.

    Not a full home walk — only Claude Code / Codex / Copilot CLI layouts.
    """
    home = (home or Path.home()).resolve()
    seen: set[str] = set()

    def _emit(path: Path) -> Iterable[Path]:
        try:
            if not path.is_file():
                return
            key = str(path.resolve())
        except OSError:
            return
        if key in seen:
            return
        seen.add(key)
        yield path

    claude_projects = home / ".claude" / "projects"
    if claude_projects.is_dir():
        try:
            for path in claude_projects.rglob("*.jsonl"):
                yield from _emit(path)
        except OSError:
            pass

    for sub in ("sessions", "archived_sessions"):
        root = home / ".codex" / sub
        if not root.is_dir():
            continue
        try:
            for path in root.rglob("rollout-*.jsonl"):
                yield from _emit(path)
        except OSError:
            pass

    copilot_state = home / ".copilot" / "session-state"
    if copilot_state.is_dir():
        try:
            for path in copilot_state.glob("*/events.jsonl"):
                yield from _emit(path)
        except OSError:
            pass


def _inline_findings(
    path: Path,
    text: str,
    *,
    scope: str,
    kind: str,
    high_reason: str,
    possible_reason: str,
) -> list[Finding]:
    """Split content hits into high vs possible findings. Never includes values."""
    likely_names, possible_names, prefix, bearer_possible = scan_text_hits(text)
    if path.suffix.lower() == ".md":
        # Assignment-only hits in docs are not likely; prefix hits still count.
        for name in likely_names:
            if name.upper() not in {n.upper() for n in possible_names}:
                possible_names.append(name)
        likely_names = []

    out: list[Finding] = []
    if likely_names or prefix:
        count = len(likely_names) if likely_names else 1
        reason = high_reason
        if prefix and not likely_names:
            reason = f"inline credential-shaped token ({prefix})"
        elif prefix and likely_names:
            reason = f"assignment + {prefix}"
        out.append(
            Finding(
                path=str(path),
                kind=kind,
                secret_names=likely_names,
                secret_count=count,
                reason=reason,
                importable=False,
                scope=scope,
                confidence="high",
            )
        )
    if possible_names or bearer_possible:
        names = possible_names
        count = len(names) if names else 1
        out.append(
            Finding(
                path=str(path),
                kind=kind,
                secret_names=names,
                secret_count=count,
                reason=possible_reason,
                importable=False,
                scope=scope,
                confidence="possible",
            )
        )
    return out


def _findings_for_transcript(path: Path, *, scope: str) -> list[Finding]:
    """Scan one JSONL session transcript; names/paths/line hits only."""
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size > _MAX_TRANSCRIPT_BYTES:
        return []

    high_lines: list[int] = []
    possible_lines: list[int] = []
    high_names: list[str] = []
    possible_names: list[str] = []
    seen_high: set[str] = set()
    seen_possible: set[str] = set()

    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, raw in enumerate(fh, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                likely, possible, prefix, bearer_possible = _scan_transcript_payload(
                    obj
                )
                high = bool(likely or prefix)
                poss = bool(possible or bearer_possible)
                if not high and not poss:
                    continue
                if high:
                    high_lines.append(line_no)
                    for name in likely:
                        key = name.upper()
                        if key in seen_high:
                            continue
                        seen_high.add(key)
                        high_names.append(name)
                elif poss:
                    possible_lines.append(line_no)
                    for name in possible:
                        key = name.upper()
                        if key in seen_possible or key in seen_high:
                            continue
                        seen_possible.add(key)
                        possible_names.append(name)
    except OSError:
        return []

    out: list[Finding] = []
    if high_lines:
        out.append(
            Finding(
                path=str(path),
                kind="agent_session_transcript",
                secret_names=high_names,
                secret_count=len(high_lines),
                reason=(
                    f"agent session transcript: {len(high_lines)} line(s) with "
                    "high-confidence credential-shaped content (advisory; false "
                    "positives/negatives expected)"
                ),
                importable=False,
                scope=scope,
                hit_lines=high_lines,
                confidence="high",
            )
        )
    if possible_lines:
        out.append(
            Finding(
                path=str(path),
                kind="agent_session_transcript",
                secret_names=possible_names,
                secret_count=len(possible_lines),
                reason=(
                    f"agent session transcript: {len(possible_lines)} line(s) with "
                    "possible identifier- or passphrase-shaped content"
                ),
                importable=False,
                scope=scope,
                hit_lines=possible_lines,
                confidence="possible",
            )
        )
    return out


def _findings_for_path(path: Path, *, scope: str) -> list[Finding]:
    kind = _filename_kind(path)
    if kind == "dotenv":
        finding = _dotenv_finding(path, scope=scope)
        return [] if finding is None else [finding]

    if kind is not None:
        names: list[str] = []
        count = 1
        reason = f"sensitive filename ({kind})"
        if kind == "credentials.json":
            names = _json_key_names(path)
            count = max(len(names), 1)
            reason = f"credentials.json ({count} top-level key name(s))"
        elif kind == "mcp_config":
            names = _json_key_names(path)
            count = max(len(names), 1)
            reason = f"MCP config ({count} top-level key name(s))"
        elif kind in (".npmrc", ".pypirc"):
            reason = f"{kind} (may contain registry auth tokens)"
        elif kind == "ssh_private_key":
            reason = "SSH private key file"
        elif kind == "shell_history":
            text = _safe_read_text(path)
            if not text:
                return []
            return _inline_findings(
                path,
                text,
                scope=scope,
                kind=kind,
                high_reason="shell history with credential-shaped content",
                possible_reason=(
                    "shell history with possible identifier- or "
                    "passphrase-shaped content"
                ),
            )
        elif kind == "git_config":
            text = _safe_read_text(path) or ""
            if not re.search(
                r"(?i)(token|password|authorization|_authToken)\s*=", text
            ) and "://" not in text:
                if not re.search(r"https?://[^/\s:]+:[^/\s]+@", text):
                    return []
            reason = "git config may embed credentials"
        return [
            Finding(
                path=str(path),
                kind=kind,
                secret_names=names,
                secret_count=count,
                reason=reason,
                importable=False,
                scope=scope,
                confidence="high",
            )
        ]

    suffix = path.suffix.lower()
    if suffix not in _CONTENT_SCAN_SUFFIXES and path.name not in {
        "Dockerfile",
        "Makefile",
        "Jenkinsfile",
    }:
        return []
    text = _safe_read_text(path)
    if not text:
        return []
    return _inline_findings(
        path,
        text,
        scope=scope,
        kind="inline",
        high_reason="assignment pattern matching secret-guard vocabulary",
        possible_reason="possible identifier- or passphrase-shaped assignment",
    )


def _should_skip_dir(name: str, *, include_excluded: bool) -> bool:
    if include_excluded:
        # Still never walk into .amnesia vault storage.
        return name == ".amnesia"
    return name in DEFAULT_EXCLUDE_DIR_NAMES or name.endswith(".egg-info")


def iter_project_files(
    root: Path,
    *,
    include_excluded: bool = False,
) -> Iterable[Path]:
    """Yield files under ``root``, honouring default exclusions."""
    root = root.resolve()
    if not root.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        # Prune in place so os.walk does not descend.
        dirnames[:] = sorted(
            d
            for d in dirnames
            if not _should_skip_dir(d, include_excluded=include_excluded)
        )
        for fname in filenames:
            if any(fname.endswith(suf) for suf in _SKIP_SUFFIXES):
                continue
            yield Path(dirpath) / fname


def scan_project(
    root: Path,
    *,
    include_excluded: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for path in iter_project_files(root, include_excluded=include_excluded):
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        key = str(path)
        try:
            key = str(path.resolve())
        except OSError:
            pass
        if key in seen:
            continue
        seen.add(key)
        for finding in _findings_for_path(path, scope="project"):
            if (
                finding.kind == "dotenv"
                and finding.secret_count == 0
                and not finding.secret_names
            ):
                continue
            findings.append(finding)
    findings.sort(key=lambda f: (f.path, f.confidence))
    return findings


def _deep_candidate_paths(home: Path | None = None) -> list[Path]:
    home = (home or Path.home()).resolve()
    candidates: list[Path] = []

    # Dotfiles / known secret homes.
    for name in (
        ".env",
        ".env.local",
        ".npmrc",
        ".pypirc",
        ".gitconfig",
        ".git-credentials",
        ".bash_history",
        ".zsh_history",
        ".zhistory",
        ".python_history",
        ".node_repl_history",
    ):
        candidates.append(home / name)

    ssh = home / ".ssh"
    for key_name in _SSH_PRIVATE_NAMES:
        candidates.append(ssh / key_name)

    # MCP / agent configs (Cursor, Claude Desktop).
    candidates.extend(
        [
            home / ".cursor" / "mcp.json",
            home / ".claude" / "mcp.json",
            home / ".config" / "claude" / "claude_desktop_config.json",
            home / ".config" / "Cursor" / "User" / "mcp.json",
        ]
    )
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.extend(
            [
                Path(appdata) / "Claude" / "claude_desktop_config.json",
                Path(appdata) / "Cursor" / "User" / "mcp.json",
            ]
        )
    # PowerShell history (Windows).
    if appdata:
        candidates.append(
            Path(appdata)
            / "Microsoft"
            / "Windows"
            / "PowerShell"
            / "PSReadLine"
            / "ConsoleHost_history.txt"
        )

    return candidates


def scan_deep(home: Path | None = None) -> list[Finding]:
    """Scan known home / shell / MCP / agent-transcript locations.

    Not a full home tree walk — fixed candidates plus known transcript globs.
    """
    findings: list[Finding] = []
    seen: set[str] = set()
    for path in _deep_candidate_paths(home):
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        key = str(path)
        try:
            key = str(path.resolve())
        except OSError:
            pass
        if key in seen:
            continue
        seen.add(key)
        for finding in _findings_for_path(path, scope="deep"):
            if (
                finding.kind == "dotenv"
                and finding.secret_count == 0
                and not finding.secret_names
            ):
                continue
            findings.append(finding)

    for path in iter_agent_transcript_files(home):
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if key in seen:
            continue
        seen.add(key)
        for finding in _findings_for_transcript(path, scope="deep"):
            seen.add(finding.path)
            findings.append(finding)

    findings.sort(key=lambda f: (f.path, f.confidence))
    return findings


def leak_count(findings: list[Finding]) -> int:
    return sum(
        max(f.secret_count, 0) for f in findings if f.confidence == "high"
    )


def possible_count(findings: list[Finding]) -> int:
    return sum(
        max(f.secret_count, 0) for f in findings if f.confidence == "possible"
    )


def transcript_line_hit_count(findings: list[Finding]) -> int:
    """Sum of high-confidence LEAK line-hits in transcript findings."""
    return sum(
        max(f.secret_count, 0)
        for f in findings
        if f.kind == "agent_session_transcript" and f.confidence == "high"
    )


def headline(findings: list[Finding], *, project_label: str = "this project") -> str:
    n = leak_count(findings)
    unit = "LEAK" if n == 1 else "LEAKs"
    return (
        f"{n} high-confidence {unit} found — your agent can read {n} secret"
        f"{'' if n == 1 else 's'} in {project_label} "
        f"(LEAK = Locally Exposed Agent Keys)"
    )


def _possible_note(findings: list[Finding]) -> str | None:
    p = possible_count(findings)
    if p == 0:
        return None
    unit = "hit" if p == 1 else "hits"
    return (
        f"{p} possible identifier- or passphrase-shaped {unit} not counted; "
        f"--fail-on possible to gate on them"
    )


def findings_to_json(findings: list[Finding], *, project_root: str) -> dict[str, Any]:
    n = leak_count(findings)
    transcript_hits = transcript_line_hit_count(findings)
    return {
        "leak_count": n,
        "possible_count": possible_count(findings),
        "transcript_line_hits": transcript_hits,
        "headline": headline(findings),
        "project_root": project_root,
        "findings": [asdict(f) for f in findings],
        "detection_note": (
            "Advisory heuristics; leak_count is high-confidence only "
            "(likely / prefix / filename). possible_count is identifier- or "
            "passphrase-shaped. Values are never included."
        ),
    }


def _format_hit_lines(hit_lines: list[int]) -> str:
    if not hit_lines:
        return ""
    if len(hit_lines) <= _HIT_LINES_DISPLAY_CAP:
        shown = ", ".join(str(n) for n in hit_lines)
        return f"\n      lines: {shown}"
    head = hit_lines[:_HIT_LINES_DISPLAY_CAP]
    rest = len(hit_lines) - _HIT_LINES_DISPLAY_CAP
    shown = ", ".join(str(n) for n in head)
    return f"\n      lines: {shown} (and {rest} more; see --json)"


def format_human_report(
    findings: list[Finding],
    *,
    project_root: Path,
    show_possible: bool = False,
) -> str:
    lines: list[str] = [headline(findings), ""]
    note = _possible_note(findings)
    if note:
        lines.append(note)
        lines.append("")
    transcript_hits = transcript_line_hit_count(findings)
    if transcript_hits:
        unit = "LEAK" if transcript_hits == 1 else "LEAKs"
        lines.append(
            f"{transcript_hits} {unit} found in agent session transcripts "
            f"(line-hits; advisory detection)"
        )
        lines.append("")
    listed = [
        f
        for f in findings
        if f.confidence == "high" or (show_possible and f.confidence == "possible")
    ]
    if not listed:
        if possible_count(findings) and not show_possible:
            lines.append(
                "No high-confidence locally exposed agent keys found under "
                "default exclusions. Use --show-possible to list identifier- "
                "or passphrase-shaped hits."
            )
        else:
            lines.append(
                "No locally exposed agent keys found under default exclusions."
            )
        return "\n".join(lines)
    lines.append(f"Project root: {project_root}")
    lines.append("")
    for i, f in enumerate(listed, start=1):
        names = ", ".join(f.secret_names) if f.secret_names else "(filename/presence)"
        lines.append(
            f"  [{i}] {f.path}"
            f"\n      kind={f.kind}  count={f.secret_count}  "
            f"scope={f.scope}  confidence={f.confidence}"
            f"\n      names: {names}"
            f"\n      {f.reason}"
            + ("  [importable]" if f.importable else "")
            + _format_hit_lines(f.hit_lines)
        )
        lines.append("")
    lines.append(
        "Values are never shown. Store importable dotenv findings with the "
        "post-scan offer, or run `ka import FILE`."
    )
    lines.append(
        "Detection is advisory; false positives and false negatives are "
        "expected. Word-shaped passphrases appear under possible, not the "
        "headline count."
    )
    return "\n".join(lines)


def importable_findings(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.importable and f.secret_count > 0]
