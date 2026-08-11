"""``ka scan`` — LEAK (Locally Exposed Agent Keys) discovery.

Walks a project tree (and optionally ``--deep`` home/shell/MCP locations
plus known agent session transcript JSONL trees) looking for plaintext
secret *files* and light assignment / prefix patterns. Reports **names,
paths, counts, and (for transcripts) line numbers only** — never prints,
logs, or copies secret values.

Detection is **advisory** regex + entropy heuristics (same vocabulary as
the secret-guard hook): false positives and false negatives are expected.
Policy classification: Scan LEAK report is **advisory** (not cryptography).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from key_amnesia.dotenv_import import parse_dotenv
from key_amnesia.hooks.secret_guard import (
    _ASSIGN,
    _BEARER,
    _PREFIX_PATTERNS,
    _assignment_is_secret,
    _collect_strings,
)

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


def _content_assignment_names(text: str) -> list[str]:
    """Reuse hook assignment vocabulary; return matched *names* only."""
    names: list[str] = []
    seen: set[str] = set()
    for match in _ASSIGN.finditer(text):
        value = match.group("value")
        if not _assignment_is_secret(value):
            continue
        name = match.group("name")
        key = name.upper()
        if key in seen:
            continue
        seen.add(key)
        names.append(name)
    return names


def _content_prefix_hit(text: str) -> str | None:
    for kind, pattern in _PREFIX_PATTERNS:
        if pattern.search(text):
            return kind
    if _BEARER.search(text):
        return "Bearer token"
    return None


def scan_text_for_leaks(text: str) -> tuple[list[str], str | None]:
    """Shared detector: assignment *names* + optional prefix/Bearer kind.

    Never returns secret values. Same vocabulary as the secret-guard hook.
    """
    if not text:
        return [], None
    return _content_assignment_names(text), _content_prefix_hit(text)


def _looks_like_json_container(s: str) -> bool:
    t = s.lstrip()
    return t.startswith("{") or t.startswith("[")


def _strings_from_decoded_json(obj: Any) -> list[str]:
    """Collect strings from a decoded JSON value; unwrap one nested JSON string."""
    out: list[str] = []
    for s in _collect_strings(obj):
        out.append(s)
        if not _looks_like_json_container(s):
            continue
        try:
            nested = json.loads(s)
        except json.JSONDecodeError:
            continue
        if isinstance(nested, (dict, list)):
            out.extend(_collect_strings(nested))
    return out


def _scan_transcript_payload(obj: Any) -> tuple[list[str], str | None]:
    """Run detectors on all string payloads from one JSONL line object."""
    names: list[str] = []
    seen: set[str] = set()
    prefix: str | None = None
    for s in _strings_from_decoded_json(obj):
        line_names, line_prefix = scan_text_for_leaks(s)
        for name in line_names:
            key = name.upper()
            if key in seen:
                continue
            seen.add(key)
            names.append(name)
        if line_prefix and prefix is None:
            prefix = line_prefix
    return names, prefix


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


def _finding_for_transcript(path: Path, *, scope: str) -> Finding | None:
    """Scan one JSONL session transcript; names/paths/line hits only."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > _MAX_TRANSCRIPT_BYTES:
        return None

    hit_lines: list[int] = []
    all_names: list[str] = []
    seen_names: set[str] = set()

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
                names, prefix = _scan_transcript_payload(obj)
                if not names and not prefix:
                    continue
                hit_lines.append(line_no)
                for name in names:
                    key = name.upper()
                    if key in seen_names:
                        continue
                    seen_names.add(key)
                    all_names.append(name)
    except OSError:
        return None

    if not hit_lines:
        return None

    return Finding(
        path=str(path),
        kind="agent_session_transcript",
        secret_names=all_names,
        secret_count=len(hit_lines),
        reason=(
            f"agent session transcript: {len(hit_lines)} line(s) with "
            "credential-shaped content (advisory regex+entropy; false "
            "positives/negatives expected)"
        ),
        importable=False,
        scope=scope,
        hit_lines=hit_lines,
    )


def _finding_for_path(path: Path, *, scope: str) -> Finding | None:
    kind = _filename_kind(path)
    if kind == "dotenv":
        return _dotenv_finding(path, scope=scope)

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
            # Presence alone is a LEAK; don't parse auth tokens into names.
            reason = f"{kind} (may contain registry auth tokens)"
        elif kind == "ssh_private_key":
            reason = "SSH private key file"
        elif kind == "shell_history":
            text = _safe_read_text(path)
            if text:
                prefix = _content_prefix_hit(text)
                assigns = _content_assignment_names(text)
                if prefix or assigns:
                    names = assigns
                    count = max(len(assigns), 1 if prefix else 0)
                    reason = "shell history with credential-shaped content"
                else:
                    return None  # empty/harmless history — not a LEAK
            else:
                return None
        elif kind == "git_config":
            text = _safe_read_text(path) or ""
            # Only flag if it looks like it embeds a token (url with @, etc.)
            if not re.search(
                r"(?i)(token|password|authorization|_authToken)\s*=", text
            ) and "://" not in text:
                # Still check for github token-ish in https URLs
                if not re.search(r"https?://[^/\s:]+:[^/\s]+@", text):
                    return None
            reason = "git config may embed credentials"
        return Finding(
            path=str(path),
            kind=kind,
            secret_names=names,
            secret_count=count,
            reason=reason,
            importable=False,
            scope=scope,
        )

    # Light content scan for assignment / well-known prefixes.
    suffix = path.suffix.lower()
    if suffix not in _CONTENT_SCAN_SUFFIXES and path.name not in {
        "Dockerfile",
        "Makefile",
        "Jenkinsfile",
    }:
        return None
    text = _safe_read_text(path)
    if not text:
        return None
    names, prefix = scan_text_for_leaks(text)
    if not names and not prefix:
        return None
    count = len(names) if names else 1
    reason = (
        f"inline credential-shaped token ({prefix})"
        if prefix and not names
        else "assignment pattern matching secret-guard vocabulary"
    )
    if prefix and names:
        reason = f"assignment + {prefix}"
    return Finding(
        path=str(path),
        kind="inline",
        secret_names=names,
        secret_count=count,
        reason=reason,
        importable=False,
        scope=scope,
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
        finding = _finding_for_path(path, scope="project")
        if finding is None:
            continue
        # Skip comment-only / empty dotenv files (no LEAK secrets to report).
        if (
            finding.kind == "dotenv"
            and finding.secret_count == 0
            and not finding.secret_names
        ):
            continue
        if finding.path in seen:
            continue
        seen.add(finding.path)
        findings.append(finding)
    findings.sort(key=lambda f: f.path)
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
        finding = _finding_for_path(path, scope="deep")
        if finding is None:
            continue
        if finding.kind == "dotenv" and finding.secret_count == 0 and not finding.secret_names:
            continue
        if finding.path in seen:
            continue
        seen.add(finding.path)
        findings.append(finding)

    for path in iter_agent_transcript_files(home):
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if key in seen:
            continue
        finding = _finding_for_transcript(path, scope="deep")
        if finding is None:
            continue
        seen.add(finding.path)
        # Also mark resolved key so candidate-path overlap cannot double-count.
        seen.add(key)
        findings.append(finding)

    findings.sort(key=lambda f: f.path)
    return findings


def leak_count(findings: list[Finding]) -> int:
    return sum(max(f.secret_count, 0) for f in findings)


def transcript_line_hit_count(findings: list[Finding]) -> int:
    """Sum of LEAK line-hits in ``agent_session_transcript`` findings."""
    return sum(
        max(f.secret_count, 0)
        for f in findings
        if f.kind == "agent_session_transcript"
    )


def headline(findings: list[Finding], *, project_label: str = "this project") -> str:
    n = leak_count(findings)
    unit = "LEAK" if n == 1 else "LEAKs"
    return (
        f"{n} {unit} found — your agent can read {n} secret"
        f"{'' if n == 1 else 's'} in {project_label} "
        f"(LEAK = Locally Exposed Agent Keys)"
    )


def findings_to_json(findings: list[Finding], *, project_root: str) -> dict[str, Any]:
    n = leak_count(findings)
    transcript_hits = transcript_line_hit_count(findings)
    return {
        "leak_count": n,
        "transcript_line_hits": transcript_hits,
        "headline": headline(findings),
        "project_root": project_root,
        "findings": [asdict(f) for f in findings],
        "detection_note": (
            "Advisory regex+entropy heuristics (secret-guard vocabulary); "
            "false positives and false negatives are expected. "
            "Values are never included."
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


def format_human_report(findings: list[Finding], *, project_root: Path) -> str:
    lines: list[str] = [headline(findings), ""]
    transcript_hits = transcript_line_hit_count(findings)
    if transcript_hits:
        unit = "LEAK" if transcript_hits == 1 else "LEAKs"
        lines.append(
            f"{transcript_hits} {unit} found in agent session transcripts "
            f"(line-hits; advisory detection)"
        )
        lines.append("")
    if not findings:
        lines.append("No locally exposed agent keys found under default exclusions.")
        return "\n".join(lines)
    lines.append(f"Project root: {project_root}")
    lines.append("")
    for i, f in enumerate(findings, start=1):
        names = ", ".join(f.secret_names) if f.secret_names else "(filename/presence)"
        lines.append(
            f"  [{i}] {f.path}"
            f"\n      kind={f.kind}  count={f.secret_count}  scope={f.scope}"
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
        "Detection is advisory (regex + entropy heuristics); false positives "
        "and false negatives are expected."
    )
    return "\n".join(lines)


def importable_findings(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.importable and f.secret_count > 0]
