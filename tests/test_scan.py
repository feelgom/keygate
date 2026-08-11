"""PR5: ka scan LEAK discovery + offer-to-import into project vault.

Always uses throwaway KEY_AMNESIA_HOME via `ka_home` — never the
maintainer's real vault. Never asserts on secret *values* in stdout/err
except to confirm they are absent.
"""

from __future__ import annotations

import getpass
import json
from pathlib import Path

import pytest

from key_amnesia import vault as vault_mod
from key_amnesia.cli import main
from key_amnesia.project import ensure_project_scaffold, project_vault_path
from key_amnesia.scan import (
    DEFAULT_EXCLUDE_DIR_NAMES,
    Finding,
    headline,
    importable_findings,
    iter_agent_transcript_files,
    leak_count,
    scan_deep,
    scan_project,
    transcript_line_hit_count,
)


SECRET_VALUE = "super-secret-value-NEVER-PRINT-me"
SECRET_VALUE_2 = "another-leak-value-XYZ9"


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    proj = tmp_path / "project"
    proj.mkdir()
    monkeypatch.chdir(proj)
    return proj


def test_scan_finds_dotenv_names_not_values(ka_home, project_dir, capsys) -> None:
    (project_dir / ".env").write_text(
        f"API_KEY={SECRET_VALUE}\nDB_PASS={SECRET_VALUE_2}\n",
        encoding="utf-8",
    )

    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert rc == 1
    assert data["leak_count"] == 2
    assert "LEAK" in data["headline"]
    assert SECRET_VALUE not in captured.out
    assert SECRET_VALUE_2 not in captured.out
    assert SECRET_VALUE not in captured.err

    paths = [f["path"] for f in data["findings"]]
    assert any(p.endswith(".env") for p in paths)
    names = data["findings"][0]["secret_names"]
    assert "API_KEY" in names
    assert "DB_PASS" in names


def test_scan_clean_tree_exits_zero(ka_home, project_dir, capsys) -> None:
    (project_dir / "README.md").write_text("# hello\n", encoding="utf-8")

    rc = main(["scan", "--no-import"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "0 LEAK" in out or "0 LEAKs" in out


def test_scan_excludes_node_modules_and_venv_by_default(
    ka_home, project_dir
) -> None:
    (project_dir / "node_modules").mkdir()
    (project_dir / "node_modules" / ".env").write_text(
        f"HIDDEN={SECRET_VALUE}\n", encoding="utf-8"
    )
    (project_dir / ".venv").mkdir()
    (project_dir / ".venv" / ".env").write_text(
        f"HIDDEN2={SECRET_VALUE}\n", encoding="utf-8"
    )
    (project_dir / "build").mkdir()
    (project_dir / "build" / ".env").write_text(
        f"HIDDEN3={SECRET_VALUE}\n", encoding="utf-8"
    )
    (project_dir / ".git").mkdir()
    (project_dir / ".git" / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n", encoding="utf-8"
    )

    findings = scan_project(project_dir)
    assert findings == []
    assert "node_modules" in DEFAULT_EXCLUDE_DIR_NAMES
    assert ".git" in DEFAULT_EXCLUDE_DIR_NAMES


def test_scan_include_excluded_finds_nested_dotenv(
    ka_home, project_dir, capsys
) -> None:
    nm = project_dir / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / ".env").write_text(f"NESTED={SECRET_VALUE}\n", encoding="utf-8")

    rc = main(["scan", "--include-excluded", "--no-import", "--json"])
    data = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert data["leak_count"] == 1
    assert any("node_modules" in f["path"] for f in data["findings"])
    assert SECRET_VALUE not in json.dumps(data)


def test_scan_detects_sensitive_filenames(ka_home, project_dir) -> None:
    (project_dir / "credentials.json").write_text(
        '{"aws_key": "AKIA", "token": "x"}\n', encoding="utf-8"
    )
    (project_dir / ".npmrc").write_text("//registry.npmjs.org/:_authToken=npm_x\n", encoding="utf-8")
    (project_dir / ".pypirc").write_text("[pypi]\npassword = x\n", encoding="utf-8")
    (project_dir / "id_rsa").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
    (project_dir / "id_ed25519").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
    mcp = project_dir / ".cursor"
    mcp.mkdir()
    (mcp / "mcp.json").write_text('{"mcpServers": {}}\n', encoding="utf-8")

    findings = scan_project(project_dir)
    kinds = {f.kind for f in findings}
    assert "credentials.json" in kinds
    assert ".npmrc" in kinds
    assert ".pypirc" in kinds
    assert "ssh_private_key" in kinds
    assert "mcp_config" in kinds
    assert leak_count(findings) >= 5


def test_scan_assignment_pattern_names_only(ka_home, project_dir, capsys) -> None:
    # High-entropy mixed value so the hook heuristic fires.
    (project_dir / "config.py").write_text(
        'api_key = "AbCdEfGh12345678XyZ"\n',
        encoding="utf-8",
    )

    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert rc == 1
    assert data["leak_count"] >= 1
    assert "AbCdEfGh12345678XyZ" not in captured.out
    inline = [f for f in data["findings"] if f["kind"] == "inline"]
    assert inline
    assert "api_key" in inline[0]["secret_names"]


def test_scan_headline_wording() -> None:
    findings = [
        Finding(
            path="/tmp/.env",
            kind="dotenv",
            secret_names=["A", "B"],
            secret_count=2,
            reason="test",
            importable=True,
        )
    ]
    text = headline(findings)
    assert text.startswith("2 LEAKs found")
    assert "your agent can read 2 secrets" in text
    assert "Locally Exposed Agent Keys" in text


def test_scan_deep_home_paths(ka_home, tmp_path, monkeypatch) -> None:
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    (home / ".env").write_text(f"HOME_KEY={SECRET_VALUE}\n", encoding="utf-8")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("PRIVATE\n", encoding="utf-8")

    findings = scan_deep(home)
    assert any(f.kind == "dotenv" for f in findings)
    assert any(f.kind == "ssh_private_key" for f in findings)
    blob = json.dumps([f.__dict__ for f in findings])
    assert SECRET_VALUE not in blob


def test_scan_cli_deep_flag(ka_home, project_dir, tmp_path, monkeypatch, capsys) -> None:
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    (home / ".npmrc").write_text("_authToken=npm_xxx\n", encoding="utf-8")

    rc = main(["scan", "--deep", "--no-import", "--json"])
    data = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert any(f["scope"] == "deep" for f in data["findings"])


def test_scan_import_yes_into_project_vault(
    ka_home, password, project_dir, monkeypatch, capsys
) -> None:
    ensure_project_scaffold(project_dir)
    vp = project_vault_path(project_dir)
    vault_mod.save_vault(
        vp,
        password,
        {
            "secrets": {},
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )
    (project_dir / ".env").write_text(
        f"SCANNED={SECRET_VALUE}\nOTHER={SECRET_VALUE_2}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)

    rc = main(["scan", "--yes"])
    captured = capsys.readouterr()

    assert rc == 1  # still LEAK until sources cleaned; we keep files with --yes
    assert SECRET_VALUE not in captured.out
    assert SECRET_VALUE_2 not in captured.out

    payload = vault_mod.load_vault(vp, password)
    assert payload["secrets"]["SCANNED"] == SECRET_VALUE
    assert payload["secrets"]["OTHER"] == SECRET_VALUE_2
    assert (project_dir / ".env").exists()  # --yes skips delete
    assert (project_dir / "amnesia.toml").exists()


def test_scan_import_partial_selection(
    ka_home, password, project_dir, monkeypatch
) -> None:
    ensure_project_scaffold(project_dir)
    vp = project_vault_path(project_dir)
    vault_mod.save_vault(
        vp,
        password,
        {
            "secrets": {},
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )
    (project_dir / ".env").write_text(f"ONE={SECRET_VALUE}\n", encoding="utf-8")
    (project_dir / ".env.local").write_text(
        f"TWO={SECRET_VALUE_2}\n", encoding="utf-8"
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)
    # Offer? yes; selection "1"; delete? no; rename? no; gitignore? no.
    answers = iter(["y", "1", "n", "n", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    rc = main(["scan"])
    assert rc == 1

    payload = vault_mod.load_vault(vp, password)
    assert "ONE" in payload["secrets"]
    assert "TWO" not in payload["secrets"]


def test_scan_creates_project_vault_when_missing(
    ka_home, password, project_dir, monkeypatch
) -> None:
    (project_dir / ".env").write_text(f"FRESH={SECRET_VALUE}\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    # New vault: master + confirm; then --yes path uses getpass for existing...
    # With --yes and no vault: _prompt_new_master_password uses getpass twice.
    pw_answers = iter([password, password])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(pw_answers))

    rc = main(["scan", "--yes"])
    assert rc == 1

    vp = project_vault_path(project_dir)
    assert vp.exists()
    payload = vault_mod.load_vault(vp, password)
    assert payload["secrets"]["FRESH"] == SECRET_VALUE
    assert (project_dir / ".amnesia").is_dir()


def test_importable_findings_filters() -> None:
    findings = [
        Finding("a", "dotenv", ["A"], 1, "", True),
        Finding("b", "dotenv", [], 0, "", False),
        Finding("c", ".npmrc", [], 1, "", False),
    ]
    imp = importable_findings(findings)
    assert len(imp) == 1
    assert imp[0].path == "a"


def test_scan_never_prints_values_human_report(
    ka_home, project_dir, capsys
) -> None:
    (project_dir / ".env").write_text(
        f"TOKEN={SECRET_VALUE}\n", encoding="utf-8"
    )
    rc = main(["scan", "--no-import"])
    captured = capsys.readouterr()
    assert rc == 1
    assert "TOKEN" in captured.out
    assert SECRET_VALUE not in captured.out
    assert SECRET_VALUE not in captured.err


# --- Agent session transcript scan (--deep) ---

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "agent_transcripts"

# Planted fake secrets in fixtures — must never appear in scan output.
_TRANSCRIPT_PLANTED = (
    "sk-ant-FAKESECRET_for_tests_only_xx",
    "AbCdEfGh12345678XyZ",
    "FAKEBEARERTOKEN123456",
    "sk-proj-NOTAREALKEY_but_long_enough_abc",
    "npm_abcdefghijklmnopqrstuv",
)


def _assert_no_planted(blob: str) -> None:
    for secret in _TRANSCRIPT_PLANTED:
        assert secret not in blob


def _install_transcript_home(home: Path) -> dict[str, Path]:
    """Lay out Claude / Codex / Copilot transcript trees under fake home."""
    claude_proj = home / ".claude" / "projects" / "C--tmp-demo"
    claude_proj.mkdir(parents=True)
    session = claude_proj / "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.jsonl"
    session.write_text(
        (_FIXTURES / "claude" / "session-with-leaks.jsonl").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    clean = claude_proj / "ffffffff-1111-2222-3333-444444444444.jsonl"
    clean.write_text(
        (_FIXTURES / "claude" / "session-clean.jsonl").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    sub = (
        claude_proj
        / "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        / "subagents"
        / "agent-deadbeef.jsonl"
    )
    sub.parent.mkdir(parents=True)
    sub.write_text(
        (_FIXTURES / "claude" / "subagent-with-leak.jsonl").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )

    codex_day = home / ".codex" / "sessions" / "2026" / "01" / "01"
    codex_day.mkdir(parents=True)
    codex = codex_day / "rollout-with-leak.jsonl"
    codex.write_text(
        (_FIXTURES / "codex" / "rollout-with-leak.jsonl").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )

    copilot = home / ".copilot" / "session-state" / "sess-1" / "events.jsonl"
    copilot.parent.mkdir(parents=True)
    copilot.write_text(
        (_FIXTURES / "copilot" / "events-with-leak.jsonl").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )

    return {
        "claude_session": session,
        "claude_clean": clean,
        "claude_subagent": sub,
        "codex": codex,
        "copilot": copilot,
    }


def test_scan_deep_agent_transcripts_line_hits(
    ka_home, tmp_path, monkeypatch
) -> None:
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    paths = _install_transcript_home(home)

    findings = scan_deep(home)
    transcripts = [f for f in findings if f.kind == "agent_session_transcript"]

    session_f = next(f for f in transcripts if Path(f.path) == paths["claude_session"])
    # Lines 3 (sk-ant) and 5 (nested API_KEY JSON string).
    assert session_f.hit_lines == [3, 5]
    assert session_f.secret_count == 2
    assert session_f.scope == "deep"
    assert any(n.upper() == "API_KEY" for n in session_f.secret_names)

    assert not any(Path(f.path) == paths["claude_clean"] for f in transcripts)

    sub_f = next(f for f in transcripts if Path(f.path) == paths["claude_subagent"])
    assert sub_f.hit_lines == [1]
    assert sub_f.secret_count == 1

    codex_f = next(f for f in transcripts if Path(f.path) == paths["codex"])
    assert codex_f.secret_count >= 1
    assert 1 in codex_f.hit_lines

    copilot_f = next(f for f in transcripts if Path(f.path) == paths["copilot"])
    assert copilot_f.hit_lines == [1]

    assert transcript_line_hit_count(findings) == sum(
        f.secret_count for f in transcripts
    )
    blob = json.dumps([f.__dict__ for f in findings])
    _assert_no_planted(blob)


def test_scan_default_skips_home_transcripts(
    ka_home, project_dir, tmp_path, monkeypatch
) -> None:
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    _install_transcript_home(home)

    findings = scan_project(project_dir)
    assert not any(f.kind == "agent_session_transcript" for f in findings)


def test_scan_cli_deep_transcripts_no_values(
    ka_home, project_dir, tmp_path, monkeypatch, capsys
) -> None:
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    _install_transcript_home(home)

    rc = main(["scan", "--deep", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert rc == 1
    assert data["transcript_line_hits"] >= 4
    assert any(f["kind"] == "agent_session_transcript" for f in data["findings"])
    assert "advisory" in data["detection_note"].lower()
    _assert_no_planted(captured.out)
    _assert_no_planted(captured.err)
    _assert_no_planted(json.dumps(data))

    human_rc = main(["scan", "--deep", "--no-import"])
    human = capsys.readouterr().out
    assert human_rc == 1
    assert "agent session transcripts" in human
    assert "advisory" in human.lower()
    _assert_no_planted(human)


def test_iter_agent_transcript_files_globs(tmp_path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    paths = _install_transcript_home(home)
    found = {p.resolve() for p in iter_agent_transcript_files(home)}
    assert paths["claude_session"].resolve() in found
    assert paths["claude_subagent"].resolve() in found
    assert paths["codex"].resolve() in found
    assert paths["copilot"].resolve() in found
    assert paths["claude_clean"].resolve() in found  # present on disk; clean has no LEAK
