"""Tests for `ka import`: dotenv -> vault merge, collisions, delete/rename,
the .gitignore offer, and minimal amnesia.toml generation.

Uses the shared `ka_home` / `seeded_vault` fixtures (throwaway
KEY_AMNESIA_HOME) plus a separate `project_dir` for the cwd-relative
`.gitignore` / `amnesia.toml` side effects.
"""

from __future__ import annotations

import getpass
from pathlib import Path

import pytest

from key_amnesia.cli import main
from key_amnesia.vault import load_vault


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    proj = tmp_path / "project"
    proj.mkdir()
    monkeypatch.chdir(proj)
    return proj


def _write_env(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_import_requires_tty(ka_home, project_dir, monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    env_file = _write_env(project_dir / ".env", "A=1\n")

    rc = main(["import", str(env_file)])
    err = capsys.readouterr().err

    assert rc == 1
    assert "interactive terminal" in err


def test_import_file_not_found(seeded_vault, project_dir, monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    rc = main(["import", str(project_dir / "missing.env")])
    err = capsys.readouterr().err

    assert rc == 1
    assert "not found" in err.lower()


def test_import_no_vault_refuses(ka_home, project_dir, monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    env_file = _write_env(project_dir / ".env", "A=1\n")

    rc = main(["import", str(env_file)])
    err = capsys.readouterr().err

    assert rc == 1
    assert "ka init" in err


def test_import_empty_file_is_a_noop(seeded_vault, project_dir, monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    env_file = _write_env(project_dir / ".env", "# nothing here\n")

    rc = main(["import", str(env_file)])
    out = capsys.readouterr().out

    assert rc == 0
    assert "No KEY=VALUE entries" in out
    assert env_file.exists()


def test_import_happy_path_writes_secrets_manifest_and_gitignore(
    seeded_vault, password, project_dir, monkeypatch, capsys
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)
    env_file = _write_env(
        project_dir / ".env", "NEW_SECRET=super-value\nANOTHER=another-value\n"
    )
    # Order asked: delete? -> no; rename? -> no; gitignore? -> yes.
    answers = iter(["n", "n", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    rc = main(["import", str(env_file)])
    out = capsys.readouterr().out
    assert rc == 0

    payload = load_vault(seeded_vault, password)
    assert payload["secrets"]["NEW_SECRET"] == "super-value"
    assert payload["secrets"]["ANOTHER"] == "another-value"
    # Pre-existing secrets untouched.
    assert payload["secrets"]["api_key"] == "super-secret-value-123"

    # Never printed to this terminal.
    assert "super-value" not in out
    assert "another-value" not in out

    manifest = project_dir / "amnesia.toml"
    assert manifest.exists()
    text = manifest.read_text(encoding="utf-8")
    assert 'env = "NEW_SECRET"' in text
    assert 'env = "ANOTHER"' in text
    assert "required = true" in text

    gitignore = project_dir / ".gitignore"
    assert gitignore.exists()
    assert ".env*" in gitignore.read_text(encoding="utf-8").splitlines()

    # Declined both delete and rename -> file stays put.
    assert env_file.exists()


def test_import_collision_default_skip_keeps_old_value(
    seeded_vault, password, project_dir, monkeypatch, capsys
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)
    env_file = _write_env(project_dir / ".env", "api_key=attempted-overwrite\n")
    # Collision prompt -> blank answer -> default (skip). No import happens,
    # so no further prompts are made.
    answers = iter([""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    rc = main(["import", str(env_file)])
    out = capsys.readouterr().out
    assert rc == 0

    payload = load_vault(seeded_vault, password)
    assert payload["secrets"]["api_key"] == "super-secret-value-123"
    assert "Skipped" in out
    assert "attempted-overwrite" not in out
    assert not (project_dir / "amnesia.toml").exists()
    assert env_file.exists()


def test_import_collision_overwrite_when_confirmed(
    seeded_vault, password, project_dir, monkeypatch
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)
    env_file = _write_env(project_dir / ".env", "api_key=new-value\n")
    # Collision -> yes (overwrite); delete? no; rename? no; gitignore? no.
    answers = iter(["y", "n", "n", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    rc = main(["import", str(env_file)])
    assert rc == 0

    payload = load_vault(seeded_vault, password)
    assert payload["secrets"]["api_key"] == "new-value"


def test_import_delete_confirmed_removes_source(
    seeded_vault, password, project_dir, monkeypatch
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)
    env_file = _write_env(project_dir / ".env", "FRESH=value\n")
    # delete? yes; double-confirm? yes; gitignore? no.
    answers = iter(["y", "y", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    rc = main(["import", str(env_file)])
    assert rc == 0
    assert not env_file.exists()


def test_import_delete_declined_second_confirm_keeps_file(
    seeded_vault, password, project_dir, monkeypatch
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)
    env_file = _write_env(project_dir / ".env", "FRESH=value\n")
    # delete? yes; double-confirm? NO (backs out) -> file kept, no rename asked;
    # gitignore? no.
    answers = iter(["y", "n", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    rc = main(["import", str(env_file)])
    assert rc == 0
    assert env_file.exists()


def test_import_rename_when_delete_declined(
    seeded_vault, password, project_dir, monkeypatch
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)
    env_file = _write_env(project_dir / ".env", "FRESH=value\n")
    # delete? no; rename? yes; gitignore? no.
    answers = iter(["n", "y", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    rc = main(["import", str(env_file)])
    assert rc == 0
    assert not env_file.exists()
    assert (project_dir / ".env.imported").exists()
    assert (project_dir / ".env.imported").read_text(encoding="utf-8") == "FRESH=value\n"


def test_import_never_prints_secret_value_to_own_terminal(
    seeded_vault, password, project_dir, monkeypatch, capsys
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)
    env_file = _write_env(project_dir / ".env", "BRAND_NEW=very-secret-value-here\n")
    answers = iter(["y", "y", "n"])  # delete + confirm, gitignore no
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    rc = main(["import", str(env_file)])
    captured = capsys.readouterr()

    assert rc == 0
    assert "very-secret-value-here" not in captured.out
    assert "very-secret-value-here" not in captured.err


def test_import_wrong_password_denied(
    seeded_vault, project_dir, monkeypatch, capsys
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "totally-wrong-password")
    env_file = _write_env(project_dir / ".env", "A=1\n")

    rc = main(["import", str(env_file)])
    err = capsys.readouterr().err

    assert rc == 1
    assert env_file.exists()
    assert "A=1" not in err
