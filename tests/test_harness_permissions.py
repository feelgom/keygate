"""Harness permission merge: Claude / Cursor / Codex, manifest, hook-missing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from key_amnesia.harness_permissions import (
    VALUE_EMIT_VERBS,
    claude_allow_matchers,
    claude_deny_matchers,
    cursor_allow_prefixes,
    deny_in_allow_conflicts,
    dump_json,
    load_json_object_strict,
    merge_string_list,
    prepare_claude,
    prepare_cursor,
    prepare_codex,
    run_permissions,
)
from key_amnesia.paths import permissions_manifest_path
from key_amnesia.setup_cmd import (
    CLAUDE_MATCHER,
    _hook_command,
    _merge_claude_settings,
    _merge_cursor_hooks,
    cmd_setup,
)


def _ns(**kwargs):
    import argparse

    defaults = {
        "skills_only": False,
        "hook_only": False,
        "permissions_only": False,
        "permissions_remove": False,
        "yes": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _claude_with_hook(home: Path, extra: dict | None = None) -> Path:
    path = home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    _merge_claude_settings(path)
    if extra:
        data = json.loads(path.read_text(encoding="utf-8"))
        data.update(extra)
        path.write_text(dump_json(data), encoding="utf-8")
    return path


def test_value_emit_never_in_file_allow() -> None:
    blob = "\n".join(claude_allow_matchers() + cursor_allow_prefixes())
    for verb in VALUE_EMIT_VERBS:
        assert f" {verb}" not in blob
        assert f" {verb}:*" not in blob


def test_claude_skip_missing_home(tmp_path: Path) -> None:
    out = prepare_claude(tmp_path, {"rules": {}})
    assert out.ok
    assert not out.changes
    assert "absent" in out.lines[0]


def test_claude_fail_closed_malformed(tmp_path: Path) -> None:
    claude = tmp_path / ".claude"
    claude.mkdir()
    path = claude / "settings.json"
    path.write_text("{ not json", encoding="utf-8")
    out = prepare_claude(tmp_path, {"rules": {}})
    assert not out.ok
    assert not out.changes
    assert any("fail closed" in ln for ln in out.lines)


def test_claude_merge_permissions_and_automode(tmp_path: Path) -> None:
    path = _claude_with_hook(
        tmp_path,
        extra={
            "autoMode": {
                "environment": {"Z_KEEP": "1", "A_KEEP": "2"},
                "allow": ["Bash(echo:*)"],
            },
            "unrelated": True,
        },
    )
    env_before = list(
        json.loads(path.read_text(encoding="utf-8"))["autoMode"]["environment"]
    )
    rc = run_permissions(
        tmp_path,
        yes=True,
        may_install_hook=False,
        install_hook_fn=None,
        tty=False,
    )
    assert rc == 0
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["unrelated"] is True
    assert list(data["autoMode"]["environment"]) == env_before
    assert "Bash(echo:*)" in data["autoMode"]["allow"]
    assert any(x.startswith("Bash(ka run:*)") for x in data["permissions"]["allow"])
    assert any(x.startswith("PowerShell(ka run:*)") for x in data["permissions"]["allow"])
    assert any(" — key-amnesia" in x for x in data["autoMode"]["allow"])
    assert any(x.startswith("Bash(ka set:*)") for x in data["permissions"]["deny"])
    assert not any("ka reveal" in x for x in data["permissions"]["allow"])


def test_second_write_byte_identical(tmp_path: Path) -> None:
    _claude_with_hook(tmp_path)
    run_permissions(tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False)
    path = tmp_path / ".claude" / "settings.json"
    first = path.read_bytes()
    run_permissions(tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False)
    assert path.read_bytes() == first


def test_manifest_drift_drops_stale_not_user(tmp_path: Path) -> None:
    path = _claude_with_hook(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["permissions"] = {
        "allow": ["Bash(user-own:*)", "Bash(ka stale:*)"],
        "deny": [],
    }
    path.write_text(dump_json(data), encoding="utf-8")
    manifest = {
        "version": 1,
        "rules": {"claude.permissions.allow": ["Bash(ka stale:*)"]},
    }
    permissions_manifest_path().write_text(dump_json(manifest), encoding="utf-8")
    rc = run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert rc == 0
    allow = json.loads(path.read_text(encoding="utf-8"))["permissions"]["allow"]
    assert "Bash(user-own:*)" in allow
    assert "Bash(ka stale:*)" not in allow
    assert any(x.startswith("Bash(ka run:*)") for x in allow)


def test_deny_in_allow_loud_not_deleted_with_yes(tmp_path: Path, capsys) -> None:
    conflict = "Bash(ka set:*) in the SpookyOwl repo"
    path = _claude_with_hook(
        tmp_path,
        extra={"autoMode": {"allow": [conflict], "environment": {"X": "1"}}},
    )
    rc = run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert conflict in err
    data = json.loads(path.read_text(encoding="utf-8"))
    assert conflict in data["autoMode"]["allow"]


def test_permissions_only_missing_hook_no_silent_write(tmp_path: Path, capsys) -> None:
    claude = tmp_path / ".claude"
    claude.mkdir()
    path = claude / "settings.json"
    path.write_text(dump_json({"hooks": {}}), encoding="utf-8")
    rc = run_permissions(
        tmp_path,
        yes=True,
        may_install_hook=False,
        install_hook_fn=None,
        tty=False,
    )
    assert rc != 0
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "permissions" not in data
    out = capsys.readouterr()
    combined = out.out + out.err
    assert "hook" in combined.lower()
    assert "ka set" in combined.lower() or "without" in combined.lower()


def test_permissions_only_cli_missing_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        dump_json({"other": True}), encoding="utf-8"
    )
    rc = cmd_setup(_ns(permissions_only=True, yes=True))
    assert rc != 0
    data = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert "permissions" not in data


def test_cursor_never_creates_permissions_json(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    _merge_cursor_hooks(tmp_path / ".cursor" / "hooks.json")
    out = prepare_cursor(tmp_path, {"rules": {}})
    assert not (tmp_path / ".cursor" / "permissions.json").exists()
    assert not any(c.path.name == "permissions.json" for c in out.changes)
    assert any("not creating" in ln for ln in out.lines)


def test_cursor_appends_existing_allowlist(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    _merge_cursor_hooks(tmp_path / ".cursor" / "hooks.json")
    perm = tmp_path / ".cursor" / "permissions.json"
    perm.write_text(
        dump_json({"terminalAllowlist": ["git", "npm"]}),
        encoding="utf-8",
    )
    rc = run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert rc == 0
    data = json.loads(perm.read_text(encoding="utf-8"))
    assert "git" in data["terminalAllowlist"]
    assert "npm" in data["terminalAllowlist"]
    assert "ka run" in data["terminalAllowlist"]


def test_cursor_no_add_allowlist_key_uses_instructions(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    _merge_cursor_hooks(tmp_path / ".cursor" / "hooks.json")
    perm = tmp_path / ".cursor" / "permissions.json"
    perm.write_text(dump_json({"other": True}), encoding="utf-8")
    rc = run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert rc == 0
    data = json.loads(perm.read_text(encoding="utf-8"))
    assert "terminalAllowlist" not in data
    assert "block_instructions" not in data.get("autoRun", {})
    assert "ka run" in data["autoRun"]["allow_instructions"]


def test_cursor_cli_config_merge_only_if_schema_matches(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    _merge_cursor_hooks(tmp_path / ".cursor" / "hooks.json")
    cli = tmp_path / ".cursor" / "cli-config.json"
    cli.write_text(
        dump_json({"permissions": {"allow": ["Shell(ls)"]}}),
        encoding="utf-8",
    )
    rc = run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert rc == 0
    data = json.loads(cli.read_text(encoding="utf-8"))
    assert "Shell(ls)" in data["permissions"]["allow"]
    assert "ka run" in data["permissions"]["allow"]


def test_cursor_cli_config_never_created(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    _merge_cursor_hooks(tmp_path / ".cursor" / "hooks.json")
    run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    assert not (tmp_path / ".cursor" / "cli-config.json").exists()


def test_codex_print_only(tmp_path: Path, capsys) -> None:
    out = prepare_codex(tmp_path)
    assert not out.changes
    assert any("config.toml" in ln for ln in out.lines)
    assert any("/hooks" in ln for ln in out.lines)


def test_fail_closed_wrong_types(tmp_path: Path) -> None:
    path = _claude_with_hook(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["permissions"] = []
    path.write_text(dump_json(data), encoding="utf-8")
    out = prepare_claude(tmp_path, {"rules": {}})
    assert not out.ok
    assert not out.changes


def test_merge_string_list_types() -> None:
    merged, err = merge_string_list(["a"], ["b"], [])
    assert err is None
    assert merged == ["a", "b"]
    merged, err = merge_string_list([1], ["b"], [])  # type: ignore[list-item]
    assert err is not None


def test_deny_in_allow_prefix_match() -> None:
    hits = deny_in_allow_conflicts(
        ["Bash(ka set:*) in the SpookyOwl repo", "Bash(ka run:*)"]
    )
    assert hits == ["Bash(ka set:*) in the SpookyOwl repo"]


def test_load_json_strict_missing(tmp_path: Path) -> None:
    data, err = load_json_object_strict(tmp_path / "nope.json")
    assert data == {}
    assert err is None


def test_permissions_remove_only_manifested(tmp_path: Path) -> None:
    path = _claude_with_hook(tmp_path)
    run_permissions(
        tmp_path, yes=True, may_install_hook=False, install_hook_fn=None, tty=False
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    data["permissions"]["allow"].insert(0, "Bash(user-keep:*)")
    path.write_text(dump_json(data), encoding="utf-8")
    from key_amnesia.harness_permissions import remove_manifested_rules

    rc = remove_manifested_rules(tmp_path)
    assert rc == 0
    allow = json.loads(path.read_text(encoding="utf-8"))["permissions"]["allow"]
    assert "Bash(user-keep:*)" in allow
    assert not any(x.startswith("Bash(ka run:*)") for x in allow)


def test_claude_deny_matchers_omit_prompt_helper() -> None:
    blob = "\n".join(claude_deny_matchers())
    assert "_prompt-helper" not in blob
    assert "ka set:*" in blob or "ka set:*)" in blob


def test_hook_command_still_used() -> None:
    assert "key-amnesia" in _hook_command() or "secret_guard" in _hook_command()
    assert "Bash" in CLAUDE_MATCHER
