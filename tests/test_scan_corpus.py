"""Labeled scan corpus: before-measurement, tiers, and ka scan exit paths.

Never asserts on secret *values* except to confirm they are absent from
captured output. Generated likely values live only under pytest tmp.
"""

from __future__ import annotations

import json
import math
import re
import shutil
from collections import Counter
from pathlib import Path

import pytest

from key_amnesia.cli import main
from key_amnesia.detect import (
    NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE,
    NAMED_WEAKENINGS,
    classify_value,
    find_prefix_kind,
    find_secret_kind,
    scan_text_hits,
)
from key_amnesia.hooks import secret_guard as sg
from key_amnesia.scan import leak_count, possible_count, scan_project

CORPUS = Path(__file__).resolve().parent / "fixtures" / "scan_corpus"
NEGATIVES = CORPUS / "negatives"
DEMOTED = CORPUS / "demoted"
POSITIVES = CORPUS / "positives"

# Generated at test time only — not committed. Shapes match 0.4.9 hook fixtures.
_GEN_MIXED = "aB3xQ9mK2pL7vN4wZ8"
_GEN_MIXED_B = "Zk9pL2xQ7mN4vB8w"
_GEN_HEX32 = "a1b2c3d4e5f6789012345678abcdef01"
_GEN_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
_GEN_URLSAFE = "A7xQ2mK9pL4vN8wZ1bC3dE5fG6hJ0kL"
_GEN_VALUES = (_GEN_MIXED, _GEN_MIXED_B, _GEN_HEX32, _GEN_JWT, _GEN_URLSAFE)

DEMOTED_TO_WEAKENING = {
    "passphrase_correct_horse_battery.py": NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE,
}

# 0.4.9 assignment heuristic — before-measurement only.
_LEGACY_ASSIGN = re.compile(
    r"""(?ix)
    (?P<name>(?:[a-z0-9]+[_-])*(?:api[_-]?key|token|secret|password|passwd|private[_-]?key))
    \s*[:=]\s*
    (?P<q>['"]?)
    (?P<value>[^\s'"]{8,})
    (?P=q)
    """
)
_LEGACY_PLACEHOLDERS = {
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


def _iter_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file() and p.name != "README.md")


def _legacy_entropy(s: str) -> float:
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _legacy_assignment_is_secret(value: str) -> bool:
    v = value.strip("'\"")
    if len(v) < 8:
        return False
    low = v.lower()
    if low in _LEGACY_PLACEHOLDERS:
        return False
    if re.fullmatch(r"x{6,}", low) or re.fullmatch(r"0{6,}|1{6,}", low):
        return False
    mixed = sum(
        [
            any(c.isupper() for c in v),
            any(c.islower() for c in v),
            any(c.isdigit() for c in v),
        ]
    ) >= 2
    if not mixed:
        return False
    return _legacy_entropy(v) >= 3.0


def _legacy_flags(text: str) -> bool:
    if re.search(r"\bBearer\s+[A-Za-z0-9._\-+=/]{16,}", text, re.I):
        return True
    for match in _LEGACY_ASSIGN.finditer(text):
        if _legacy_assignment_is_secret(match.group("value")):
            return True
    return False


def _file_has_likely_or_prefix(text: str) -> bool:
    if find_prefix_kind(text):
        return True
    likely, _possible, prefix, _bp = scan_text_hits(text)
    return bool(likely or prefix)


def _assert_no_gen_values(blob: str) -> None:
    for value in _GEN_VALUES:
        assert value not in blob
    assert "CorrectHorseBattery" not in blob


def test_before_measurement_legacy_over_blocks_negatives() -> None:
    """0.4.9 assignment heuristic flagged function-call / identifier shapes."""
    flagged = [
        path.name
        for path in _iter_files(NEGATIVES)
        if _legacy_flags(path.read_text(encoding="utf-8"))
    ]
    assert flagged, "before-measurement expected 0.4.9 to over-block some negatives"
    assert "function_call_secrets.py" in flagged
    assert "camelcase_identifier.py" in flagged
    assert "type_annotation.py" in flagged


@pytest.mark.parametrize("path", _iter_files(NEGATIVES), ids=lambda p: p.name)
def test_negatives_not_likely_or_prefix(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert not _file_has_likely_or_prefix(text)


@pytest.mark.parametrize("path", _iter_files(DEMOTED), ids=lambda p: p.name)
def test_demoted_is_possible_and_named(path: Path) -> None:
    assert path.name in DEMOTED_TO_WEAKENING
    assert DEMOTED_TO_WEAKENING[path.name] in NAMED_WEAKENINGS
    text = path.read_text(encoding="utf-8")
    likely, possible, prefix, bearer_possible = scan_text_hits(text)
    assert prefix is None
    assert not likely
    assert possible or bearer_possible
    assert classify_value("CorrectHorseBattery") == "possible"
    assert find_secret_kind(text) is not None


def test_demoted_files_all_mapped() -> None:
    names = {p.name for p in _iter_files(DEMOTED)}
    assert names == set(DEMOTED_TO_WEAKENING)


@pytest.mark.parametrize("path", _iter_files(POSITIVES), ids=lambda p: p.name)
def test_on_disk_positives_are_prefix(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert find_prefix_kind(text) is not None


def test_generated_likely_values_classify_likely() -> None:
    for value in _GEN_VALUES:
        assert classify_value(value) == "likely", value[:4]


def test_negatives_only_tmp_scan_zero(ka_home, tmp_path, monkeypatch, capsys) -> None:
    tree = tmp_path / "neg"
    shutil.copytree(NEGATIVES, tree)
    monkeypatch.chdir(tree)
    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out or "{}")
    assert rc == 0
    assert data.get("leak_count", 0) == 0
    _assert_no_gen_values(captured.out + captured.err)


def test_demoted_only_tmp_scan_exit_paths(
    ka_home, tmp_path, monkeypatch, capsys
) -> None:
    tree = tmp_path / "dem"
    shutil.copytree(DEMOTED, tree)
    monkeypatch.chdir(tree)

    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert rc == 0
    assert data["leak_count"] == 0
    assert data["possible_count"] > 0
    assert all(f["confidence"] in ("high", "possible") for f in data["findings"])
    _assert_no_gen_values(captured.out + captured.err)

    rc = main(["scan", "--no-import", "--fail-on", "high"])
    capsys.readouterr()
    assert rc == 0

    rc = main(["scan", "--no-import", "--fail-on", "possible"])
    captured = capsys.readouterr()
    assert rc == 1
    _assert_no_gen_values(captured.out + captured.err)

    rc = main(["scan", "--no-import", "--show-possible"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "possible" in captured.out.lower()
    _assert_no_gen_values(captured.out + captured.err)


def test_high_confidence_tree_exits_1_both_fail_on(
    ka_home, tmp_path, monkeypatch, capsys
) -> None:
    tree = tmp_path / "high"
    tree.mkdir()
    (tree / "config.py").write_text(f'api_key = "{_GEN_MIXED}"\n', encoding="utf-8")
    monkeypatch.chdir(tree)

    rc = main(["scan", "--no-import", "--fail-on", "high", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert rc == 1
    assert data["leak_count"] >= 1
    _assert_no_gen_values(captured.out + captured.err)

    rc = main(["scan", "--no-import", "--fail-on", "possible"])
    captured = capsys.readouterr()
    assert rc == 1
    _assert_no_gen_values(captured.out + captured.err)


def test_fail_on_invalid_exits_2(ka_home) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--no-import", "--fail-on", "nope"])
    assert exc.value.code == 2


def test_generated_likely_in_env_json_yaml_toml_export(
    ka_home, tmp_path, monkeypatch, capsys
) -> None:
    tree = tmp_path / "gen"
    tree.mkdir()
    (tree / ".env").write_text(f"API_KEY={_GEN_MIXED}\n", encoding="utf-8")
    (tree / "config.json").write_text(
        json.dumps({"api_key": _GEN_MIXED_B}), encoding="utf-8"
    )
    (tree / "config.yaml").write_text(f"api_key: {_GEN_HEX32}\n", encoding="utf-8")
    (tree / "config.toml").write_text(f'api_key = "{_GEN_JWT}"\n', encoding="utf-8")
    (tree / "quoted.toml").write_text(
        f'"api_key" = "{_GEN_URLSAFE}"\n', encoding="utf-8"
    )
    (tree / "export.sh").write_text(f"export TOKEN={_GEN_MIXED}\n", encoding="utf-8")
    monkeypatch.chdir(tree)

    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert rc == 1
    assert data["leak_count"] >= 1
    kinds_or_names = json.dumps(data)
    assert "api_key" in kinds_or_names.lower() or "API_KEY" in kinds_or_names
    _assert_no_gen_values(captured.out + captured.err)

    findings = scan_project(tree)
    assert leak_count(findings) >= 1
    paths = {Path(f.path).name for f in findings if f.confidence == "high"}
    assert ".env" in paths
    assert "config.json" in paths
    assert "config.yaml" in paths
    assert "config.toml" in paths
    assert "quoted.toml" in paths
    assert "export.sh" in paths


def test_md_assignment_not_likely_prefix_still_high(
    ka_home, tmp_path, monkeypatch, capsys
) -> None:
    tree = tmp_path / "docs"
    tree.mkdir()
    (tree / "notes.md").write_text(f'api_key = "{_GEN_MIXED}"\n', encoding="utf-8")
    monkeypatch.chdir(tree)
    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["leak_count"] == 0
    assert data["possible_count"] >= 1
    assert rc == 0
    _assert_no_gen_values(captured.out + captured.err)

    (tree / "readme.md").write_text("sk-" + "a" * 25 + "\n", encoding="utf-8")
    rc = main(["scan", "--no-import", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["leak_count"] >= 1
    assert rc == 1


def test_bearer_identifier_hook_denies_scan_not_leak(ka_home, tmp_path) -> None:
    text = "Authorization: Bearer someVariableName"
    assert sg.find_finding(text) == "Bearer token"
    tree = tmp_path / "b"
    tree.mkdir()
    (tree / "hdr.txt").write_text(text + "\n", encoding="utf-8")
    findings = scan_project(tree)
    assert leak_count(findings) == 0
    assert possible_count(findings) >= 1


def test_product_diff_has_no_new_network_imports() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "key_amnesia"
    banned = ("urllib.request", "urllib3", "requests", "http.client", "aiohttp")
    for path in (
        root / "detect.py",
        root / "scan.py",
        root / "hooks" / "secret_guard.py",
    ):
        text = path.read_text(encoding="utf-8")
        for name in banned:
            assert name not in text
