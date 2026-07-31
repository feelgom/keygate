"""Admission-consent layer on top of the guard's authkey trust boundary.

A live authkey alone lets any same-user process talk to the guard (the
ssh-agent-style limit documented in DESIGN.md). Admission adds a UX/consent
gate on top, bound to the connecting process's **kernel-verified identity**
(`peer_identity.PeerIdentity`) rather than a bearer credential: the first
request from an unrecognized process tree is a yes/no prompt on the guard's
own foreground TTY; approval binds admission to that identity (and its real
OS descendants) for the rest of this guard run, scoped to whichever secrets
were actually granted.

These tests exercise `_check_admission`'s kernel-identity path by passing a
`peer=PeerIdentity(...)` kwarg to `guard_handle_message`, exactly as
`guard_serve` does in production. Legacy in-memory opaque-token behavior
is covered separately in `test_guard_admission_legacy.py` via
`guard_handle_message_legacy`.
"""

from __future__ import annotations

import sys
import time

from key_amnesia.guard import (
    AdmittedSession,
    GuardState,
    guard_handle_message,
)
from key_amnesia.peer_identity import PeerIdentity

PEER = PeerIdentity(pid=4242, start_time=1000)
OTHER_PEER = PeerIdentity(pid=9999, start_time=2000)


def _state(**overrides) -> GuardState:
    kwargs = dict(
        secrets={"api_key": "super-secret-value-123"},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"m" * 32,
    )
    kwargs.update(overrides)
    return GuardState(**kwargs)


def _admitted(peer: PeerIdentity, **overrides) -> AdmittedSession:
    kwargs = dict(
        identities=[peer],
        first_seen="2026-01-01T00:00:00+00:00",
        granted_secrets=set(),
        unscoped=True,
        granted_until=time.time() + 600,
    )
    kwargs.update(overrides)
    return AdmittedSession(**kwargs)


def test_unrecognized_peer_prompts_and_admits(ka_home) -> None:
    state = _state()
    calls: list[tuple[PeerIdentity, str]] = []

    def approve(caller: PeerIdentity, summary: str) -> bool:
        calls.append((caller, summary))
        return True

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=PEER, admit_prompt=approve
    )
    assert reply["ok"] is True
    assert reply["names"] == ["api_key"]
    assert "admission_token" not in reply  # nothing minted on this path
    assert calls == [(PEER, "list secret names")]
    assert state.admitted is not None
    assert state.admitted.identities == [PEER]
    assert state.admitted.request_count == 1


def test_unrecognized_peer_denies_on_no(ka_home) -> None:
    state = _state()
    reply = guard_handle_message(
        {"verb": "list"},
        state,
        peer=PEER,
        admit_prompt=lambda caller, summary: False,
    )
    assert reply["ok"] is False
    assert reply["reason"] == "admission denied"
    assert state.admitted is None


def test_unrecognized_peer_denies_on_timeout(monkeypatch, ka_home) -> None:
    """A real (unmocked) prompt that never answers must fail closed quickly."""
    state = _state()
    monkeypatch.setattr("key_amnesia.guard.ADMISSION_TIMEOUT_S", 0.2)
    monkeypatch.setattr("builtins.input", lambda *a, **k: (time.sleep(5), "y")[1])

    start = time.monotonic()
    reply = guard_handle_message({"verb": "list"}, state, peer=PEER)
    elapsed = time.monotonic() - start

    assert reply["ok"] is False
    assert reply["reason"] == "admission denied"
    assert elapsed < 3  # bounded by ADMISSION_TIMEOUT_S, not the 5s hang


def test_unavailable_peer_identity_fails_closed(ka_home) -> None:
    """`peer=None` means a real kernel lookup was attempted and failed — this
    must never be treated as "no peer info supplied" (the legacy fallback)."""
    state = _state()

    def fail_if_called(*_a, **_k):
        raise AssertionError("must never prompt for an unverifiable peer")

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=None, admit_prompt=fail_if_called
    )
    assert reply["ok"] is False
    assert reply["reason"] == "admission denied"
    assert state.admitted is None


def test_admitted_peer_skips_prompt_no_reprompt(ka_home) -> None:
    state = _state()
    state.admitted = _admitted(PEER)

    def fail_if_called(*_a, **_k):
        raise AssertionError("admit_prompt must not be called for an admitted peer")

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=PEER, admit_prompt=fail_if_called
    )
    assert reply["ok"] is True
    assert state.admitted.request_count == 1


def test_descendant_of_admitted_peer_is_silently_in_tree(monkeypatch, ka_home) -> None:
    """A real OS descendant of the admitted process is recognized without a
    prompt (see `peer_identity.is_in_admitted_tree`) — mock the ancestor
    walk rather than spawning a real child process (covered by the E2E
    security tests in `test_peer_identity_e2e.py`)."""
    state = _state()
    state.admitted = _admitted(PEER)
    child = PeerIdentity(pid=5555, start_time=3000)
    monkeypatch.setattr(
        "key_amnesia.peer_identity.get_ancestor_chain",
        lambda pid, max_depth=32: [child, PEER],
    )

    def fail_if_called(*_a, **_k):
        raise AssertionError("descendant of admitted peer must not reprompt")

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=child, admit_prompt=fail_if_called
    )
    assert reply["ok"] is True


def test_unrelated_peer_is_not_in_tree_and_reprompts(ka_home) -> None:
    """A peer sharing no OS ancestry with the admitted process is treated as
    a fresh, unrecognized peer — never silently admitted."""
    state = _state()
    state.admitted = _admitted(PEER)
    calls = {"n": 0}

    def approve(*_a, **_k):
        calls["n"] += 1
        return True

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=OTHER_PEER, admit_prompt=approve
    )
    assert reply["ok"] is True
    assert calls["n"] == 1
    assert state.admitted.identities == [OTHER_PEER]  # grant now bound to the new peer


def test_secret_scoped_grant_allows_granted_secret_without_reprompt(ka_home) -> None:
    state = _state(secrets={"api_key": "v1", "db_pass": "v2"})
    state.admitted = _admitted(PEER, granted_secrets={"api_key"}, unscoped=False)

    def fail_if_called(*_a, **_k):
        raise AssertionError("must not reprompt for an already-granted secret")

    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": ["api_key"],
            "command": [sys.executable, "-c", "print('ok')"],
        },
        state,
        peer=PEER,
        admit_prompt=fail_if_called,
    )
    assert reply["ok"] is True


def test_secret_scoped_grant_reprompts_for_ungranted_secret(ka_home) -> None:
    state = _state(secrets={"api_key": "v1", "db_pass": "v2"})
    state.admitted = _admitted(PEER, granted_secrets={"api_key"}, unscoped=False)
    calls = {"n": 0}

    def approve(*_a, **_k):
        calls["n"] += 1
        return True

    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": ["db_pass"],
            "command": [sys.executable, "-c", "print('ok')"],
        },
        state,
        peer=PEER,
        admit_prompt=approve,
    )
    assert reply["ok"] is True
    assert calls["n"] == 1
    # Scope expanded to include the newly-approved secret, old grant retained.
    assert state.admitted.granted_secrets == {"api_key", "db_pass"}


def test_secret_scoped_grant_denies_on_no_for_ungranted_secret(ka_home) -> None:
    state = _state(secrets={"api_key": "v1", "db_pass": "v2"})
    state.admitted = _admitted(PEER, granted_secrets={"api_key"}, unscoped=False)

    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": ["db_pass"],
            "command": [sys.executable, "-c", "print('ok')"],
        },
        state,
        peer=PEER,
        admit_prompt=lambda *a, **k: False,
    )
    assert reply["ok"] is False
    assert reply["reason"] == "admission denied"
    # Old grant untouched by the rejected expansion attempt.
    assert state.admitted.granted_secrets == {"api_key"}


def test_unscoped_admission_allows_any_secret_without_reprompt(ka_home) -> None:
    state = _state(secrets={"api_key": "v1", "db_pass": "v2"})
    state.admitted = _admitted(PEER, unscoped=True)

    def fail_if_called(*_a, **_k):
        raise AssertionError("unscoped (pre-admit ALL) grant must never reprompt")

    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": ["db_pass"],
            "command": [sys.executable, "-c", "print('ok')"],
        },
        state,
        peer=PEER,
        admit_prompt=fail_if_called,
    )
    assert reply["ok"] is True


def test_pre_admit_consumes_window_for_next_unrecognized_peer(ka_home) -> None:
    state = _state()
    state.pre_admit_until = time.time() + 60
    state.pre_admit_unscoped = True

    def fail_if_called(*_a, **_k):
        raise AssertionError("a pre-admitted peer must not be prompted")

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=PEER, admit_prompt=fail_if_called
    )
    assert reply["ok"] is True
    assert state.admitted is not None
    assert state.admitted.unscoped is True
    # Single-use: consumed regardless of the window's remaining time.
    assert state.pre_admit_until is None


def test_pre_admit_scoped_to_specific_secrets(ka_home) -> None:
    state = _state(secrets={"api_key": "v1", "db_pass": "v2"})
    state.pre_admit_until = time.time() + 60
    state.pre_admit_unscoped = False
    state.pre_admit_secrets = {"api_key"}

    def fail_if_called(*_a, **_k):
        raise AssertionError("pre-admitted scope must not reprompt for its own secret")

    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": ["api_key"],
            "command": [sys.executable, "-c", "print('ok')"],
        },
        state,
        peer=PEER,
        admit_prompt=fail_if_called,
    )
    assert reply["ok"] is True
    assert state.admitted.granted_secrets == {"api_key"}
    assert state.admitted.unscoped is False


def test_pre_admit_expired_window_falls_back_to_prompt(ka_home) -> None:
    state = _state()
    state.pre_admit_until = time.time() - 1  # already expired
    state.pre_admit_unscoped = True
    calls = {"n": 0}

    def approve(*_a, **_k):
        calls["n"] += 1
        return True

    reply = guard_handle_message(
        {"verb": "list"}, state, peer=PEER, admit_prompt=approve
    )
    assert reply["ok"] is True
    assert calls["n"] == 1


def test_status_reports_admission_state(ka_home) -> None:
    state = _state()
    state.admitted = _admitted(PEER, request_count=3)
    reply = guard_handle_message({"verb": "status"}, state, peer=PEER)
    assert reply["ok"] is True
    assert reply["admitted"] is True
    assert reply["admitted_since"] == "2026-01-01T00:00:00+00:00"
    assert reply["admitted_pids"] == [PEER.pid]
    assert reply["request_count"] == 4  # incremented by this very request


def test_status_reports_pre_admit_pending(ka_home) -> None:
    """`_dispatch_verb` reply shape while pre-admit is armed but not yet
    consumed — dispatched directly (below `_check_admission`) since *any*
    real request from an unrecognized peer would immediately consume the
    single-use pre-admit window before ever reaching this reply."""
    from key_amnesia.guard import _dispatch_verb

    state = _state()
    state.pre_admit_until = time.time() + 60
    state.pre_admit_unscoped = True
    reply = _dispatch_verb("status", {"verb": "status"}, state)
    assert reply["ok"] is True
    assert reply["pre_admit_pending"] is True
    assert reply["pre_admit_scope"] == "ALL (unscoped pre-admit)"
