# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow the git tags `0.4.0` … `0.4.8`.

## [0.4.8] — 2026-08-11

### Added

- `ka scan --deep` walks known **agent session transcript** JSONL trees (Claude Code `~/.claude/projects/**/*.jsonl` including subagents; Codex `~/.codex/sessions|archived_sessions/**/rollout-*.jsonl`; Copilot CLI `~/.copilot/session-state/*/events.jsonl`). Reports path + line hits; never prints values. Detection remains advisory (regex+entropy; false positives/negatives expected).

## [0.4.7] — 2026-08-04

### Changed

- `--admit-tree` prompt labels each offered level by depth (`this client` / `parent` / `grandparent` / `ancestor ↑N`) so it is clear which choice is narrower vs wider trust up the process tree.

## [0.4.6] — 2026-08-04

### Fixed

- Spawned-console auth helper: single `Listener.accept` thread (restarting accept each second orphaned the connection → parent closed the pipe → helper `WinError 232`); connect to parent *before* running `ka run` commands; do not abort the wait on flaky `Popen.poll`; `parent_alive` fail-open only on access-denied (not missing PIDs).
- Helper always attempts an IPC status reply with a reason instead of silent exit (`helper exited without connecting`).

## [0.4.5] — 2026-08-04

### Security model

- Added opt-in `ka unlock --admit-tree`: at the first unrecognized-peer prompt, choose a kernel-verified ancestor as the admission root so its OS descendants (including later sibling CLI invocations under that parent) are in-tree for the session (`via=interactive-tree`). Off by default; no config/env; `--pre-admit` unchanged.
- Windows holds `OpenProcess` on the chosen root for the admission lifetime.
- Offer floors: max 8 ancestors; never the last 2 chain entries (connecting peer never floored out); never `pid <=` platform minimum; foreign-owned levels skipped.

### Fixed

- CI: import `conftest` without a `tests` package (`#48`).
- CI: POSIX failures from the pytest console-spawn guard (`#49`).

## [0.4.4] — 2026-08-03

### Fixed

- Suite isolation: `ka_home` autouse with fail-if-outside-tmp.
- Agent TTY routing: inline auth requires stdin **and** stdout TTY; `KEY_AMNESIA_NONINTERACTIVE` forces spawned-console.
- Guard visibility: `guard_request` audits IPC abandon as `warn`; structured `code` on replies; `ka run`/`list` print why the guard path was abandoned.

## [0.4.3] — 2026-08-02

### Added

- OpenAI Codex support in `ka setup`: skills under `~/.agents/skills/` and `~/.codex/skills/`; Codex `PreToolUse` hook (`Bash|Write|Edit|apply_patch`); secret-guard allows `apply_patch`.

## [0.4.2] — 2026-07-31

### Security model

- `migrate_kam1_to_kam2` requires `confirm=` unconditionally.
- Windows ancestor walk takes one `CreateToolhelp32Snapshot` per chain.
- `guard_handle_message` requires keyword-only `peer=`; legacy opaque-token path is tests-only (`guard_handle_message_legacy`).
- Linux `SO_PEERCRED` compares kernel uid to `os.geteuid()` and fails closed on mismatch.
- Optional `@pytest.mark.slow` for process-spawning tests.

## [0.4.1] — 2026-07-31

### Security model

- Windows connecting-peer `OpenProcess` HANDLE held on `PeerIdentity` for the admission lifetime (ancestor walks still open-read-close); `release()` on replace and foreground-guard teardown.
- README honesty on Windows vs Linux `SO_PEERCRED`, ancestry UX vs in-tree malware, and the residual GetNamedPipeClientProcessId→OpenProcess race.
- Legacy IPC display field renamed `caller_pid` → `claimed_pid_unverified`.

### Changed

- Usage skill: verify with `ka status` / `ka connect` before assuming vault access.

## [0.4.0] — 2026-07-31

### Added

- Experimental macOS PID-file isolated-console spawn (`open`/`osascript` lose the process handle; wrapper writes PID then `exec`s helper). Marked experimental until confirmed on a real Mac.
- CI matrix adds `macos-latest` (Python 3.10 / 3.13) alongside Windows and Ubuntu.

### Security model

- Kernel peer-identity admission on macOS remains fail-closed (unchanged). Other non-Win/Linux/Darwin platforms still fail closed.

[0.4.7]: https://github.com/fujitoid/key-amnesia/compare/0.4.6...0.4.7
[0.4.6]: https://github.com/fujitoid/key-amnesia/compare/0.4.5...0.4.6
[0.4.5]: https://github.com/fujitoid/key-amnesia/compare/0.4.4...0.4.5
[0.4.4]: https://github.com/fujitoid/key-amnesia/compare/0.4.3...0.4.4
[0.4.3]: https://github.com/fujitoid/key-amnesia/compare/0.4.2...0.4.3
[0.4.2]: https://github.com/fujitoid/key-amnesia/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/fujitoid/key-amnesia/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/fujitoid/key-amnesia/releases/tag/0.4.0
