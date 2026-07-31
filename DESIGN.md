# key-amnesia v3 — Design

Python prototype CLI (`key-amnesia` / `ka`) for Windows-primary use. Encrypted vault storage, Windows `CREATE_NEW_CONSOLE` human-prompt routing, a bounded-capability cached guard over named-pipe IPC (authkey only, plus an in-memory admission-consent layer), and buffer-then-scrub output redaction.

**0.3.0 cut:** browser-fill and the entire KeePassXC-Browser Native Messaging integration (`browser_fill.py`, `native_host.py`, `native_host_install.py`, `keepass_protocol.py`, `logins.py`, `login_cli.py`, `ka login`, `ka browser-fill`) are removed. `ka unlock` is no longer a detached child process — it *is* the guard, running in the caller's own foreground terminal. New: `ka passwd` / `ka change-password`, admission-consent prompting on the guard's own TTY, and honest death reporting (`last_guard_state.json`).

**0.3.1 (additive, no CLI-surface changes to `set`/`run`/`list`/`init`/`passwd`/`unlock`/`lock`/`status`/`renew`):** the three agent skills move from a root `skills/` copy into the installed package itself (`src/key_amnesia/skills/*/SKILL.md`, shipped as package data); a new blocking PreToolUse/preToolUse secret-guard hook module (`src/key_amnesia/hooks/secret_guard.py`, console script `key-amnesia-hook`) replaces the root `.claude/hooks/` copy; and a new non-interactive `ka setup` command (`src/key_amnesia/setup_cmd.py`) installs both into `~/.claude/` and `~/.cursor/` and merges each host's hook config idempotently.

**0.3.2 (bugfix + UX, no CLI-surface changes; first PyPI release):** fixed `ka set NAME VALUE` printing its raw value to the caller's own terminal (`PromptRequest.detail`/`mutation` split — see "Nothing sensitive on argv"); fixed the guard's extend-prompt and new periodic time-remaining reminder both silently skipping while idle (an idle guard sat inside `listener.accept()` for its whole remaining lifetime and never re-checked); `ka unlock`'s startup banner now shows expiry clock time and how to stop early; `ka status` shows time remaining; rebranded CLI palette from neon teal/amber to a restrained brushed-chrome/brass theme with dimmed secondary text and three new glyphs (🔓 ⏳ 💀). Also: dropped Git LFS for the README hero image (its hook self-install broke `pip install git+...` for anyone with `git-lfs` on PATH), added `pyproject.toml` PyPI metadata, added GitHub Actions CI, and published `key-amnesia` 0.3.2 to PyPI for the first time (`pip install key-amnesia` now works without a git URL).

**0.3.3 (bugfix, no CLI-surface changes):** `cmd_run`'s relay of scrubbed command output crashed with a raw `UnicodeEncodeError` on a console codepage (e.g. legacy Windows cp1252) that couldn't represent one of the command's own output characters — found live publishing 0.3.2 itself (twine's output tripped it, *after* the upload had already succeeded, hiding that success behind a traceback). Fixed with the same degrade-don't-crash rule `theme.py` already applies to its own output (`_write_command_output`, `test_cli_output_encoding.py`).

**0.3.7 (bugfix, no CLI-surface / no IPC-verb changes):** fixed the guard's stale in-memory secrets snapshot (README limit 9 / "Known limitation" below). `GuardState` gained `vault_path`, `vault_key` (derived SecretBox key only — never the password), and `vault_content_fingerprint`; `run`/`list`/`status` now call `_maybe_reload_secrets`, which re-opens the vault with the retained key (no Argon2id) whenever the fingerprint changes. `cmd_unlock` switched from `load_vault` to `load_vault_with_key` to obtain that key without deriving it twice; `vault.py` gained `load_vault_with_key`, `load_vault_with_retained_key`, and `vault_fingerprint`. Verb set is unchanged — still exactly `{run, list, lock, status, renew}`; no `reload` verb was added (`tests/test_guard_verbs_regression.py` untouched). New exposure: the guard now retains **derived key material** for the session (see "Who holds plaintext" and the note under GuardState below) — same trust tier as the plaintext secrets it already held, but worth naming explicitly. `tests/test_guard_reload.py`.

**0.3.10 (project vaults + guard registry; no IPC-verb changes):** walk-up discovery of `.amnesia/` from cwd (stops at home); per-env vault files under `.amnesia/envs/<name>/`; `.amnesia/config.json` `use_global` (default true) merges the global vault with project winning on name collision; CLI `--vault` / `--global` / `--no-global` / `--env`; `ka init --project [--env NAME]` scaffolds the tree and auto-gitignores `.amnesia/`; `ka import` / fresh-auth mutations target the resolved project vault when inside a project; `ka unlock` / `run` / `list` / `status` merge when configured (two independent password prompts when both vaults exist). Guard lock + `last_guard_state.json` sit beside the active vault; discovery-only registry at `~/.key-amnesia/guards/<hash>.json` (vault path, env, pid, expiry, address — **never** authkey). `GuardState.vault_sources` extends the 0.3.7 fingerprint reload so a merged unlock refreshes when *any* contributing vault file changes. Existing global vault: zero-action compatible. Verb set unchanged. `project.py`, `tests/test_project_vaults.py`.

**0.3.9 (opens the `.env`-replacement line; no IPC-verb changes; no vault-format/resolution changes):** new `ka import FILE` command plus a shared, reusable core (`dotenv_import.py`) that a later `ka scan` (roadmap) can call into for its own offer-to-import path. `ka import` parses a dotenv-format file and merges its `NAME=value` pairs into the currently-resolved vault (still the single global vault — per-project vaults land in a later PR); it is **TTY-only**, like `init`/`passwd` (never routed through the spawned-console helper — it reads the local file itself rather than having a human type each value, and drives several interactive-only decisions below). Name collisions with an existing secret **default to skip** and only overwrite on an explicit confirm. After a successful import it asks (never silently) whether to delete the source file — a "yes" is double-confirmed before anything is removed — or, if delete was declined, offers to rename it to `<name>.imported`; separately it also offers (never silently, and skipped entirely if a covering pattern already exists) adding `.env*` to `.gitignore`. Finally it generates or merges a minimal `amnesia.toml` in the current directory (one `[[secret]]` table per imported name: `name`, `required = true`, `description = ""`, `env`) — this manifest is inert until a later PR adds `ka check` / `ka run` enforcement; merging only appends blocks for names not already present, matched on their `env` field. Never prints a secret value at any point. `tests/test_dotenv_import.py`, `tests/test_import_cmd.py`.
**0.3.8 (admission model replaced; no IPC-verb changes; no new verb):** the admission-consent layer no longer trusts a message-supplied `caller_pid` or an opaque bearer token — it binds to the connecting process's **kernel-verified identity** instead (new `peer_identity.py`: `GetNamedPipeClientProcessId` + `OpenProcess`/`GetProcessTimes` on Windows, `SO_PEERCRED` + `/proc/<pid>/stat` on Linux; macOS/other fails closed). `admitted_session.token` is **gone** — there is no on-disk admission credential anymore; `guard_request` attaches nothing beyond an optional display-only `client_name`. Admission now also supports **secret-scoped grants** (a `run` naming a secret outside the admitted tree's current grant re-prompts to expand scope, rather than either a blanket allow or a blanket re-prompt-everything) and an opt-in, single-use, loud **`ka unlock --pre-admit [--pre-admit-secret NAME ...]`** (default window `pre-admit-seconds`, config default 900s / 15m) that auto-admits the very next unrecognized peer without a prompt — unscoped (ALL secrets) if no `--pre-admit-secret` is given. New `ka connect` is a plain CLI alias for `ka status` (same handler, no separate guard verb — still exactly `{run, list, lock, status, renew}`, `tests/test_guard_verbs_regression.py` untouched). New optional `--name LABEL` on every guard-talking command sets `KEY_AMNESIA_CLIENT_NAME` so the admission prompt can show a human-friendly label — display-only, never a trust input. See "Admission consent — kernel-verified peer identity" below for the full model, `peer_identity.py`, `test_guard_admission.py`, `test_guard_admission_legacy.py` (in-memory-only backward-compat path for callers that predate kernel identity), and `test_peer_identity_e2e.py` (real spawned-process security tests).
**Out of scope:** macOS (and Safari); browser integration of any kind (removed, not deferred — see above); passkeys / TOTP; MCP wrapper; GUI; macOS isolated-console spawn (`Terminal.app` / `osascript`); DPAPI-protecting the names sidecar. Next iteration: Rust port of the same primitives (Argon2id, SecretBox AEAD, local IPC verbs).

---

## Package layout

```
key-amnesia/
  DESIGN.md
  README.md
  LICENSE                          # Apache 2.0
  .gitignore
  MANIFEST.in                      # ships skills/*/SKILL.md + hooks/*.py as package data
  pyproject.toml
  .claude/hooks/                   # pointer only — canonical hook now installed via `ka setup`
  skills/                          # pointer only — canonical skills now installed via `ka setup`
  src/key_amnesia/
    __init__.py
    __main__.py
    cli.py                         # argparse; all subcommands + --help
    paths.py
    project.py                     # .amnesia/ walk-up, VaultContext, merge helpers (since 0.3.10)
    config.py
    crypto.py                      # Argon2id + SecretBox (vault only)
    vault.py                       # binary layout + JSON payload; migrates obsolete fill keys
    dotenv_import.py               # shared dotenv parse + vault-merge core (ka import; reusable by a future ka scan)
    scrub.py                       # exact substring replace, no regex
    audit.py                       # JSONL; never logs passwords
    ipc.py                         # Listener/Client + authkey only
    prompt_route.py                # isatty + CREATE_NEW_CONSOLE; env handoff
    guard.py                       # foreground singleton; admission consent; death reporting; multi-source reload; discovery registry
    peer_identity.py               # kernel-verified peer (pid, start_time); no message-supplied pid trusted
    run_exec.py                    # buffer-then-scrub-then-relay
    clipboard.py
    theme.py                       # branded CLI output (NO_COLOR / non-TTY safe)
    platform.py                    # isolated-console spawn (Windows CREATE_NEW_CONSOLE; Linux emulators + /dev/tty install offer)
    setup_cmd.py                   # `ka setup`: installs skills + merges hook config into ~/.claude, ~/.cursor
    skills/                        # packaged agent skills (key-amnesia-usage / -hygiene / -migrate), package data
    hooks/
      secret_guard.py              # PreToolUse (Claude) / preToolUse (Cursor) blocking hook; console script key-amnesia-hook
  tests/
```

Entry points: `key-amnesia` and `ka` both → `key_amnesia.cli:main`; `key-amnesia-hook` → `key_amnesia.hooks.secret_guard:main`.

Deps: `pynacl`, `pyperclip`. Dev: `pytest`.

**Seams:** `theme.py` owns all branded local-console UX (respects `NO_COLOR` / non-TTY; scrubbed relays and raw reveal values stay unstyled). `platform.py` owns isolated-console spawn on Windows and Linux (macOS fail-closed).

---

## File formats

### Vault (`~/.key-amnesia/vault.bin`, override `KEY_AMNESIA_VAULT_PATH`)

```
magic[4]="KAM1" | version[1]=1 | salt[16] | opslimit[8] LE | memlimit[8] LE | SecretBox blob
```

Payload JSON:

```json
{
  "secrets": {"NAME": "value", ...},
  "created_at": "...",
  "updated_at": "..."
}
```

**Migration from pre-0.3.0 vaults:** older payloads may still carry `logins` / `browser_associations` / `database_id` from the removed browser-fill feature. `_normalize_payload` (in `vault.py`) drops all three on every `load_vault` / `save_vault`. If `logins` was a non-empty list, `load_vault` prints a one-time `theme.info` notice (`"Removed obsolete login associations - browser-fill was removed in 0.3.0."`); empty/absent keys are dropped silently. The save side never re-prints (a load-then-mutate-then-save round trip in the same command only warns once), but a save always persists the cleanup — a vault touched once under 0.3.0 has no legacy keys on disk from then on.

KDF: `argon2id.kdf` with **OPSLIMIT_SENSITIVE / MEMLIMIT_SENSITIVE only** (deliberate; never dial down). Dir `~/.key-amnesia/` with `0o700` on POSIX; Windows user-profile ACL defaults.

**Creation is explicit, not implicit.** `ka init` is the only path that creates a vault: it requires an interactive TTY (refuses non-interactively — vault creation is never routed through the spawned-console/agent flow at all, unlike every other privileged command), prompts for the master password **twice**, and only writes the vault if both entries match exactly; a mismatch aborts with nothing created. `ka set` refuses with a clear error (`"Vault not initialized. Run 'ka init' first."`) if no vault exists yet — it never creates one as a side effect. This replaced an earlier v0 gap where the first `ka set` call silently created the vault from a single, unconfirmed password entry (a typo there was permanent and undetectable until the next unlock attempt failed, with no recovery path since Argon2id + SecretBox provide none by design).

**Changing the master password.** `ka passwd` (alias `ka change-password`) re-encrypts the vault under a new password with a **fresh** Argon2id salt (`save_vault(..., salt=crypto.generate_salt())` — `save_vault` otherwise preserves the existing salt on a same-password re-save). TTY-only like `init` (never routed through the spawned-console helper — the master password never needs to leave this process either way). Refuses outright while a guard session is alive (`theme.error("Lock the vault first: ka lock")`) rather than letting the guard's in-memory key go stale mid-session.

### Names sidecar (prompt-free `list`)

Whole-vault AEAD cannot list names without the password. Sidecar `~/.key-amnesia/vault.names.json` = `{"names":[...]}` updated on every successful `set`/`remove`.

**Tradeoff:** secret *names* are plaintext at rest on disk; values never are. Acceptable to keep `list` agent-callable with no prompt. Future option (DPAPI-protect sidecar on Windows) remains out of scope.

### Config (`config.json`)

`session-mode` (default `per-call`), `session-timeout-minutes` (30), `prompt-timeout-seconds` (90), `pre-admit-seconds` (900 — default window for `ka unlock --pre-admit`, since 0.3.8).

### Project manifest (`amnesia.toml`, since 0.3.9)

Written/merged by `ka import` in the current directory — one minimal `[[secret]]` table per imported name:

```toml
[[secret]]
name = "OPENAI_API_KEY"
required = true
description = ""
env = "OPENAI_API_KEY"
```

**Inert in this release** — nothing yet reads it back (`ka check` / `ka run` missing-required enforcement is a later PR). Merging an existing `amnesia.toml` only appends blocks for names not already covered (matched on the `env` field of an existing `[[secret]]` entry); it never rewrites or removes an entry a human may have hand-edited.

### Guard lock (`guard.lock`)

`address` (named pipe), `authkey_hex`, `pid`, `expires_at`.

Lives **beside the active vault** since 0.3.10 (`guard_lock_path_for_vault`): global unlock → `~/.key-amnesia/guard.lock`; project unlock → `.amnesia/guard.lock` (or `.amnesia/envs/<name>/guard.lock`). Same for `last_guard_state.json`.

**No `session_key_hex`.** Authkey authentication alone defines the IPC trust boundary. An extra SecretBox layer over messages was dropped: with a session key co-stored in `guard.lock` next to the authkey, the same processes that can read the authkey can read the session key — zero added protection, pure complexity.

### Project vaults (`.amnesia/`, since 0.3.10)

```
.amnesia/
  config.json              # {"use_global": true, "default_env": optional}
  vault.bin                # default env
  vault.names.json
  envs/<name>/vault.bin    # --env / KA_ENV / default_env
  envs/<name>/vault.names.json
```

Walk-up from cwd for `.amnesia/`, stop at home. No project → global vault (zero-action compatible). Merge: project secrets overlay global when `use_global` and the global vault file exists; independent ciphertexts → **two password prompts** on unlock/run. Fresh-auth cmds (`set`/`remove`/`reveal`/`copy`) target a single resolved vault only. Policy note: `use_global: false` is CLI-level isolation for agents — not a cryptographic boundary.

### Guard registry (`~/.key-amnesia/guards/<hash>.json`, since 0.3.10)

Discovery only — vault path, env, pid, expiry, endpoint **address**. **Never authkey** (that stays only in the vault-adjacent lock). Written/removed by `run_foreground_guard` only when an explicit `vault_path` was passed (so tests that call it without a vault never touch real home). `ka status` globs + liveness-checks; stale entries dropped. Documented daily use: one `ka unlock` per project vault.

### No admission credential on disk (since 0.3.8)

Pre-0.3.8, admission minted an opaque `secrets.token_urlsafe(32)` string (`admitted_session.token`) cached on disk by the client (`guard_request`) so later invocations in the same shell skipped the prompt. That file is **gone**: admission since 0.3.8 binds to the connecting process's kernel-verified `(pid, start_time)` identity instead (see "Admission consent — kernel-verified peer identity" below) — there is nothing admission-related to steal, read, or leave stale on disk. The in-memory opaque-token check (`AdmittedSession.token`, `_check_admission_legacy`) still exists in `guard.py` purely so `guard_handle_message` stays callable unmodified by test/call sites that predate kernel identity and never pass a `peer` kwarg; `guard_serve` — the only production dispatch path — always supplies a real `peer`, so that legacy branch never runs against a live guard.

### Last guard state (`last_guard_state.json`)

Written by the guard on **every** exit path — `started_at`, `ended_at`, `reason` (`locked` / `expired` / `interrupted` / `crashed: <ExcType>`), `request_count`. Read by `format_no_guard_message()` so `ka lock` / `ka status` report what actually happened (`"Guard is not running. Last session ended 14:32 (expired after 30m, handled 4 requests)."`) instead of a bare "No active guard session."

### Audit (`audit.log` JSONL)

`timestamp`, `action`, `secret_names`, `command`, `route` (`inline`|`spawned-console`|`guard-session`), `result` (`allowed`|`denied`|`timeout`|`warn`), `reason`. Never secret values, never passwords. `warn` (0.3.8) is a detection-only event that isn't itself an allow/deny outcome — an unrecognized peer showing up at the guard, or a `--pre-admit` window being armed — written unconditionally, independent of how the prompt is eventually answered.

---

## Console routing (central mechanism)

```
Needs human auth
  → stdin.isatty?
      yes → getpass/input inline → KDF decrypt in-process
      no  → spawn isolated console (bare argv, env handoff)
              → Windows: CREATE_NEW_CONSOLE
              → Linux: first of x-terminal-emulator / gnome-terminal / konsole / xterm
                (requires DISPLAY or WAYLAND_DISPLAY)
              → macOS / other / headless / no emulator → fail closed
              → parent waits on IPC (timeout 90s)
              → helper already did KDF locally; status-only reply
```

**`unlock` is the one action a spawned helper console cannot complete.** `ka unlock` blocks in the *caller's own terminal* for the life of the session — a separate spawned console is a different process with a different TTY, so it cannot become that guard on the parent's behalf. A non-interactive `unlock` still routes through the same isatty/spawn logic as every other command (so the routing decision, and its audit trail, stay uniform), but the helper's `unlock` handler refuses immediately with a clear reason (`"unlock must be run in a foreground terminal"`) instead of trying to start anything.

**Known limitation: `isatty()` is a heuristic, not a guarantee of an attentive human.** The routing above assumes a tty-shaped stdin means a real person is present to type a password inline. In practice a pseudo-terminal can exist with nobody actually watching it — observed with an AI coding agent whose own tool harness sometimes allocates a pty for a subprocess it invokes, unpredictably from the caller's side. When that happens, `key-amnesia` takes the inline branch and prints the prompt into a stream nobody reads. **Not fixed** (no reliable way to distinguish "tty-shaped" from "someone is actually there" from inside the process) — named honestly rather than silently left as a mystery. **What is fixed:** the consequence used to be an indefinite hang (`getpass`/`input` block forever with no timeout); inline password entry now runs on a `prompt-timeout-seconds`-bounded thread and fails closed with a clear "prompt timed out" outcome instead of hanging. The guard's own admission prompt (see below) uses the same bounded-thread pattern with a fixed 60s timeout.

### Nothing sensitive on argv — ever

Windows process-creation auditing (event 4688) and same-user process explorers record full command lines. Argv is an accidental persistence/exposure channel.

- Helper argv is **only** the bare subcommand: `key-amnesia _prompt-helper` (plus interpreter/module path as needed by the entry point).
- Pass request payload, authkey, reply address, parent PID, etc. via **environment variables** set on the `Popen` `env=` dict (not captured by 4688). Clear those env vars from the helper's view after reading if practical.
- Same rule everywhere else: no keys, no request JSON, no secret names, no secret values on any command line.

Helper behavior after env handoff:

- Prints clear UX, collects input, KDF/decrypts in-process.
- Watches parent PID / IPC disconnect → cancel and exit (no orphan window).
- Parent receives status-only replies — never password, never raw secrets.
- **Linux non-interactive spawn:** try `x-terminal-emulator`, then `gnome-terminal`, `konsole`, `xterm` (first on `PATH`). Headless (no `DISPLAY` / `WAYLAND_DISPLAY`), missing emulator, or spawn failure → fail closed. **macOS isolated-console spawn remains out of scope** (fail closed).

### `PromptRequest.detail` vs `mutation` — two fields, two trust levels

`detail` is human-facing context, printed unconditionally by `_prompt_password_inline` in the *caller's own terminal* — it must never carry secret material, since that terminal is whatever the human is already typing into (screen recording, scrollback, session logging all apply). `mutation` is the machine payload a spawned helper `json.loads()`s to apply a `set`/`config` mutation when the parent process can't hold the password itself (`ka set NAME VALUE`'s `{"name", "value"}`, `ka config set KEY VALUE`'s `{"key", "value"}`) — it may carry a raw secret value, but `_prompt_password_inline` never touches it.

`run_prompt_helper`'s own console *does* preview `mutation`'s value (`Value  : ...`) before asking for the password — that window is spawned in isolation (`CREATE_NEW_CONSOLE` / a fresh terminal emulator), unreadable and untypeable by the agent that triggered it, so showing the incoming value there lets the human deny before it's committed (see README's "Security limits" §8). Previewing the same value in the *inline* path would be pointless (the human just typed it) and unsafe (their own terminal, not an isolated one) — this is exactly the bug `test_set_never_prints_value.py` guards against.

---

## Output scrubbing (buffer-then-scrub-then-relay)

**No streaming.** For every `run` path (CLI per-call, helper per-call, guard):

1. Collect the child's stdout and stderr **fully** as bytes (`communicate()` / equivalent).
2. Decode each stream once at the end.
3. Scrub each stream **independently**.
4. Scrub with **all** injected secret values (every name→value in the inject set), not just one.
5. Exact substring replacement only (`str.replace`-style). **Never** build a regex from the secret value.
6. Relay each scrubbed stream outward in one piece; return exit code.

Command output is **not live** — the agent sees it only after the command exits. Residual limit: deliberately obfuscated echoes (e.g. base64) still slip through.

---

## Foreground guard singleton + admission consent + honest death reporting (v3)

`ka unlock` **is** the guard. There is no detached child process, no `_guard` subcommand, and no bootstrap-env handoff (all present in v2, all removed). `run_foreground_guard(payload, timeout_minutes)`:

1. Builds `GuardState` (secrets, plus — since 0.3.7 — the vault path and the derived SecretBox key so it can reload on change; see "Known limitation" below. No fill state, ever).
2. Starts one `multiprocessing.connection.Listener`, writes `guard.lock`.
3. Prints `"Guard listening (pid …, timeout …m). Waiting for requests..."` plus an expiry-clock-time / "how to stop early" (`Ctrl+C` or `ka lock`) detail line, both on the caller's own terminal.
4. Blocks in `guard_serve` until locked, expired, or interrupted. A `REMINDER_INTERVAL_S` (default 300s) nudge repeats the time-remaining even if the guard is completely idle.
5. On **every** exit path, writes `last_guard_state.json` with an honest reason before clearing `guard.lock`.

A second terminal's `ka unlock` still sees the live lock and soft-warns without starting a second guard (same singleton behavior as v2) — the singleton check is unchanged; only the guard's own execution model (foreground vs. detached-child) changed.

### Admission consent — kernel-verified peer identity (0.3.8)

The guard's authkey remains the hard security boundary (same-user processes that know the authkey can talk to the guard — the ssh-agent-style limit, unchanged since v2). On top of that, a lightweight **consent** layer gates the first request from any unrecognized process *tree*: a yes/no prompt printed on the **guard's own foreground TTY** —

```
Session ({client_name} (pid {pid}, verified)) wants: {short_summary}. Admit? [y/N]
```

— bounded by a 60s `threading.Thread` + `join` (same fail-closed pattern as the inline password prompt); timeout or any non-yes answer denies. `{client_name}` is present only if the caller passed `--name LABEL` (display-only — see below); "verified" appears whenever the peer's identity came from a real kernel lookup, which is always true on the only two supported platforms.

**What changed from the pre-0.3.8 model:** admission used to trust a message-supplied `caller_pid` for display and mint an opaque bearer token (`admitted_session.token`, cached on disk by the client) as the actual re-admission credential — any process that could read that file, or that simply claimed a `caller_pid`, got the same trust as the originally-admitted client. Since 0.3.8, `peer_identity.py` asks the **kernel**, not the message, who is on the other end of the IPC connection:

- **Windows:** `GetNamedPipeClientProcessId` on the accepted pipe handle gets the connecting pid; `OpenProcess` + `GetProcessTimes` on that pid immediately afterward gets its creation timestamp. The `(pid, start_time)` pair is `PeerIdentity` — pairing with a creation timestamp defeats PID-recycling (a *different* process that later reuses the same pid has a different start time and is never confused with the original).
- **Linux:** `SO_PEERCRED` on the accepted socket gets the connecting pid (and uid/gid, unused); `/proc/<pid>/stat` gets its start-time-in-clock-ticks (field 22) for the same `PeerIdentity` pairing.
- **macOS / other platforms:** no kernel-level peer lookup is implemented — `get_peer_identity` returns `None`, and `_check_admission` treats `peer=None` as **fail closed**, never as "no peer info supplied" (that's a distinct sentinel, `_PEER_UNSET`, reserved for pre-kernel-identity callers — see below). An unrecognized-platform guard simply cannot admit any client.

Approval binds admission to that peer's `PeerIdentity`, not a token: `GuardState.admitted` (`AdmittedSession.identities`) remembers it, and later connections are recognized either by an exact match or by walking the **new** connection's OS ancestor chain (`peer_identity.get_ancestor_chain`, bounded to `MAX_ANCESTOR_DEPTH` hops) looking for an admitted identity — a genuine OS *descendant* of the admitted process (e.g. a child shell it spawned) is silently in-tree, while a merely-sibling process (even the next separate CLI invocation from the same login shell) is treated as a fresh, unrecognized peer and re-prompts. This is a deliberate trade-off for a bearer-credential-free design (see `is_in_admitted_tree`) — `--pre-admit` exists to smooth over a bounded window of expected repeat activity from otherwise-unrelated processes.

**Secret-scoped grants.** `AdmittedSession.granted_secrets` / `unscoped` track *which* secrets a `run` request has actually been approved for, not just whether the tree is admitted at all: a `run` naming a secret outside the current grant re-prompts to expand scope (`"scope expanded"` in the audit trail) rather than either silently allowing it or re-prompting for verbs that never asked for it. `unscoped=True` (only ever set by `--pre-admit` with no `--pre-admit-secret`, or an interactively-approved request with no secret names) grants every secret with no further prompting.

**Opt-in, single-use `--pre-admit`.** `ka unlock --pre-admit [--pre-admit-secret NAME ...]` arms a bounded window (`GuardState.pre_admit_until`, default `pre-admit-seconds` = 900s / 15m from config) during which the very next unrecognized peer is admitted with **no prompt at all** — scoped to the named secrets, or unscoped ALL secrets if none given. This is loud by design: printed immediately to the guard's own TTY plus a distinct `pre-admit-armed` audit event when armed, and a normal `admission` audit event (`via=pre-admit`) the moment it's actually consumed. Single-use — consumed by the first peer to connect, whether or not the window's remaining time has elapsed, and cleared either way.

**Legacy in-memory-only fallback (`_PEER_UNSET`).** `guard_handle_message(msg, state, *, peer=_PEER_UNSET, admit_prompt=None)` defaults `peer` to a sentinel distinct from `None`: `_PEER_UNSET` means "caller doesn't know about kernel peer identity at all" and routes to `_check_admission_legacy`, the exact pre-0.3.8 opaque-token-in-message check — kept alive only so hand-built test/call sites that predate 0.3.8 keep working unmodified. `guard_serve` (the only production dispatch path) always supplies a real `peer` from `peer_identity.get_peer_identity`, so the legacy branch never executes against a live guard.

`ka status` (and its plain alias `ka connect` — same handler, no separate guard verb) reports admission state: `admitted: yes/no`, `admitted_since`, `admitted_pids`, `granted_secrets`, `granted_until`, `request_count`, plus `pre_admit_pending` / `pre_admit_scope` / `pre_admit_until` while a pre-admit window is armed but not yet consumed. The guard also logs one non-secret line per handled request on its own TTY (verb + allowed/denied) — a live activity feed for whoever is sitting at that terminal.

**`--name LABEL` (display-only, never a trust input).** Any guard-talking command accepts `--name LABEL`, threaded through as the `KEY_AMNESIA_CLIENT_NAME` environment variable and attached to the outgoing message as `client_name`; the admission prompt shows it alongside the kernel-verified pid so a human approving the request has more context than a bare number. It carries zero trust weight — admission decisions never consult it, only kernel-verified `PeerIdentity`.

### Honest death reporting

Every guard exit path is wrapped and reported truthfully instead of a bare "no active session":

| Exit path | `last_guard_state.json` reason |
|---|---|
| Explicit `lock` verb (IPC) | `locked` |
| TTL reached | `expired` |
| `KeyboardInterrupt` (Ctrl+C) | `interrupted` — prints a one-line uptime/request-count/admitted summary on the guard's own TTY, then tears down the same way as `locked` |
| Any other exception | `crashed: <ExcType>` |

`format_no_guard_message()` (used by `cmd_lock` and `cmd_status`, and any future "no live guard" path) reads that file and produces e.g. `"Guard is not running. Last session ended 14:32 (expired after 30m, handled 4 requests)."` instead of a bare `"No active guard session."`

---

## Two-tier security model

1. **Hard guarantee (unchanged since v1):** the guard IPC never returns raw secrets; verbs stay exactly `{run, list, lock, status, renew}`. Automated regression asserts this dispatch set (`tests/test_guard_verbs_regression.py`).
2. **Admission consent (new in v3, described above)** is a UX/consent layer, not a second hard guarantee — it never weakens or replaces the authkey boundary, and it never gates *which* verbs exist, only *whether a first-time caller gets to use any of them* without a human noticing.

Browser-fill's "practical guarantee" / auth-precedent exception described in v2 no longer applies — that entire feature (and its narrowly-scoped cached-session read exception) is removed in 0.3.0.

---

## Who holds plaintext (invariant-critical)

| Path | Decryptor | Value use |
|------|-----------|-----------|
| Interactive per-call `run` | CLI | CLI injects env + spawns |
| Non-interactive per-call `run` | Helper | **Helper** spawns; returns scrubbed I/O + exit only |
| Cached `run` (live guard) | Guard | **Guard** spawns; IPC = scrubbed I/O + exit only |
| Interactive reveal/copy | CLI | Same console print/clipboard |
| Non-interactive reveal/copy | Helper | Show/copy **only in helper window**; caller gets status flag only |
| `ka passwd` | CLI (TTY-only) | Re-encrypts locally; never leaves this process |

Non-interactive per-call `run` makes the helper the one-shot decryptor and executor (bounded result shape, same as the guard path). Secrets are never handed back over IPC to the agent-invoked waiting process.

**Since 0.3.7, `Cached run (live guard)` also retains the derived SecretBox key** (not the password) for the guard's session lifetime, so it can reload the vault on a content change — see "Known limitation — stale in-memory secrets" above. No other row in this table changed: the master password itself still never leaves the process that prompted for it (README limit 7).

Guard IPC has **no** `get-value`/`reveal` verb. Same-user processes can talk to the guard (ssh-agent limit); damage is bounded to `run`/`list`/`lock`/session-control only, and now additionally requires at least one admitted consent prompt per guard lifetime.

---

## IPC

`multiprocessing.connection` on `\\.\pipe\key-amnesia-<random>` + `authkey` only. Messages are ordinary pickled/JSON objects over the authenticated connection — **no additional payload SecretBox**.

Guard verbs: `run`, `list`, `lock`, `status`, `renew` only — still exactly five since v1; `ka connect` is a plain CLI alias for `status`, not a sixth verb. Since 0.3.8, messages carry nothing admission-related at all: no `caller_pid`, no `admission_token`. The guard identifies the caller straight from the kernel at the IPC layer (see "Admission consent — kernel-verified peer identity" above); the only client-supplied, display-only addition is an optional `client_name` (from `--name` / `KEY_AMNESIA_CLIENT_NAME`).

Master password never appears on this channel in any form. Master password is never satisfiable non-interactively without a spawned console.

---

## Session modes

- **per-call (default):** no persistent guard; each privileged op goes through password routing; discard after use.
- **cached:** `unlock` runs the guard in the caller's own foreground terminal; timeout from unlock; ~2 min before expiry (`EXTEND_PROMPT_WINDOW_S`) prompt extend on the guard's own TTY if still interactive; a periodic `REMINDER_INTERVAL_S` (default 300s) nudge repeats time-remaining in between. Both checks tick on every accept-poll cycle, not just when a client connects — an idle guard nobody talks to still surfaces them on schedule (a prior bug had them silently skipped for a guard blocked in `listener.accept()` with no incoming traffic; see `test_guard_extend_prompt.py`, `test_guard_startup_banner.py`). `lock` tears it down. Live guard → `run`/`list` skip the password prompt (first use per client still needs one admission consent prompt).

**Fixed in 0.3.7 — stale in-memory secrets.** `GuardState.secrets` used to be populated once from `load_vault` at `run_foreground_guard` time and never re-read afterward: a `ka set`/`ka remove` made against the vault file while a guard was already live updated the file correctly, but that guard kept handing out its old in-memory copy for the rest of its session until `ka lock` + `ka unlock`. Fixed without a repeated Argon2id cost per request and without a new IPC verb: `run_foreground_guard` now retains the SecretBox key already derived for the initial decrypt (`cmd_unlock` uses `load_vault_with_key` instead of `load_vault`) alongside a cheap content fingerprint (size + mtime + hash) of the vault file. On every `run`/`list`/`status`, `_maybe_reload_secrets` recomputes that fingerprint; if it moved, the guard re-opens the vault via `load_vault_with_retained_key` (SecretBox decrypt only, no KDF, no password prompt) and replaces `state.secrets`. A transient read error (e.g. caught mid-write by another process) is treated as "nothing to reload yet" — the guard keeps serving its last-known-good snapshot rather than dropping secrets on a torn read. `GuardState` instances built without `vault_path`/`vault_key` (every guard-dispatch test, and any future in-memory-only caller) skip the check entirely — behavior for those is unchanged.

**New exposure this introduces — derived key retained in guard memory.** Previously the guard held only the decrypted plaintext secrets for the session; the master password itself never left the process that prompted for it (README limit 7) and was never retained anywhere. The guard now *also* retains the Argon2id-derived SecretBox key for as long as the session lives, so it can re-open the vault later without asking again. This is **not** the password — it cannot be used to derive the password backward, and it is scoped to this one vault file — but it is new memory-resident key material that didn't exist before 0.3.7, in the same trust ballpark as the plaintext secrets the guard was already holding. Same-user-process access is the existing limit (README §6); nothing here changes who can talk to the guard, only what the guard itself now remembers.

Always fresh master-password routing (never guard shortcut) for `reveal`, `copy`, `remove`, `config set`, `set`, and `passwd`.

---

## Commands

- `init` — creates the vault; TTY-only (no agent-triggered path), double-confirms the master password, refuses if a vault already exists
- `passwd` / `change-password` — re-encrypts the vault under a new password with a fresh salt; TTY-only; refuses while a guard session is alive
- `set` / `remove` — fresh auth; mutate vault + names index; `set` refuses if no vault exists yet rather than creating one implicitly
- `import FILE` — TTY-only; parses a dotenv file (`dotenv_import.py`) and merges its entries into the resolved vault; collision default skip; offers delete/rename of the source file and a `.gitignore` entry; generates/merges a minimal `amnesia.toml`; never prints a value
- `run --secret/--as ... -- cmd` — guard hit or per-call decrypt path; buffer-then-scrub child stdout/stderr → `***REDACTED(name)***`
- `list` — read names sidecar (no prompt); never values
- `unlock [--pre-admit] [--pre-admit-secret NAME ...]` — *is* the guard; blocks in the caller's own terminal until locked/expired/interrupted; `--pre-admit` loudly arms a single-use, bounded-window auto-admit for the next unrecognized peer (see "Admission consent" above)
- `lock` — tear down the live guard session (or report the last one's honest fate if none is live)
- `reveal` / `copy` — always fresh auth; display location follows TTY vs helper rule
- `config set session-mode|session-timeout-minutes|prompt-timeout-seconds|pre-admit-seconds` — always fresh auth
- `status` (alias `connect`, same handler, no separate guard verb) — live guard status (pid, expiry, secret count, admission state, pre-admit-pending state) or the last session's honest death report
- `run`/`list`/`lock`/`status`/`connect` accept `--name LABEL` — display-only client label shown in the guard's admission prompt (see "Admission consent" above); never a trust input
- `setup` — non-interactive: copies the 3 packaged skills to `~/.claude/skills/` + `~/.cursor/skills/` and idempotently merges the secret-guard hook into `~/.claude/settings.json` (`PreToolUse`) + `~/.cursor/hooks.json` (`preToolUse`); `--skills-only` / `--hook-only` to do just one half; never mutates vault/session state
- `_prompt-helper` — internal; bare argv + env handoff; omitted from top-level summary, still supports `--help`

---

## Core signatures

```python
def derive_key(password: bytes, salt: bytes, opslimit: int, memlimit: int) -> bytes: ...
def load_vault(path, password: str) -> dict: ...
def load_vault_with_key(path, password: str) -> tuple[dict, bytes]: ...
# same decrypt as load_vault, also returns the derived SecretBox key so the
# caller can retain it (guard reload) without deriving twice.
def load_vault_with_retained_key(path, key: bytes) -> dict: ...
# no Argon2id — re-opens with an already-derived key.
def vault_fingerprint(path=None) -> str | None: ...
# size:mtime_ns:sha256hex of the vault file; None if unreadable right now.
def save_vault(path, password: str, payload: dict, *, salt=None) -> None: ...

def require_human_auth(request: PromptRequest, timeout_s: int) -> AuthOutcome: ...
def run_with_secrets(command: list[str], env_inject: dict[str, str],
                     secrets_by_name: dict[str, str], cwd=None) -> RunResult: ...
# RunResult: exit_code, scrubbed_stdout, scrubbed_stderr (after full buffer)

def scrub_text(text: str, secrets: dict[str, str]) -> str: ...
# exact str.replace for every value; no regex

def guard_handle_message(msg: dict, state: GuardState, *,
                         peer: "PeerIdentity | None | object" = _PEER_UNSET,
                         admit_prompt=None) -> dict: ...
# `peer` is the connection's kernel-verified identity (see peer_identity.py);
# guard_serve always supplies a real one. The _PEER_UNSET default routes to
# the pre-0.3.8 in-memory opaque-token check for callers that predate
# kernel identity; an explicit `peer=None` (a real lookup that failed)
# always fails closed instead.
def run_foreground_guard(payload: dict, timeout_minutes: int, *,
                         vault_path=None, vault_key: bytes | None = None,
                         pre_admit: bool = False,
                         pre_admit_secrets: list[str] | None = None,
                         pre_admit_seconds: int = 900) -> int: ...
# vault_path/vault_key are optional and both-or-nothing in practice; when
# given, the guard retains vault_key (derived key only) and reloads
# state.secrets on a vault content change — see "Known limitation" above.
# pre_admit arms a single-use, bounded-window auto-admit for the next
# unrecognized peer — see "Admission consent" above.
def format_no_guard_message() -> str: ...

# peer_identity.py — kernel-verified peer identity, no message-supplied pid trusted
def get_peer_identity(conn: Connection) -> "PeerIdentity | None": ...
# None on lookup failure or an unsupported platform (macOS/other) — always
# fail-closed, never a silent "trust it anyway".
def get_ancestor_chain(pid: int, max_depth: int = 32) -> list["PeerIdentity"]: ...
# [pid's own identity, parent's, grandparent's, ...], best-effort, bounded.
def is_in_admitted_tree(admitted: list["PeerIdentity"], peer: "PeerIdentity") -> bool: ...
# True if peer exactly matches one of `admitted`, or is a real OS descendant
# of one (walks peer's own ancestor chain looking for an admitted match).
```

---

## Guard never returns raw secret values

The guard and helper IPC replies expose only: status, scrubbed stdout/stderr, exit codes, secret *names*, and session metadata (including admission state). Never passwords. Never raw secret values.

---

## Testing

Vault round-trip / wrong password / tamper; obsolete browser-fill key migration on load (one-time notice only when `logins` was non-empty, silent drop otherwise, save-side persists the cleanup without a second notice) (`test_vault_migration.py`); `init` mismatch creates nothing, match creates an unlockable vault, refuses if a vault already exists; `set` refuses when no vault exists yet; `passwd` happy path re-encrypts with a fresh salt, refuses while guard alive, mismatch aborts, wrong current password aborts, TTY-only (`test_passwd_cmd.py`); scrubbing on both per-call and guard paths; crafted IPC client never gets raw values; guard verb set regression (`{run,list,lock,status,renew}` only, admission pre-seeded so verb dispatch itself is under test); cached-session `run` executes in the caller's cwd (threaded through the IPC message); kernel-verified-peer admission-consent prompt approves/denies/times out, an unavailable peer identity (`peer=None`) always fails closed rather than falling back to the legacy path, an admitted peer skips re-prompting, a real OS descendant of an admitted peer is silently in-tree while an unrelated peer is not and re-prompts, secret-scoped grants allow already-granted secrets without re-prompting and re-prompt (allow or deny) to expand scope for a new one, unscoped grants never re-prompt, `--pre-admit` consumes its single-use window for the next unrecognized peer (unscoped or scoped to specific secrets) and falls back to a normal prompt once expired, `status` reports admission state and pending pre-admit (`test_guard_admission.py`); the pre-0.3.8 in-memory opaque-token fallback path (`_PEER_UNSET`, no `peer` kwarg supplied) still approves/denies/re-prompts exactly as before, purely for callers that predate kernel identity (`test_guard_admission_legacy.py`); real spawned-process E2E security tests — an unrelated spawned process is never silently admitted, a genuine child process of an admitted process is silently in-tree without a prompt (`test_peer_identity_e2e.py`); honest death reporting for `locked`/`expired`/`interrupted`/`crashed: <ExcType>`, `format_no_guard_message()` phrasing, guard prints its live status banner on start (`test_guard_death_reporting.py`); foreground unlock never spawns a subprocess, a spawned helper console refuses the `unlock` action with a clear reason instead of trying to start anything (`test_foreground_unlock.py`); argparse `--help` walk over the root parser and every subparser renders on a simulated cp1252 console without raising, automatically covers `setup` (`test_argparse_help_cp1252.py`); `isatty=False` asserts `CREATE_NEW_CONSOLE`, bare argv, env handoff; password never in IPC; inline password prompts fail closed on a bounded timeout instead of hanging when `isatty()` is fooled by a tty-shaped-but-unattended stream; reveal/copy non-interactive returns status only; helper parent-death cancels; unlock→run→lock→fallback; reveal/copy ignore live guard; config/remove/`set` need password; audit with no plaintext; `--help` (including `init`); scrubber uses replace not regex; Linux emulator selection order and env/argv handoff, immediate-exit fallthrough to the next emulator, headless and no-emulator fail-closed, macOS/other-platform fail-closed (`test_posix.py`); themed output respects `NO_COLOR` and non-TTY streams, ASCII glyph fallback, scrubbed/revealed values stay unstyled, degrades non-cp1252-encodable caller text instead of crashing (`test_theme.py`); secret-guard hook blocks every known prefix (OpenAI/Anthropic/AWS/GitHub/GitLab/Slack/Google/Stripe/npm) and high-entropy assignments, allows placeholder assignments (`PASSWORD=test123`), bare mentions, comments, and `ka run`/`ka set` command lines, host detection (Claude vs Cursor payload shape) picks the right deny contract, disable env skips everything, fails open on malformed/empty/non-dict stdin (`test_secret_guard.py`); `ka setup` copies all three skills to both hosts with matching content, overwrites stale copies on rerun, `--skills-only`/`--hook-only` isolate each half, Claude `settings.json` / Cursor `hooks.json` merges preserve unrelated keys and other hooks and are idempotent on rerun, malformed settings recover to a fresh merge, PATH check reports found/not-found via monkeypatched `shutil.which` (`test_setup_cmd.py`); a real wheel build (`pip wheel`) contains all three packaged `SKILL.md` files and the hook module (`test_package_skills_data.py`); the extend-prompt and idle-time reminder both fire on an idle guard parked inside a never-returning `listener.accept()` — not just when a client happens to connect — and an accepted extend actually pushes `expires_at` out (`test_guard_extend_prompt.py`); the startup banner shows the expiry clock and how to stop early, and the periodic reminder backs off once inside the extend window (`test_guard_startup_banner.py`); `ka set`'s value never appears in the caller's own terminal, is reachable only via `PromptRequest.mutation` and not `detail`, and the isolated spawned-console helper still previews it before applying the mutation (`test_set_never_prints_value.py`); guard reload picks up a `set` made while unlocked on the very next `run`/`list`/`status`, a `remove` makes a secret disappear the same way, reload is driven by the vault's content fingerprint (not a fixed poll interval or a new verb), and the guard never returns a raw secret value across a reload (`test_guard_reload.py`); dotenv parsing (quoted/unquoted values, `export`, comments), collision merge defaulting to skip vs. an explicit overwrite callback, minimal `amnesia.toml` generation and no-duplicate merge, the `.gitignore` offer (never silent, no-ops if already covered), and the delete/double-confirm/rename/keep source-file state machine, all as pure functions with injected yes/no callbacks (`test_dotenv_import.py`); `ka import` end-to-end — TTY-only refusal, missing file, no-vault refusal, wrong password denied, an empty file is a no-op, a happy path merges new names into the vault while leaving existing ones untouched and writes both `.gitignore` and `amnesia.toml`, a name collision defaults to skip and only overwrites on explicit confirm, delete/rename/keep are all reachable via prompt answers, and no secret value is ever printed to the terminal (`test_import_cmd.py`).
