# Guard and admission

## Cached sessions

```bash
ka config set session-mode cached
ka unlock
ka lock
ka status          # alias: ka connect
```

`ka unlock` runs the guard **in that terminal**. Startup shows expiry and
how to stop early (`Ctrl+C` or `ka lock` from another terminal). Before
expiry the guard asks whether to extend; no answer means lock.

## Guard never returns values

IPC verbs stay exactly `{run, list, lock, status, renew}`. There is no
"give me the secret" request. The guard runs your command itself (with
injection) and returns scrubbed output + exit code.

## Kernel-verified admission

The first command from an unrecognized process triggers a yes/no prompt on
the guard's own TTY. Approval binds to the connecting process's
**kernel-verified** identity (OS pid + creation time — not a client-claimed
field). Descendants of an admitted tree go through; unrelated processes get
their own prompt. There is **no on-disk admission token** to steal.

Optional display-only `--name LABEL` / `KEY_AMNESIA_CLIENT_NAME` for the
prompt text — **zero security weight**.

## Pre-admit

```bash
ka unlock --pre-admit
ka unlock --pre-admit --pre-admit-secret NAME   # repeatable; scoped
```

Opt-in, never default. Auto-admits the **next** connecting process for a
bounded window (default 15 minutes / `pre-admit-seconds`). Unscoped
(ALL secrets) is loud on the TTY and in the audit log. This trades
consent-before for audit-after for one bounded single-use tree.

## Reload

On every `run` / `list` / `status`, the guard fingerprints vault file(s).
If changed, it re-opens with the retained derived SecretBox key (no
Argon2id). Merged project+global unlocks fingerprint every contributing
file.
