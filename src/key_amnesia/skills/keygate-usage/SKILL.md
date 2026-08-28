---
name: keygate-usage
description: >-
  Use keygate (`kg`) to run commands with secrets from Bitwarden (or local vault)
  without ever seeing the values. Check state first (`kg status` / `kg list`),
  then use `kg run --secret NAME -- <command>`. Never paste keys into chat, argv,
  or files. Use when needing API keys, passwords, env injection, or `kg` commands.
---

# Using keygate

keygate lets AI agents **use** secrets without **seeing** them. Secrets are fetched from your password manager (Bitwarden) or local vault, injected into a child process environment, and the output is scrubbed before returning to the agent.

## Quick start

```bash
kg status          # is a guard session live?
kg list            # what secret names are available?
kg run --secret OPENAI_API_KEY -- python script.py   # use a secret
```

## Backends

keygate supports multiple secret backends:

| Backend | Config | Requirement |
|---------|--------|-------------|
| Local vault (default) | `kg config set backend vault` | None (built-in) |
| Bitwarden | `kg config set backend bitwarden` | `bw` CLI installed + logged in |

### Bitwarden setup

```bash
# 1. Install bw CLI
brew install bitwarden-cli   # or your package manager

# 2. Login (one-time)
bw login

# 3. Configure keygate to use Bitwarden
kg config set backend bitwarden

# 4. Unlock (starts a guard session)
kg unlock
# → prompts for Bitwarden master password
# → loads all secrets from "key-amnesia" folder in BW
# → guard holds them in memory, scrubs all output
```

## State-first — never blanket init/unlock

Before doing anything, check what already exists:

```bash
kg status   # is a guard session live?
kg list     # what secret names exist (no values shown)
```

Do **not** reflexively run `kg init` or `kg unlock`. Only suggest to the human when `status`/`list` show they're needed.

## Preferred pattern

```bash
kg run --cwd DIR --secret NAME --as NAME=ENVVAR -- <command> [args...]
```

- `--as` maps secret NAME to env var ENVVAR (format: `NAME=ENVVAR`)
- Multiple secrets: repeat `--secret` / `--as` pairs
- Use `--cwd DIR` instead of `cd DIR && ...`
- Never embed a secret's actual value in any command

## Safe for agents

| Action | OK? | Notes |
|--------|-----|-------|
| `kg status` | Yes | Session metadata only |
| `kg list` | Yes | Names only, never values |
| `kg run --secret NAME -- ...` | Yes | Primary agent path |
| Reading vault files / guessing values | **No** | Guard has no value-return verb |

## Always human (never attempt yourself)

- **`kg unlock`** — human starts session in their own terminal
- **`kg init`** — human creates vault (TTY-only, password confirm)
- **`kg set NAME`** — human stores a secret
- **`kg reveal` / `kg copy`** — human-only value access

## Anti-patterns

- Pasting secrets into chat or files
- Running `kg unlock` without checking `kg status` first
- Wrapping `kg run` in pipes or `cd &&` — use `--cwd` instead
- Assuming the guard can return raw values — it cannot

## Output scrubbing

All command output is scrubbed before the agent sees it:
```
$ kg run --secret API_KEY -- curl https://api.example.com
{"auth": "***REDACTED(API_KEY)***", "status": "ok"}
```

If a secret value appears anywhere in stdout/stderr, it is replaced with `***REDACTED(name)***`.
