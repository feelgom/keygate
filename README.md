# keygate

> **Fork of [key-amnesia](https://github.com/fujitoid/key-amnesia)** — adds password manager backends (Bitwarden) so you don't need a separate encrypted vault.

AI agents can **use** your secrets without **seeing** them.

keygate connects to your password manager (Bitwarden), injects secrets into child processes as environment variables, and scrubs any leaked values from the output before the agent sees it.

## Why

`.env` files stop secrets from being committed to git — but they don't stop AI agents (Claude Code, Codex, Cursor) from reading them in plain text. keygate solves this:

- Secrets stay in your password manager (Bitwarden)
- Agents run commands with secrets injected via env vars
- Output containing secret values is automatically redacted (`***REDACTED***`)
- No plaintext files on disk that agents can read

## Install

```bash
pip install keygate-cli
```

Or with pipx (isolated environment):
```bash
pipx install keygate-cli
```

### Prerequisites

- Python 3.10+
- [Bitwarden CLI](https://bitwarden.com/help/cli/) (`brew install bitwarden-cli`)

## Setup

```bash
# 1. Login to Bitwarden (one-time)
bw login

# 2. Configure keygate to use Bitwarden
mkdir -p ~/.keygate
echo '{"backend":"bitwarden"}' > ~/.keygate/config.json

# 3. Unlock (fetches secrets, caches locally)
kg unlock
```

## Usage

```bash
# List available secrets
kg list

# Run a command with secrets injected
kg run --secret API_KEY -- python app.py

# Map to a specific env var name
kg run --secret DB_PASS --as DB_PASS=PGPASSWORD -- psql

# Multiple secrets
kg run --secret AWS_ACCESS_KEY_ID --secret AWS_SECRET_ACCESS_KEY -- aws s3 ls

# Store a new secret
kg set MY_NEW_KEY

# Lock when done
kg lock
```

## How it works

```
[AI Agent]
    │
    │  kg run --secret API_KEY -- curl https://api.example.com
    ▼
[keygate]
    1. Reads secret value from local cache (populated at unlock)
    2. Injects into child process env: API_KEY=sk-abc123...
    3. Runs: curl https://api.example.com
    4. Captures stdout/stderr
    5. Replaces "sk-abc123..." with "***REDACTED(API_KEY)***"
    6. Returns scrubbed output to agent
    ▼
[Agent sees]
    {"auth": "***REDACTED(API_KEY)***", "status": "ok"}
```

## Agent integration

keygate works with any AI coding agent:

| Agent | Integration |
|-------|-------------|
| Claude Code | Skill file + PreToolUse hook |
| Codex | Skill file + PreToolUse hook |
| Cursor | Skill file + preToolUse hook |

### Install skill + hook

```bash
./install.sh
```

This copies the keygate skill to `~/.claude/skills/keygate/` and registers the secret-guard hook in `~/.claude/settings.json`.

## Commands

| Command | Speed | Description |
|---------|-------|-------------|
| `kg unlock` | ~3s | Authenticate with Bitwarden, cache secrets locally |
| `kg list` | instant | List secret names from cache |
| `kg run` | instant | Run command with secrets injected + output scrubbed |
| `kg set NAME` | ~2s | Store a new secret in Bitwarden + update cache |
| `kg status` | instant | Check if session is active |
| `kg lock` | instant | Clear session and cached secrets |

## Security model

- Secrets are stored in Bitwarden (encrypted at rest, never in plaintext files)
- Local cache (`~/.keygate/secrets_cache.json`) exists only while unlocked, permissions 0600
- `kg lock` wipes the cache immediately
- Output scrubbing catches leaked values via exact string matching (longest-first)
- The PreToolUse hook blocks commands containing credential-shaped tokens

### Limitations

- If an agent base64-encodes or character-splits a secret, scrubbing won't catch it (same limitation as key-amnesia)
- Local cache is plaintext while unlocked — `kg lock` when not in use

## Relationship to key-amnesia

This project is a **fork of [key-amnesia](https://github.com/fujitoid/key-amnesia)** (Apache-2.0).

### What keygate changes

| Area | key-amnesia | keygate |
|------|-------------|---------|
| Secret storage | Own encrypted vault (Argon2id + SecretBox) | Bitwarden (via `bw` CLI) |
| Dependencies | PyNaCl required | PyNaCl optional (only for local vault mode) |
| Session model | Foreground guard process (blocking) | Session file (non-blocking) |
| CLI command | `ka` | `kg` |
| Speed | KDF on every unlock (~2s) | Cache after first load (instant `run`/`list`) |

### What keygate preserves from upstream

- `scrub.py` — output scrubbing engine (exact string replacement)
- `run_exec.py` — subprocess execution + env injection + scrub
- `hooks/secret_guard.py` — PreToolUse hook (credential detection + verb deny)
- `detect.py` — secret pattern detection (high-entropy, vendor prefixes)
- `setup_cmd.py` — agent skill/hook installer
- Local vault mode (still works if you `pip install keygate[vault]`)

### Syncing with upstream

```bash
# Track upstream
git remote add upstream https://github.com/fujitoid/key-amnesia.git

# Fetch and merge upstream updates
git fetch upstream
git merge upstream/master --no-edit

# Our changes are isolated to:
#   - src/key_amnesia/backend.py          (new)
#   - src/key_amnesia/backend_bitwarden.py (new)
#   - src/key_amnesia/cli.py              (backend dispatch at top of each cmd_*)
#   - src/key_amnesia/config.py           (backend config key)
#   - src/key_amnesia/paths.py            (KEYGATE_HOME env var)
#   - src/key_amnesia/vault.py            (lazy crypto import)
```

Merge conflicts are minimal because keygate's additions are mostly in **new files** (`backend*.py`) and **early-return dispatches** at the top of existing command functions.

## License

Apache-2.0 (same as upstream key-amnesia)
