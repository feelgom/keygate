# keygate

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
git clone https://github.com/feelgom/keygate.git
cd keygate
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Add to PATH
ln -sf $(pwd)/.venv/bin/kg ~/bin/kg
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

## Based on

Forked from [key-amnesia](https://github.com/fujitoid/key-amnesia) with the following changes:
- Added Bitwarden backend (no PyNaCl required)
- Removed guard/admission system for PM backends (simpler session-file approach)
- Rebranded CLI to `kg` / `keygate`
- Local secret caching for instant `kg run` / `kg list`

## License

Apache-2.0
