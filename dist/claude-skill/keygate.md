---
name: keygate
description: >-
  Run commands with secrets from Bitwarden without AI agents seeing the values.
  Use `kg status`, `kg list`, `kg run --secret NAME -- <cmd>`. Output is scrubbed.
  Trigger: API key needed, secret injection, env var, password, credential.
---

# keygate — Secret Gate for AI Agents

keygate lets you **use** secrets without **seeing** them. Values come from Bitwarden (or a local encrypted vault), get injected into child process env vars, and output is scrubbed before you see it.

## Commands you CAN use

```bash
kg status                              # check if guard session is active
kg list                                # list available secret names (no values)
kg run --secret NAME -- <command>      # run with secret injected as env var
kg run --secret NAME --as NAME=ENVVAR -- <cmd>  # map to specific env var name
kg run --cwd /path --secret A --secret B -- <cmd>  # multiple secrets
```

## Commands you CANNOT use (human-only)

- `kg unlock` — starts guard session (human types their BW master password)
- `kg init` — creates vault
- `kg set NAME` — stores a secret
- `kg reveal` / `kg copy` — accesses raw values
- `kg config set backend bitwarden` — switches backend

## Workflow

1. **Check state first**: `kg status` then `kg list`
2. **If no session**: tell the human to run `kg unlock` in their terminal
3. **Use secrets**: `kg run --secret NAME -- <command>`
4. **Output is safe**: any leaked value becomes `***REDACTED(NAME)***`

## Rules

- NEVER paste, echo, or hardcode secrets in commands or files
- NEVER try to read vault files or guess values
- NEVER run `kg unlock`, `kg init`, `kg set` yourself
- ALWAYS use `--cwd DIR` instead of `cd DIR && kg run ...`
- ALWAYS check `kg status` before assuming a session exists
- If `kg run` fails with "no active guard", tell the human to run `kg unlock`

## Example

```bash
# Check what's available
kg status
kg list

# Use an API key
kg run --secret STRIPE_KEY --as STRIPE_KEY=STRIPE_SECRET_KEY -- python charge.py

# Multiple secrets with env var mapping
kg run --secret DB_PASSWORD --as DB_PASSWORD=PGPASSWORD --secret API_KEY -- ./deploy.sh
```
