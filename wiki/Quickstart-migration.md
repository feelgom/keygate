# Quickstart migration

Goal: get off plaintext `.env` faster than deciding whether to.

```bash
# Inside a project
ka init --project          # creates .amnesia/; gitignores it
ka import .env             # TTY-only; never prints values
ka scan                    # find remaining LEAKs
ka run --secret NAME --as NAME -- <command>
```

## `ka import`

- Parses dotenv `NAME=value` pairs into the resolved vault (project vault
  when `.amnesia/` is found).
- Collisions default to **skip**; overwrite only on explicit confirm.
- After import: offers delete (double-confirm) or rename to
  `.imported`, offers `.env*` gitignore, merges `amnesia.toml`.
- Never prints a secret value.

## `ka scan`

Reports Locally Exposed Agent Keys — filenames and light patterns. Default
exclusions skip `node_modules`, `.venv`/`venv`, common build dirs, and
`.git` internals (`--include-excluded` to include). Git-history scanning is
**not** in the default path.

```bash
ka scan
ka scan --deep      # + home/shell/MCP paths
ka scan --json      # machine-readable; report-only
ka scan --yes       # import all importable dotenv hits (password still required)
```

## Session modes

| Mode | Feel |
|------|------|
| `per-call` (default) | Password every privileged use |
| `cached` | `ka unlock` once; guard for ~30m |

```bash
ka config set session-mode cached
ka unlock
ka lock
```
