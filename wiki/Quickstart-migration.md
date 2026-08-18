# Quickstart migration

Goal: get off plaintext `.env` faster than deciding whether to.

```bash
# Inside a project
ka init --project          # creates .amnesia/; gitignores it
ka import .env             # TTY-only; never prints values
ka scan                    # find remaining LEAKs; may offer import
ka run --secret NAME --as NAME=ENVVAR -- <command>
```

Order matters: **import → scan → run**. Import moves a known dotenv file into
the vault; scan finds what is still readable as plaintext; run injects by
name so the agent never sees values.

`--as` takes **`NAME=ENVVAR`** (vault secret name = target environment
variable). Omit `--as` and `--secret NAME` alone injects as `NAME`. Wrong
forms such as `--as API_KEY`, `--as NAME`, or `--as ENVVAR` are rejected.

## `ka import`

- TTY-only — run it in your own console. Collision, delete/rename, and
  gitignore decisions are interactive confirms; there is no agent path.
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
**not** a feature of the default path (or of this tool's advertised
workflow). The headline and default exit count **high-confidence** hits
only. Identifier- and word-shaped-passphrase hits are `possible`
(`--fail-on possible` to gate; `--show-possible` to list paths). Values are
never printed.

After the human report, an interactive TTY may offer to store selected
importable dotenv hits into the project vault (password still required).
Use report-only when you do not want that offer:

```bash
ka scan
ka scan --no-import   # report only; never offer vault import
ka scan --deep        # + home/shell/MCP paths
ka scan --json        # machine-readable; report-only
ka scan --fail-on possible   # also exit 1 on identifier/passphrase-shaped hits
ka scan --show-possible      # list possible paths in the human report
ka scan --yes         # import all importable dotenv hits (password still required)
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
