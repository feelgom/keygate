# Commands

Skeleton reference. Prefer `ka <command> --help` for flags. Full design
notes live in the repository `DESIGN.md`.

| Command | What it does |
|---------|--------------|
| `ka init [--project] [--env NAME]` | Create vault (double-confirm password). `--project` → `.amnesia/` |
| `ka passwd` / `ka change-password` | Change master password (refuses while session active) |
| `ka set NAME` | Store/update secret (hidden prompt preferred over inline value) |
| `ka remove NAME` | Delete a secret |
| `ka import FILE` | Import dotenv into resolved vault (TTY-only) |
| `ka check [--json]` | Manifest vs project names sidecar (CI; no decrypt) |
| `ka scan [--deep] [--wide] [--include-excluded] [--json] [--strict] [--yes] [--no-import]` | LEAK report (names/paths/counts only); optional offer-to-import |
| `ka run --cwd DIR --secret NAME [--as NAME=ENVVAR] -- <cmd>` | Inject + scrub; agent-facing path (`=` form required for `--as`) |
| `ka list` | Names only; safe for agents; no prompt |
| `ka unlock [--pre-admit] [--pre-admit-secret NAME] [--admit-tree]` | Start cached guard session (pre-admit / admit-tree flags opt-in) |
| `ka lock` | End session early |
| `ka reveal NAME` / `ka copy NAME` | Human-only surface of a value; always fresh auth |
| `ka config show` / `ka config set KEY VALUE` | Settings |
| `ka status` / `ka connect` | Session status (+ registry of live guards). `connect` is a **CLI alias** for `status` — not a sixth IPC verb |
| `ka setup [--skills-only] [--hook-only] [--permissions-only] [--permissions-remove] [--yes]` | Install skills, secret-guard hook, and harness allow-lists (Claude / Cursor / Codex) |
| `ka docs [--print]` | Print wiki URL; open browser unless `--print` |
| `ka identity create` / `show` | Local X25519 identity for KAM2 |
| `ka member add` / `list` / `remove` | Members/roles (first add enables KAM2) |
| `ka grant` / `ka revoke` | Per-secret ACL |
| `ka export --for MEMBER` | Ciphertext bundle for one member |

### `run` mapping

```bash
ka run --cwd DIR --secret API_KEY --as API_KEY=API_KEY -- python my_script.py
# or inject under the secret's own name:
ka run --cwd DIR --secret API_KEY -- python my_script.py
```

`--as` takes `NAME=ENVVAR` only (CLI requires the `=` form). Omitting
`--as` injects the secret under its vault name. Prefer `--cwd DIR` over
`cd &&`; do not wrap `ka run` in pipes or `2>&1`.

### `scan` flags

- `--deep` — also check home dotfiles, shell history, global git config,
  known MCP paths (not a full home walk). Independent of `--wide`.
- `--include-excluded` / `--wide` — include default-excluded dirs; git-history scan
  still out of scope. `--wide` is an alias only.
- `--json` — machine-readable report (`leak_count` matches the `--strict` gate; always includes `certain_count`, `likely_count`, `possible_count`, and per-finding `confidence` + `reasons`)
- `--strict certain|high|paranoid` — default `high`: exit 1 iff certain+likely `leak_count` > 0. `certain` is prefixes and confirmed filenames. `likely` is assignments and UUID-shaped values. `paranoid` also fails on identifier/passphrase/low-transition hits and unconfirmed `mcp.json` (the ≤0.4.9 assignment gate). Invalid value → exit 2. Headline names the gate. The three-count summary prints at every strictness. Unconfirmed MCP configs count as one possible per file.
- `--yes` — import all importable dotenv findings without selection
  prompts (password still required)
- `--no-import` — report only; never offer vault store

### `unlock` flags

- `--pre-admit` — loudly pre-admit the next client for a bounded window
- `--pre-admit-secret NAME` — scope that window (repeatable); omit for
  unscoped ALL-secrets pre-admit
- `--admit-tree` — at the first unrecognized-peer prompt, choose a
  kernel-verified ancestor as the admission root (widens trust to its
  descendants); session-only, off by default

Vault-aware commands also accept `--vault PATH`, `--global`, `--no-global`,
`--env NAME`. Guard-talking commands accept display-only `--name LABEL`.

`reveal` / `copy`: even if an agent invokes them, the value appears only in
the human's window/clipboard; the agent process gets a status flag.

Guard IPC verbs remain exactly `{run, list, lock, status, renew}`.
