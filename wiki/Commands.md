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
| `ka scan [--deep] [--include-excluded] [--json] [--yes] [--no-import]` | LEAK report (names/paths/counts only); optional offer-to-import |
| `ka run --secret NAME [--as NAME=ENVVAR] -- <cmd>` | Inject + scrub; agent-facing path (`=` form required for `--as`) |
| `ka list` | Names only; safe for agents; no prompt |
| `ka unlock [--pre-admit] [--pre-admit-secret NAME]` | Start cached guard session (pre-admit flags opt-in) |
| `ka lock` | End session early |
| `ka reveal NAME` / `ka copy NAME` | Human-only surface of a value; always fresh auth |
| `ka config show` / `ka config set KEY VALUE` | Settings |
| `ka status` / `ka connect` | Session status (+ registry of live guards). `connect` is a **CLI alias** for `status` — not a sixth IPC verb |
| `ka setup [--skills-only] [--hook-only]` | Install skills + secret-guard hook (Claude / Cursor / Codex) |
| `ka docs [--print]` | Print wiki URL; open browser unless `--print` |
| `ka identity create` / `show` | Local X25519 identity for KAM2 |
| `ka member add` / `list` / `remove` | Members/roles (first add enables KAM2) |
| `ka grant` / `ka revoke` | Per-secret ACL |
| `ka export --for MEMBER` | Ciphertext bundle for one member |

### `run` mapping

```bash
ka run --secret API_KEY --as API_KEY=API_KEY -- python my_script.py
# or inject under the secret's own name:
ka run --secret API_KEY -- python my_script.py
```

`--as` takes `NAME=ENVVAR` only (CLI requires the `=` form). Omitting
`--as` injects the secret under its vault name.

### `scan` flags

- `--deep` — also check home dotfiles, shell history, global git config,
  known MCP paths (not a full home walk)
- `--include-excluded` — include default-excluded dirs; git-history scan
  still out of scope
- `--json` — machine-readable report
- `--yes` — import all importable dotenv findings without selection
  prompts (password still required)
- `--no-import` — report only; never offer vault store

### `unlock` flags

- `--pre-admit` — loudly pre-admit the next client for a bounded window
- `--pre-admit-secret NAME` — scope that window (repeatable); omit for
  unscoped ALL-secrets pre-admit

Vault-aware commands also accept `--vault PATH`, `--global`, `--no-global`,
`--env NAME`. Guard-talking commands accept display-only `--name LABEL`.

`reveal` / `copy`: even if an agent invokes them, the value appears only in
the human's window/clipboard; the agent process gets a status flag.

Guard IPC verbs remain exactly `{run, list, lock, status, renew}`.
