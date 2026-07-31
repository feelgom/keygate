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
| `ka check [--json]` | Manifest vs project names sidecar (CI) |
| `ka scan [...]` | LEAK report; optional offer-to-import |
| `ka run --secret NAME --as ENV -- <cmd>` | Inject + scrub; agent-facing path |
| `ka list` | Names only; safe for agents; no prompt |
| `ka unlock [--pre-admit] [...]` | Start cached guard session |
| `ka lock` | End session early |
| `ka reveal NAME` / `ka copy NAME` | Human-only surface of a value; always fresh auth |
| `ka config show` / `ka config set KEY VALUE` | Settings |
| `ka status` / `ka connect` | Session status (+ registry of live guards) |
| `ka setup` | Install skills + secret-guard hook |
| `ka docs [--print]` | Print wiki URL; open browser unless `--print` |
| `ka identity create` / `show` | Local X25519 identity for KAM2 |
| `ka member add` / `list` / `remove` | Members/roles (first add enables KAM2) |
| `ka grant` / `ka revoke` | Per-secret ACL |
| `ka export --for MEMBER` | Ciphertext bundle for one member |

Vault-aware commands also accept `--vault PATH`, `--global`, `--no-global`,
`--env NAME`.

`reveal` / `copy`: even if an agent invokes them, the value appears only in
the human's window/clipboard; the agent process gets a status flag.
