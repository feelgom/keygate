<p align="center">
  <img src="https://raw.githubusercontent.com/fujitoid/key-amnesia/master/media/assets/approved/logo-512.png" alt="key-amnesia" width="200">
</p>

# key-amnesia

[![tests](https://github.com/fujitoid/key-amnesia/actions/workflows/tests.yml/badge.svg)](https://github.com/fujitoid/key-amnesia/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/key-amnesia.svg)](https://pypi.org/project/key-amnesia/)
[![Discord](https://img.shields.io/discord/1531406398334832690?label=discord&logo=discord)](https://discord.gg/4WnQfk49xX)

**Let your AI agent *use* your passwords and API keys — without ever letting it *see* them.**

<!-- Absolute URL, not a repo-relative path: PyPI renders this README outside the
     repository and cannot resolve relative image paths, so a relative link shows
     as a broken image on the project page. -->
![key-amnesia — the vault hands the agent a sealed envelope it cannot open](https://raw.githubusercontent.com/fujitoid/key-amnesia/master/media/assets/approved/readme-hero.png)

AI coding agents (Claude Code, Cursor, Codex) are incredibly useful — right up until they need an API key. Then your choices are ugly: paste the key into the chat (now it lives in the conversation forever), put it in a plain-text `.env` file the agent can read, or just do that part yourself.

**key-amnesia is the fourth option.** Your secrets live in an encrypted vault. The agent can *trigger* commands that use them — but the actual values are injected directly into the command's environment, out of the agent's sight. If a command tries to print a secret, key-amnesia censors it before the agent sees the output. And the master password can only ever be typed by you, a real human, at a real keyboard: when an agent needs your approval, a **separate console window pops up on your screen** — one the agent cannot read or type into.

The agent gets amnesia. That's the whole point. And every access attempt — allowed or denied — is written to an audit log you can review.

**The part that matters more than any single integration:** MCP connectors and vendor plugins only ever cover the popular APIs someone bothered to build for. The long tail — a random SaaS's REST API, an internal tool, plain SMTP — is never coming. With key-amnesia, your agent can write itself a script against *any* API that takes a key, run it through `ka run`, and you don't have to be afraid anything leaks. Not "we integrated with X" — a general-purpose unlock for the APIs no one will ever get around to wrapping.

## How it works, in 30 seconds

```bash
# 1. Create the vault (type the master password twice to confirm)
ka init

# 2. Store a secret (you type it once, hidden, into a password prompt)
ka set OPENAI_API_KEY

# 3. The agent runs commands THROUGH key-amnesia instead of holding the key:
ka run --secret OPENAI_API_KEY --as OPENAI_API_KEY -- python my_script.py

# 4. That's it. The script gets the real key in its environment.
#    The agent sees the script's output — with any leaked key censored:
#    "Bearer ***REDACTED(OPENAI_API_KEY)***"
```

`ka init` asks for the master password twice; if the entries do not match, nothing is created. **There is no recovery** if you forget that password — Argon2id + SecretBox leave none by design.

When the agent triggers step 3 and your approval is needed, you'll see a new console window appear with a clear message — *"An agent-driven command is requesting: run with secret OPENAI_API_KEY"* — and only your password, typed there, lets it proceed. Close the window to deny. Nothing the agent controls can type into that window.

## Install

```bash
pip install key-amnesia
```

Or from source: `pip install git+https://github.com/fujitoid/key-amnesia`, or from a local clone: `pip install .` — every path gets you both the full `key-amnesia` command and the short `ka` alias.

> Windows and Linux supported; macOS still falls back to fail-closed (not yet implemented).

## Agent bootstrap

Paste this into your coding agent when you want it to install and teach itself key-amnesia (not a human pip walkthrough):

```
Install key-amnesia and set yourself up to use it correctly for secrets in
this project:
1. pip install key-amnesia
2. Verify `ka --version` works in a fresh terminal (if not found, fix PATH
   as instructed).
3. Run `ka setup` (installs its skills + safety hook globally).
4. Tell me to restart this session so the skill loads, then tell me exactly
   what to do in my OWN terminal to finish setup (master password etc.) —
   you cannot do that step yourself.
```

`ka setup` copies the bundled `key-amnesia-usage`, `key-amnesia-hygiene`, and `key-amnesia-migrate` skills to `~/.claude/skills/` and `~/.cursor/skills/`, and merges a `PreToolUse` (Claude Code) / `preToolUse` (Cursor) hook into each host's own config that blocks tool calls containing inline credential-shaped tokens. Restart or reload the host afterward to pick both up.

## Two modes: ask every time, or unlock a session

| Mode | What it feels like |
|------|--------------------|
| **`per-call`** (default) | Every use of a secret asks for your password. Maximum safety, maximum prompts. |
| **`cached`** | You run `ka unlock` once in your terminal; a background "guard" keeps the vault open for 30 minutes (configurable). Agent commands run without prompts until it expires or you run `ka lock`. |

```bash
ka config set session-mode cached   # switch (asks for your password)
ka unlock                           # start a session
ka lock                             # end it early, any time
```

`ka unlock` runs the guard *in that terminal* — it's the same window for the life of the session. The startup line tells you when it expires and how to stop it early (`Ctrl+C` or `ka lock` from another terminal); a periodic nudge repeats that even if the guard sits idle the whole time. Before it expires, the guard asks right there whether to extend. No answer means it locks itself. The first command from an unrecognized process reaching a live guard also gets a one-time yes/no admission prompt in that same window (`Session (pid ...) wants: ... Admit? [y/N]`) — approve once and a real child process of that same command tree goes straight through afterward; a genuinely separate process (even from the same shell) triggers its own prompt. If you know you're about to run a batch of agent commands from a fresh process each time, `ka unlock --pre-admit` loudly auto-admits just the *next* one, for a bounded window, without a prompt.

## Commands

| Command | What it does |
|---------|--------------|
| `ka init [--project] [--env NAME]` | Create an empty vault (type master password twice; refuse if already exists). `--project` creates `./.amnesia/vault.bin` (or `envs/NAME/`), writes `.amnesia/config.json`, and auto-adds `.amnesia/` to `.gitignore` |
| `ka passwd` / `ka change-password` | Change the master password (re-encrypts the vault with a fresh salt; refuses while a session is active) |
| `ka set NAME` | Store or update a secret (value typed hidden; password required; vault must already exist) |
| `ka remove NAME` | Delete a secret (password required) |
| `ka import FILE` | Import a dotenv-format file's `NAME=value` pairs into the resolved vault (project vault when inside a project; TTY-only) — asks before overwriting a name that already exists, and offers to delete/rename the source file, add `.env*` to `.gitignore`, and generate/merge a minimal `amnesia.toml` |
| `ka check [--json]` | Compare `amnesia.toml` required secrets to the **project** names sidecar (no decrypt, no global vault). Non-zero exit on missing required — designed for CI |
| `ka scan [--deep] [--include-excluded] [--json] [--yes] [--no-import]` | Scan for LEAK (Locally Exposed Agent Keys): plaintext secret files an agent can read. Names/paths/counts only — never values. Non-zero if any LEAK. Default skips `node_modules`/`.venv`/build/`.git`; `--deep` adds home/shell/MCP paths. Offers to store selected dotenv findings into the project vault |
| `ka run --secret NAME --as ENV_VAR -- <command>` | Run a command with the secret injected; output censored. The agent-facing command. When a project `amnesia.toml` exists, fails before inject if required secrets are missing |
| `ka list` | Show secret *names* only — never values; safe for agents, no prompt |
| `ka unlock [--pre-admit] [--pre-admit-secret NAME]` | Start a cached session; `--pre-admit` loudly auto-admits the very next connecting process for a bounded window (15m default), without a yes/no prompt — scope it to specific secrets with `--pre-admit-secret`, repeatable, or leave it off for ALL secrets |
| `ka lock` | End a cached session early |
| `ka reveal NAME` | Show a value to *you* (password required every time, even mid-session) |
| `ka copy NAME` | Copy a value to your clipboard instead of showing it (same rule) |
| `ka config show` / `ka config set KEY VALUE` | View / change settings (changes require your password) |
| `ka status` (alias `ka connect`) | Is a session active, and until when — plus, if not, what happened to the last one; lists other live guards from the discovery registry |
| `ka setup` | Install agent skills + the secret-guard hook for Claude Code / Cursor (`--skills-only` / `--hook-only`) |

Vault-aware commands also accept `--vault PATH`, `--global`, `--no-global`, and `--env NAME` to select which vault to use.

### Project vaults (since 0.3.10)

```bash
# Inside a git repo / project directory:
ka init --project          # creates .amnesia/vault.bin + config.json; gitignores .amnesia/
ka import .env             # lands in the project vault when .amnesia/ is found
ka unlock                  # prompts for project password, then (if use_global) global password
ka run --secret API_KEY -- ...
```

Walk-up from cwd finds the nearest `.amnesia/` (stops at your home directory). By default the project vault **merges** with the global `~/.key-amnesia` vault (project wins on name collision); set `"use_global": false` in `.amnesia/config.json` or pass `--no-global` to isolate. Per-environment vaults live at `.amnesia/envs/<name>/vault.bin` (`--env NAME` or `KA_ENV`). Existing global-only setups need no migration — no `.amnesia/` means everything stays global.

Daily use: **one `ka unlock` per project vault**. Guard lock + death-state files sit beside the active vault; a discovery-only registry at `~/.key-amnesia/guards/` lists live guards (address/pid/expiry — **never** the authkey).

### Project manifest + CI (`amnesia.toml`, since 0.3.11)

Commit an `amnesia.toml` at the project root declaring which secrets the project expects (no values):

```toml
[secrets.API_KEY]
required = true
description = "Provider API key"
env = "API_KEY"
```

`ka import` writes/merges this automatically. In CI, run `ka check` (or `ka check --json`) after the project vault's names sidecar is present — it compares required entries to the **project** names file only, never decrypts, never looks at the global vault, and exits non-zero on missing required secrets. Locally, `ka run` also refuses to inject when required secrets from that manifest are absent.

### LEAK scan (`ka scan`, since 0.3.12)

```bash
ka scan                  # project tree from cwd
ka scan --deep           # + home dotfiles / shell history / git config / MCP configs
ka scan --json           # machine-readable; report-only
ka scan --yes            # import all importable dotenv hits into .amnesia/ (password still required)
```

Reports **Locally Exposed Agent Keys** — files and light patterns an agent sitting in your project can read. The headline is `N LEAK found — your agent can read N secrets in this project`. Detection covers `.env*`, `credentials.json`, `.npmrc`, `.pypirc`, SSH private keys, MCP configs, and assignment patterns shared carefully with the secret-guard hook. Default exclusions skip `node_modules`, `.venv`/`venv`, common build dirs, and `.git` internals (`--include-excluded` to include them). Git-history scanning is a separate feature and is **not** part of the default path. Values are never printed. After the human report, you can store **selected** dotenv findings into the project vault (creates `.amnesia/` if needed) with the same collision / delete double-confirm / `.env.imported` / gitignore offers as `ka import`.

Every command supports `--help`.

`reveal` and `copy` deserve a special note: even if an agent invokes them, the value appears **only in the pop-up window on your screen** (or your clipboard) — the agent's own process receives nothing but a status flag. And they *always* require a fresh password, session or no session — so an agent can never ride an open session into actually reading a value.

## Under the hood

For the security-curious — the full detail lives in [DESIGN.md](DESIGN.md):

- **Encryption:** the vault is a single file sealed with XSalsa20-Poly1305 (libsodium's SecretBox) under a key derived from your master password via Argon2id at its most expensive (`SENSITIVE`) setting — deliberately slow to brute-force, and deliberately never dialed down.
- **The routing rule:** any command needing your password checks whether it's running in a real terminal. Yes → asks right there. No (an agent invoked it) → spawns a fresh, isolated console window whose keyboard input can only come from you. No interactive session at all → fails closed, never falls back to something insecure.
- **The guard never hands out secrets.** In cached mode, the guard *itself* runs your command with the secret injected and returns only the censored output and exit code. Its protocol simply has no "give me the value" request — so even another process connecting to it directly can't ask for one. Guard verbs stay exactly `run` / `list` / `lock` / `status` / `renew`.
- **Nothing sensitive on command lines.** Windows records process command lines in its audit logs (event 4688); key-amnesia passes all sensitive hand-off data between its own processes via environment variables instead.
- **Audit log:** `~/.key-amnesia/audit.log`, append-only JSON lines — timestamp, action, secret names (never values), route, allowed/denied/timeout.
- **Admission consent, bound to real process identity:** the first command from an unrecognized process reaching a live guard triggers a one-time yes/no prompt in the guard's own terminal window. Approval is tied to that connecting process's **kernel-verified identity** (its actual OS pid + creation time, confirmed by the operating system itself — not anything the client claims) — a real child process of an already-approved one is recognized automatically; a separate, unrelated process gets its own prompt. There is no on-disk admission credential to steal. This sits on top of — never replaces — the hard guarantee above.
- **Honest death reporting:** `ka lock` / `ka status` tell you what actually happened to the last session (`locked`, `expired`, `interrupted`, or `crashed: <reason>`) instead of a bare "no active session."
- **`ka import` reads the local file directly, on purpose.** Unlike `ka set`, which always has *you* type the value so nothing ever passes through an agent, `ka import` is TTY-only (never routed through the spawned-console agent-safe helper) and parses the dotenv file itself — it still never prints a value to your screen or anywhere else, and every follow-up decision (overwrite an existing name, delete or rename the source file, add `.env*` to `.gitignore`) is an explicit prompt, never silent.
- **`ka scan` is advisory.** It tells you where plaintext secrets sit so an agent can read them (LEAK = Locally Exposed Agent Keys). It never prints values, and storing findings into the vault is always an explicit post-report choice (or `--yes`), never automatic.
- **Roles (optional KAM2).** First `ka member add` upgrades the vault format after you confirm; a verified `vault.bin.kam1.bak` is written first. Per-secret wraps and `ka export --for MEMBER` are **cryptographic** (PyNaCl SealedBox). The admin signature over members/ACL is **tamper-evident only**. A `runner` identity cannot `reveal`/`copy` — that gate is **policy** against a human who still knows the master password, and **effective** against an agent enrolled as runner. Users who never enable roles stay on KAM1.

Files live in `~/.key-amnesia/` (override: `KEY_AMNESIA_HOME`, `KEY_AMNESIA_VAULT_PATH`).

## Security limits — read this part honestly

No tool in this class can promise absolute secrecy, and we'd rather tell you exactly where the edges are:

1. **A command you run can still leak its own secret.** Censoring catches exact copies of the value in output — a command that base64-encodes or otherwise obfuscates the secret before printing slips through. This limit is shared by every tool of this kind (`op run`, `teller run`).
2. **Output is not live.** Command output is collected fully, censored, then released — the agent sees it only after the command finishes.
3. **Secret *names* are stored in plain text** (so `ka list` can work without a password). Values never are. Treat names as non-sensitive labels.
4. **The pop-up window assumes the agent can't control your screen.** If you've given an agent screen-reading *and* keyboard/mouse-injection powers, the window's isolation weakens — your typed password stays hidden, but a yes/no confirmation could theoretically be clicked by such an agent. The same caveat applies to the guard's admission prompt.
5. **Headless machines fail closed.** No display → no way to approve → the operation is denied. By design.
6. **Same-user processes share your privileges.** Any program running under your OS account can talk to a live guard session (this is equally true of `ssh-agent`). That's why the guard is designed to never return raw values — the worst a rogue same-user process gets is the same bounded "run a command" capability the legitimate path has, and even that requires one admission prompt to be approved on your own screen first.
7. **The master password never crosses any inter-process channel**, in any form — it's consumed only inside the process that prompted you for it.
8. **Avoid `ka set NAME VALUE` with the value inline.** It's supported for scripting, but an inline value briefly appears on the calling process's command line — visible to same-user process inspection and Windows command-line auditing. Prefer plain `ka set NAME` and type the value at the hidden prompt. (If an agent tries the inline form, the approval window shows you the incoming value before asking for your password — so you can still deny it.)
9. **`--pre-admit` is an explicit, opt-in trust-widening you ask for.** It auto-admits whichever process happens to connect first within the window — not necessarily the one you meant — so only use it right before the command you're expecting, for a short window, and treat the loud confirmation line + audit log entry as the evidence of what it actually admitted.
10. **A live guard session reloads on change, not on a fixed schedule.** The guard checks a cheap content fingerprint (size + mtime + hash) of the vault file on every `run`/`list`/`status`; when a `ka set`/`ka remove` from another terminal changes it, the guard re-opens the vault with the SecretBox key it already derived at `ka unlock` time — no new password prompt, no Argon2id re-run — and replaces its in-memory secrets before answering. This closes the previous staleness gap (a live guard used to hold a fixed snapshot for its whole session). The tradeoff: the guard now keeps that **derived key** in memory for the life of the session, not just the plaintext secrets it already held — see DESIGN.md. A rotate mid-session is picked up on the very next `run`/`list`/`status`, no lock/unlock cycle required.
11. **Runner role is not a cryptographic ACL against you.** If your local identity is enrolled as `runner`, `ka` refuses `reveal`/`copy` — effective against an agent. Anyone who knows the master password can still decrypt the vault offline. Per-member `ka export` ciphertext *is* cryptographic (only that member's key opens it).

## CLI appearance

On a real terminal, status lines use a restrained brushed-chrome palette (cool chrome-blue for info/success, warm brass for warnings, red only for hard denials, slate for secondary/supporting detail lines like the auth prompt's secrets list). Set `NO_COLOR` or redirect output to a pipe/file and all ANSI escapes are omitted — agent-facing and scrubbed paths stay plain text. Unicode glyphs (✅ ❌ 🔒 🔓 ⏳ 💀) fall back to ASCII (`[OK]` / `[DENIED]` / `[LOCKED]` / `[LISTENING]` / `[EXPIRED]` / `[CRASHED]`) when color or unicode is unavailable. Scrubbed command output and raw revealed secret values are never styled.

## Community

Questions, bugs, and ideas: [Discord](https://discord.gg/4WnQfk49xX) or [GitHub issues](https://github.com/fujitoid/key-amnesia/issues).

## Support

key-amnesia is free and open source. If it's useful to you, you can support its development here:

<a href="https://www.buymeacoffee.com/fujitoid" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;" ></a>

## Development

```bash
pip install -e ".[dev]"
pytest
```

Design rationale, file formats, invariants: [DESIGN.md](DESIGN.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
