# key-amnesia

Encrypted secret vault for AI coding agents. The agent can **use** secrets
through `ka run` without ever **seeing** the values.

> **Docs as of 0.4.3.** Pages in this tree describe the shipped CLI at that
> version. The live GitHub Wiki may lag until maintainers publish from
> in-repo `wiki/` (see that directory’s `README.md` — publish instructions
> only; not a wiki page).

## How it works, in 30 seconds

```bash
pip install key-amnesia
ka setup                          # skills + secret-guard hook
ka init --project                 # or: ka init  for a global vault
ka import .env                    # TTY-only; never prints values
ka scan                           # find remaining LEAKs (names/paths only)
ka run --secret API_KEY -- python my_script.py
```

`ka run --secret NAME` injects the secret as environment variable `NAME`.
To remap the env var name: `--as NAME=ENVVAR` (vault name on the left).
Wrong forms that fail: `--as API_KEY`, `--as NAME`, `--as ENVVAR` (no `=`).

`ka init` asks for the master password twice; if the entries do not match,
nothing is created. **There is no recovery** if you forget that password.

## Pages

- [Why not `.env`](Why-not-dotenv) — LEAK framing
- [Install](Install) — pip + `ka setup`
- [Quickstart migration](Quickstart-migration) — `import` → `scan` → `run`
- [Agent usage](Agent-usage) — state-first agent path; human-only commands
- [Project vaults](Project-vaults)
- [Manifest & `ka check`](Manifest-and-check)
- [Guard & admission](Guard-and-admission)
- [Commands](Commands)
- [Roles & export](Roles-and-export) *(draft — maintainer judgement)*
- [Threat model](Threat-model) *(draft — maintainer judgement)*
- [macOS](macOS)

From a terminal: `ka docs` prints this wiki URL and tries to open it
(`ka docs --print` skips the browser).

## Platform honesty (short)

Windows and Linux are supported. macOS isolated-console spawn is
**experimental** — see [macOS](macOS).

**Windows peer identity is weaker than Linux.** Linux binds admission to
`SO_PEERCRED` (kernel-verified at accept) and rejects a peer whose kernel
uid differs from the guard’s `geteuid()`. Windows uses
`GetNamedPipeClientProcessId` then an immediate `OpenProcess` whose handle
is **held for the admission lifetime** so that PID cannot be recycled while
admitted — but the residual race between those two calls is not eliminated,
and process-tree ancestry is a consent UX (real OS descendants of an
admitted root), not an airtight boundary against in-tree malware that
already shares your account. Detail: [Threat model](Threat-model) and the
main README Security limits (§7).

Design / on-disk formats: see `DESIGN.md` in the main repository.
