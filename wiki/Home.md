# key-amnesia

Encrypted secret vault for AI coding agents. The agent can **use** secrets
through `ka run` without ever **seeing** the values.

**Quick links**

- [Why not `.env`](Why-not-dotenv) — LEAK framing
- [Install](Install) — pip + `ka setup`
- [Quickstart migration](Quickstart-migration) — `import` → `scan` → `run`
- [Project vaults](Project-vaults)
- [Manifest & `ka check`](Manifest-and-check)
- [Guard & admission](Guard-and-admission)
- [Commands](Commands)
- [Roles & export](Roles-and-export) *(draft — maintainer judgement)*
- [Threat model](Threat-model) *(draft — maintainer judgement)*
- [macOS](macOS)

From a terminal: `ka docs` prints this wiki URL and tries to open it
(`ka docs --print` skips the browser).

```bash
pip install key-amnesia
ka init --project
ka import .env
ka run --secret API_KEY --as API_KEY -- python my_script.py
```

Design / on-disk formats: see `DESIGN.md` in the main repository.
