# Why not `.env`

`.env` was designed for a threat model whose adversary was **git**. One line
in `.gitignore` and you were done.

That model is obsolete. The adversary is now the **agent sitting in your
project**. Anything the agent can read is a **LEAK** — Locally Exposed Agent
Key:

- `.env` / `.env.local` / `.env.production`
- credentials JSON, `.npmrc`, `.pypirc`
- SSH private keys left in the tree
- shell history and MCP configs (see `ka scan --deep`)

Pasting a key into chat is worse: it lives in the conversation (and often in
JSONL transcripts) forever.

key-amnesia stores values in an encrypted vault. Agents trigger
`ka run --secret NAME --as ENVVAR -- <command>`; injection happens in the
child environment; scrubbed output comes back. There is no "get secret" API
for the agent.

Find plaintext with:

```bash
ka scan
```

The headline looks like: `N LEAK found — your agent can read N secrets in
this project`. Names, paths, and counts only — never values. After the
report you can store selected dotenv findings into a project vault.
