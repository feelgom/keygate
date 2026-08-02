# Install

```bash
pip install key-amnesia
```

Or from source: `pip install git+https://github.com/fujitoid/key-amnesia`,
or from a local clone: `pip install .`. You get both `key-amnesia` and the
`ka` alias.

Windows and Linux are supported. macOS isolated-console spawn is
**experimental** (PID-file wrapper around Terminal.app / osascript; visible
window path unconfirmed by a real Mac user) — see [macOS](macOS).

Kernel peer-identity admission on macOS is **not** supported: lookup fails
closed, so a macOS guard cannot admit clients the way Windows/Linux do.
Experimental console spawn does not change that.

## Agent setup

```bash
ka setup
```

Copies bundled skills (`key-amnesia-usage`, `key-amnesia-hygiene`,
`key-amnesia-migrate`) into `~/.claude/skills/` and `~/.cursor/skills/`, and
merges a PreToolUse / preToolUse hook that blocks tool calls containing
inline credential-shaped tokens. Restart or reload the host afterward.

Flags: `--skills-only`, `--hook-only`.

## Agent bootstrap prompt

Paste into a coding agent:

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

## Open these docs

```bash
ka docs          # print URL + best-effort browser open
ka docs --print  # URL only
```
