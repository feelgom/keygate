# Project vaults

Walk-up from cwd finds the nearest `.amnesia/` (stops at your home
directory). No `.amnesia/` means the global vault at `~/.key-amnesia`
(override: `KEY_AMNESIA_HOME`, `KEY_AMNESIA_VAULT_PATH`).

## Layout

```
.amnesia/
  config.json
  vault.bin                 # default env
  vault.names.json
  envs/<name>/vault.bin     # from --env / KA_ENV
  envs/<name>/vault.names.json
```

```bash
ka init --project
ka init --project --env staging
```

## Merge with global

By default `"use_global": true` in `.amnesia/config.json` — project and
global vaults merge; **project wins** on name collision. Two passwords when
both exist and both contribute. Set `"use_global": false` or pass
`--no-global` to isolate. `--global` forces the home vault; `--vault PATH`
skips discovery.

## Guard placement

Daily use: **one `ka unlock` per project vault**. Guard lock and death-state
files sit beside the active vault. A discovery-only registry at
`~/.key-amnesia/guards/` lists live guards (address/pid/expiry — **never**
the authkey).

Existing global-only setups need no migration.
