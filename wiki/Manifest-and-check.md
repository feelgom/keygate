# Manifest and `ka check`

Commit `amnesia.toml` at the project root — names and metadata only, no
values:

```toml
[secrets.API_KEY]
required = true
description = "Provider API key"
env = "API_KEY"
```

`ka import` writes/merges this automatically. Legacy `[[secret]]`
array-of-tables is still read.

## CI

```bash
ka check
ka check --json
```

Compares required entries to the **project** names sidecar only — no
decrypt, no global vault. Non-zero exit on missing required secrets.

Locally, `ka run` also refuses to inject when required secrets from that
manifest are absent.

This is a **project contract / CI policy**, not cryptography.
