# Roles and export

> **Maintainer judgement required.** This draft restates README/DESIGN
> labels. Do not soften "policy vs human / effective vs agent" or claim
> cryptographic ACLs where only policy holds. Review before publishing to
> the live wiki.

## When KAM2 appears

Users who never touch roles stay on **KAM1** forever. First
`ka member add` upgrades the vault after you confirm:

1. Announce: enabling roles upgrades format; name backup path.
2. Write `vault.bin.kam1.bak`.
3. **Verify the backup decrypts.**
4. Only then rewrite the live file.

Never silent. `--yes` skips the interactive confirm when scripting.

## Roles

| Role | Intent |
|------|--------|
| `admin` | Full member/ACL management |
| `writer` | Can mutate secrets they can unwrap |
| `runner` | `run` yes; `reveal` / `copy` no |

**Runner denial is policy** against a human who still knows the master
password, and **effective** against an agent enrolled as runner. Offline
decrypt with the master password still works.

## Crypto vs policy (KAM2)

| Capability | Class |
|------------|--------|
| Per-secret unwrap for members (SealedBox wraps) | **Cryptographic** |
| Admin signature over member/ACL metadata | **Cryptographic, detection only** (tamper-evident) |
| Runner cannot `reveal`/`copy` | **Policy** vs human; **effective** vs agent |

## Identity and export

```bash
ka identity create --label me
ka identity show                 # pubkey only
ka member add alice --pubkey HEX --role runner
ka grant API_KEY --to alice
ka export --for alice -o alice.kamx
```

`ka export --for MEMBER` writes a KAMX ciphertext bundle containing only
that member's ACL'd secrets. Full byte layout: repository `DESIGN.md`
("KAM2 specification").
