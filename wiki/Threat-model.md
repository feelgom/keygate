# Threat model

> **Maintainer judgement required.** Prefer the plain voice of the README
> "Security limits" section. Do not claim OS identity binding is equally
> strong on every platform. Align policy-vs-crypto rows with DESIGN.md
> before treating this page as final.

## What key-amnesia tries to do

- Keep vault values out of agent context (chat, tool output, transcripts).
- Require a real human at a real keyboard for password and for admission.
- Never return raw secrets over guard IPC.
- Scrub exact copies of injected values from command output (best-effort).

## What it does not claim

1. **Obfuscated leaks.** Base64 / transform-before-print bypasses exact
   substring scrubbing — same class of limit as `op run` / `teller run`.
2. **Live streaming output.** Buffer-then-scrub-then-relay only.
3. **Secret names are ciphertext.** Names sidecar is plaintext by design.
4. **Agents with full UI control.** Screen + input injection weakens the
   isolated console story for yes/no clicks (typed password stays hidden).
5. **Headless approval.** No display → deny.
6. **Cross-user OS isolation inside one account.** Same-user processes
   share privileges; defence is "no value-return verb" + admission, not a
   new OS sandbox.
7. **Password never on IPC** — true; do not confuse with "derived key never
   in guard memory" (it is retained for reload).
8. **Inline `ka set NAME VALUE`** — argv exposure; prefer hidden prompt.
9. **`--pre-admit`** — consent-before → audit-after for one bounded tree.
10. **Guard reload key retention** — derived SecretBox key in memory for
    the session.
11. **Runner role** — not a crypto ACL against the master-password holder.

## Platform honesty (admission)

- **Linux:** `SO_PEERCRED` + start time — strong OS-backed identity.
- **Windows:** named-pipe client pid + held `OpenProcess` handle for the
  admission lifetime (closes post-connect PID recycle). Residual race only
  before that handle is open. Weaker than Linux peer creds against
  determined same-user attackers (injection class). Defence in depth, not
  a hard boundary.
- **Ancestry** does not stop malware the agent itself launches inside the
  admitted tree.

## Policy vs cryptography (summary)

| Feature | Class |
|---------|--------|
| Vault AEAD / Argon2id | Crypto |
| Guard never returns values over IPC | Crypto/protocol |
| Five-verb freeze | Protocol invariant |
| Output scrubbing | Best-effort |
| Derived key retained in guard | In-memory exposure (documented) |
| Kernel peer binding | OS-backed — strong Linux; weaker Windows |
| Process-tree admission | Raises scraper cost; not airtight vs in-tree malware |
| Secret-scoped grants / pre-admit | Consent UX / blast-radius policy |
| Manifest / `ka check` | Project contract / CI policy |
| Scan LEAK report | Advisory |
| KAM2 per-secret wrap / export | Crypto |
| Admin signature | Tamper-evident crypto |
| Runner no reveal/copy | Policy vs human; effective vs agent |

Canonical design text: repository `DESIGN.md`.
