# fm8-career-server

Pseudo localhost server (mock LSP) for **Forza Motorsport (2023 / FM8)**, built
from complete reverse engineering of the client's XLS protocol
(`forza_steamworks_release_final.exe`, SHA-256 `89bc22cd…d06e37e`).

**Original goal**: offline career with local services — actually answer the Logon
and work on top of the account state.

**Result**: a career on a fake server is **impossible without Turn 10's private
key** (see [docs/VERDICT.md](docs/VERDICT.md)). What remains, and is documented:

- the **complete XLS protocol** (framing, schemas, cryptography) — mapped and reproducible;
- an **LSP mock functional up to the cryptographic layer** (routes A/B, rejected by
  the server's signature gate);
- the viable path: **passive proxy** of the real service (real Logon, observation
  only) and **CMS edits** (the only edit the client accepts).

> ⚠️ **Disclaimer**: research project in a local sandbox. The real service never
> received fake data; this is not an account bypass; it does not bypass anti-tamper.
> Intended for protocol study.

## Structure

| Folder | Content |
|---|---|
| `docs/` | Consolidated documentation: protocol, schemas, cryptography, verdict, evidence |
| `server/` | Complete LSP mock v3 (mock_server.py + crypto + encoder + self-test) and its operations README |
| `capture/` | MITM proxy/capture + samples of real Logons (encrypted bodies, no auth headers) |
| `tools/` | Memory dumper (5 modes) and certificate/hosts scripts |
| `analysis/` | Intact full specs: ENVELOPE-SPEC.md (1459 lines), framing notes, CP report |

## Documents (read in this order)

1. **[docs/PROTOCOL.md](docs/PROTOCOL.md)** — the XLS protocol in brief
2. **[docs/SCHEMAS.md](docs/SCHEMAS.md)** — UserLogonResponse and UserData fields
3. **[docs/CRYPTO.md](docs/CRYPTO.md)** — cryptographic envelope and the signature gate
4. **[docs/VERDICT.md](docs/VERDICT.md)** — what works, what doesn't, and why
5. **[docs/EVIDENCE-INDEX.md](docs/EVIDENCE-INDEX.md)** — addresses, hashes, pointers

Mock and test-environment operation: **[server/README.md](server/README.md)**.

## Environment state

After any test session: run `tools\restore_ca.ps1` **elevated** (reverts hosts and
removes the local CA) and re-enable the antivirus. Hosts/CA should only be applied
while a test is running.

## Sanitized repository

- `keys/` (client private key extracted from the binary) exists in this folder
  **only as a local backup** and is **git-ignored** — never `git add -f keys/`.
- Samples in `capture/samples/` are encrypted bodies without headers (no XUID/auth).
- Memory dumps (96MB+), unwrap and runtime logs stay outside the repository.
