# AGENTS.md — fm8-career-server

Guidance for AI agents (Claude, OpenCode, Codex, …) working in this repository.

## What this repo is

A **pseudo localhost server (mock LSP) for Forza Motorsport 2023 (FM8)**, produced
by complete reverse engineering of the game's XLS protocol. The central result:
a career on a fake server is **impossible without Turn 10's private key** — the
client verifies every response signature against the server's public key. This
repo documents the protocol exhaustively and ships a mock that works up to the
cryptographic layer.

## Read this first, in this order

1. `README.md` — overview, structure, disclaimer
2. `docs/VERDICT.md` — what works / what doesn't and why (read before proposing anything)
3. `docs/PROTOCOL.md` — XLS transport, 13-byte response frame, kind semantics
4. `docs/SCHEMAS.md` — UserLogonResponse (31 fields) and UserData (17 fields)
5. `docs/CRYPTO.md` — envelope, RSA keys, the signature gate (`FUN_141c552f0`)
6. `docs/EVIDENCE-INDEX.md` — code addresses, hashes, where the full specs live
7. `server/README.md` — how to run/operate the mock

Deep detail lives in `analysis/ENVELOPE-SPEC.md` (1459 lines) — consult it before
doubting anything in `docs/`; the docs consolidate it.

## Layout

| Path | Content |
|---|---|
| `docs/` | Consolidated documentation (start here) |
| `server/` | Mock v3: `mock_server.py`, `xls_crypto.py`, `xls_encoder.py`, `config.json`, `self_test.py` |
| `capture/` | MITM proxy (`capture_server.py`) + encrypted Logon samples (no auth headers) |
| `tools/` | `dumper.py` (memory dump: 5 modes), cert/hosts scripts (`gen_certs.py`, `setup_ca.ps1`, `restore_ca.ps1`) |
| `analysis/` | Untouched full specs from the REA investigation |
| `keys/` | **Git-ignored.** Client private key extracted from the binary — local backup only |

## Hard rules

- **Never commit `keys/`, `*.pem`, `unwrap/`, dumps or runtime logs** (gitignored).
  Never `git add -f` these paths.
- This is a **local sandbox** project: the real T10 service must never receive
  fake data; no account bypass; no anti-tamper circumvention (do not propose
  runtime patches to the signature verifier — out of scope by design).
- After any test session, the environment must be reverted:
  `powershell tools\restore_ca.ps1` (elevated) + re-enable antivirus.
- `server/config.json` `crypto.keyDir` points at `keys/` in this folder.

## Key technical facts (avoid re-deriving)

- Response frame is **13 bytes**: `byte0 | status u32BE | code u32BE | length u32BE`
  (length is advisory but wrong length shifts the parse).
- **All scalars are big-endian** on the wire; strings are `u32BE length + UTF-8`;
  datetimes are length-prefixed text; nested messages are inline and positional
  (no prefix); arrays are `u32BE count + elements`.
- The game's request (896B) = `[session16][IV16][AES-256-CBC ct 608][SIG 256]`,
  signature = PKCS#1 v1.5/SHA-256 over body[0:640] with the **client** key.
- Response routes: A `[IV][ct][SIG]` (min 272B) and B `[OAEP][ct][SIG]` (min 512B);
  the gate verifies signatures against **Turn 10's public key** → mock cannot be
  accepted without T10's private key. Error fingerprints: `0x80500060` gate,
  `0x80500063` wrong key, `0x80510002` OAEP.
- Career balance/rewards are **server-authoritative**; the local DB only mirrors;
  CMS edits only affect presentation.

## Useful commands

```powershell
cd server
python self_test.py            # expect 175/175
python mock_server.py          # TLS :443 + control :5080 (/preset/N, /auto, /status)
```

Environment redirect (tests only): `tools\setup_ca.ps1` (elevated);
revert with `tools\restore_ca.ps1` (elevated).

## Conventions

- Python 3, stdlib-first; crypto via `cryptography` with pycryptodome →
  pure-Python fallbacks (see `xls_crypto.py`).
- Keep `docs/` consolidated and short; push detail down into `analysis/`.
- Update `docs/EVIDENCE-INDEX.md` when new addresses/hashes are established.
