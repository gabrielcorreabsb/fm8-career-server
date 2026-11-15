# Mock LSP server — operations

Mock v3: answers Logon with a **cryptographically valid route A/B response**
(accepted by the mock's own audit; rejected by the game's signature gate — see
`../docs/CRYPTO.md` §8). Kept as a reference implementation of the protocol.

## Files

- `mock_server.py` — TLS server on :443 + live control on :5080
- `xls_crypto.py` — RSA2 parsing, OAEP, PKCS#1 v1.5/SHA-256, AES-256-CBC
  (cryptography → pycryptodome → pure-Python fallback)
- `xls_encoder.py` — XLS schemas + encoder/decoder (all wire kinds)
- `config.json` — account, encoding knobs, crypto settings
- `self_test.py` — 175 checks, including encrypted roundtrip

## Run

```powershell
# 1. certificates (first time) — creates certs/ under E:\Projetos\fm8-lsp-server
python tools\gen_certs.py
# or reuse the certs from E:\Projetos\fm8-lsp-server\certs

# 2. redirect (ELEVATED) — hosts entry + local CA
powershell -File tools\setup_ca.ps1     # CA thumb 3E44359E1CE489ED95792A584DB67659A7448B7B

# 3. start the mock (from server/)
python mock_server.py

# 4. launch the game; watch server\capture_log.jsonl (note: relative to the CWD)

# 5. REVERT (ELEVATED) — always at the end
powershell -File tools\restore_ca.ps1
```

## Live control (:5080)

- `GET /preset/N` — fixes response variant N (cycling off)
- `GET /auto` — re-enables auto-cycle
- `GET /status` — JSON: variant, cycle, counters, crypto stats
  (`requests_signature_verified` works OFFLINE — audit of the game's own
  request signatures)

## Variants (build order matters)

| # | Response |
|---|---|
| 1-6 | plaintext variants of framing (all REJECTED by the game) |
| 7 | HTTP 418 renegotiation probe (FSM pauses ~53s, then retries encrypted) |
| 8 | route A: `[IV][AES-256-CBC][SIG]` 768B |
| 9 | route B: `[OAEP 0x100][AES parts][SIG 0x100]` 1008B — decisive test |

Acceptance signal (none expected): 1 Logon followed by other methods
(KeepAlive/DownloadPlayerProfile) in the log + `requests_decrypted` rising.

## Known operational caveats

- `capture_log.jsonl` path is **relative to the process CWD** — always start from
  `server/`.
- Smoke requests (bodyLen < 400) get a 13B echo and do **not** consume the cycle;
  a real Logon (≥400B) after a >60s gap resets the cycle (new boot).
- `keys/` in this repo is git-ignored backup; `config.json` `crypto.keyDir` points
  at `keys/`.
- Mock state (`_logon_count`, cycle) is per-process — restart between game boots.

## Self-test

```powershell
python self_test.py   # expect 175/175
```
