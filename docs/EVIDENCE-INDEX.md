# Evidence index

Key addresses/hashes for the binary and artifacts. Target:
`forza_steamworks_release_final.exe`
SHA-256 `89bc22cde56fe25051ac6928188488433d281e81eac6b6849a7b82415d06e37e` (x86_64 PE, ~101.5MB).

## Addresses (preferred image base 0x140000000)

### Protocol / dispatch
| Item | Address |
|---|---|
| Logon facade (slot[1] of Xls::LspMessageProviders vftable 0x14491fc68) | `0x141c44d40` |
| Pipeline builder (ILspServiceSession, retry 2.0/2000/120000) | `0x141c054e0` |
| Decode walker (wire grammar) | `0x141c30860` |
| Encode mirror | `0x141c34940` |
| Frame reader (13B, error 0x80500043) | `0x141c093d0` |
| FormatterIncoming process | `0x141c09520` |
| User registry `0x145b276e0-80`; Logon entry | `0x145b27728` |
| UserInventory registry (BuyCarPointsForCar 0x1448e1aa8) | `0x145b147a0` |
| PlayerProfile registry (DownloadPlayerProfile 0x1448d3d18) | `0x145b0e280` |
| Envelope loginData (id 0x10, inner 0x144910a78) | `0x14490d820` |
| Envelope responseData (id 0x08, inner 0x144910420) | `0x14490d8f0` |

### Schemas
| Item | Address |
|---|---|
| UserLogonResponse name/descriptor | `0x144910af0` / `0x144910420` |
| UserLogonResponse field table (31) | `0x145b28af0` (init `FUN_1400e91b0`) |
| UserData descriptor / table (17) | `0x1448dae80` / `0x145b110f0` |
| UserLogonData (request) | `0x144910c88` / table `0x145b28310` |
| DownloadPlayerProfile::Response descriptor / table | `0x145b136e8` (init `FUN_1400dbd30`) |
| DownloadPlayerProfile::Request table | `0x145b11658` (init `FUN_1400db1d0`) |
| MethodPermission desc | `0x1448ec490` |

### Cryptography
| Item | Address |
|---|---|
| Signature GATE | `0x141c552f0` |
| Route A parser / request assembler | `0x141c54050` / `0x141c547a0` |
| Route B step 1 (key roll, BCryptDecrypt private +0x170) | `0x141c53920` |
| Step 2 / CBC cortex / AES leaf / unwrap | `0x141c543f0` / `0x141c54260` / `0x141ada800` / `0x141c535d0` |
| Key expansion (len==0x20, obj+8 0x140B) | `0x141c53040` |
| Session key/IV | `session+0x208` / `+0x238` |
| 32B mask | `crypto_ctx+0x20` |
| **Client private pair** ('RSA2' 542B) | VA `0x1449209a0`, dump offset `0x0491f9a0` (+dup `0x0491fbd0`) |
| Server public keys ('RSA1' RSA-2048) | VA `0x14494af60` / `0x14494b080` |
| RSA-3072 | VA `0x145a5bcf0` |
| AES-256-CBC obfuscator (NOT the message cipher) | `0x1417d0af0` (S-box `0x1447b6d50`) |
| DecryptKey FSM | `0x141c4a600/700` (state at `this+0x94`) |
| Header X-Renegotiate / X-Encryption | `0x144920100` / `0x14494aa58` |

### CP (balance/rewards)
| Item | Address |
|---|---|
| Local DB car-row reader (Experience 0x15e, CarPoints 0x16b) | `0x1421c9170` |
| `UPDATE %s SET CarPoints = %u WHERE Id = %u` | `0x144a092a0` |
| Rewards::RewardCarPoints | `0x1449b7808` |

## Error codes
`0x80500063` wrong key · `0x80500060` gate/size · `0x80510002` OAEP ·
`0x8050000e/43` frame/status · parse negatives `-0x7fafffxx`.

## Artifacts outside this repo (REA project, `E:\Projetos\REA\output\forza-fm8-20261105\`)

- `mock-lsp\ENVELOPE-SPEC.md` (1459 lines; mirrored in `analysis/`)
- `mock-lsp\dump_text.bin` — decrypted .text dump 96,464,896B (VA 0x140001000-0x145c00000; file offset = VA − 0x140001000; dump module base 0x7ff7d4860000)
- `mock-lsp\dump_extents.bin` (35664B) — opaque extents (Denuvo-style, function-granular)
- `mock-lsp\unwrap\logon_N.{bin,unwrap.bin,meta.json}` — per-request evidence
- `lsp-capture\capture\` — full Logons + auth headers
- `CP-BALANCE-AWARDS-REPORT-20261114.md`, `XLS-FRAMING-NOTES-20261114.md`
- Analysis project: REA 6.9.0 reader (namespace `forza-reader-690-20261114`), Ghidra 12.1.4

## Samples in this repo (`capture/samples/`)

| File | Origin | Content |
|---|---|---|
| `1794711851_Logon.bin`, `1794711855_Logon.bin` | MITM capture 15/11 | encrypted Logon request body 896B (no headers) |
| `logon_1.bin`, `logon_2.bin` | test 7 (mock v3) | request bodies saved by the mock |

Useful for byte-diffing the request shape (CRYPTO.md §3) and testing decoders.
