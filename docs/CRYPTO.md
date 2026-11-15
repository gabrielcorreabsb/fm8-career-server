# XLS transport cryptography and the signature gate

Full source: `analysis/ENVELOPE-SPEC.md` §§3.4, 6, RUNTIME DUMP ANALYSIS I+II,
FINAL VERDICT. Consolidated here; evidence addresses in EVIDENCE-INDEX.md.

## 1. Who encrypts what

- **Message cipher**: XLS's own implementation in `0x141c5xxxx` + CNG (bcrypt.dll
  only for RSA/hash). The "self-implemented" AES-256-CBC `FUN_1417d0af0`
  (S-box 0x1447b6d50) is **not** the message cipher — it is an in-memory blob
  obfuscator (wstring strings).
- **Pipeline** (stages): `MessagePipelineStageEncryption` (outgoing) / `Decryption`
  (incoming) do **plumbing only** (adopt `Ref<Buffer>`); the actual cipher runs in
  the **session provider** (vtable[0x30] encrypts). Response decryption is
  **unconditional**.
- **Session key K (32B) + IV**: stored at `session+0x208` / `+0x238`; AES-256
  schedule expanded at `obj+8` (0x140B) via `FUN_141c53040` (requires len==0x20).

## 2. RSA keys

| Role | Blob | Address | Note |
|---|---|---|---|
| **CLIENT pair** (private!) | `RSA2` BCRYPT_RSAPRIVATE_BLOB 542B | VA `0x1449209a0` (+dup `0x144920bd0`), dump offset `0x0491f9a0` | `keys/client_private.pem` — used by the client to **sign requests** |
| SERVER public key (Turn 10) | `RSA1` RSA-2048, e=0x10001 | VA `0x14494af60` / `0x14494b080` | used to **verify responses** |
| RSA-3072 (second public) | `RSA1` | VA `0x145a5bcf0` | — |

A complete scan of 1.18GB / 2830 memory regions confirmed: **the only private key
in the client is the client's own pair**. Turn 10's private key does not exist
client-side (correct asymmetric design).

## 3. Request shape (896B, byte-for-byte verified)

```
[0:16)     opaque session value (from session+0x238)
[16:32)    message IV (16B random) ← cipher IV
[32:640)   AES-256-CBC ct (608B, PKCS#7)
[640:896)  RSA-2048 PKCS#1 v1.5 / SHA-256 SIGNATURE over body[0:640]
           (key: CLIENT pair)
```

The session key **does not travel in the body** and is not derivable from it
(tested: 14 candidates × 3 IVs × 3 offsets = 0 hits). Each request has its own
per-session K.

## 4. Response routes

- **Route A** (min 272B): `[IV 16][AES-256-CBC/PKCS#7 ct][SIG 0x100]`
- **Route B** (min 512B): `[OAEP-SHA1(pub_client, IV2‖K‖0*16) 0x100][AES parts][SIG 0x100]`
  — the IV travels inside the OAEP blob, no plaintext IV.

Signature: PKCS#1 v1.5 / SHA-256 over the prefix `body[0:len-0x100]`.

## 5. The GATE — `FUN_141c552f0`

```
bool f(keyObj, body, size-0x100, body+size-0x100, 0x100)
```

- Runs **before** AES on both routes; `false ⇒ 0x80500060` and AES **never runs**.
- **Verifies RESPONSE signatures against the SERVER's public key (Turn 10)**,
  not against the client pair (a tail verified by the client's public key fails
  in the server slot — verified empirically, variant 9 / route B).
- The tail is written/verified **in place** as a function of the prefix.

## 6. Error fingerprints (diagnostics)

| Code | Meaning |
|---|---|
| `0x80500063` | reached AES, wrong key (mask) |
| `0x80500060` | **signature gate rejected** (or size) |
| `0x80510002` | OAEP failed or plaintext ≠ 64B |
| `0x8050000e` / `0x80500043` | decrypted but wrong internal frame/status |

## 7. The 32B mask

`K = R XOR mask`; mask lives at `crypto_ctx+0x20` (runtime, per-installation; not
a constant in the binary). Measured empirically as non-zero (test 6). Practically
irrelevant: without T10's private key the gate blocks first.

## 8. Conclusion

**Mock with accepted Logon = impossible without Turn 10's private key.**
Breaking RSA-2048 = factoring the modulus (public record 829 bits; 2048 is ~10⁹×
harder) — mathematically out of reach. Routes tested and rejected: plaintext
(all framing variants), route A (mock's own K), route B (signed with the client
key), 418 renegotiation probe. The only remaining route — patching the runtime
verifier — is anti-tamper circumvention and is **out of scope for this project**.
