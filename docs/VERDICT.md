# Verdict — what works, what doesn't, and why

Empirical history: 9 tests against the real game (log in the REA project's
capture_log.jsonl), 3 elevated memory dumps, 175/175 mock self-test. Details in
`analysis/ENVELOPE-SPEC.md` (FINAL VERDICT).

## ❌ Fake server with accepted Logon — IMPOSSIBLE (honestly closed)

The gate `FUN_141c552f0` verifies the signature of **every response** against the
**server's** public key (Turn 10). Without T10's private key:

- well-formed plaintext → rejected (tests 1-5, all framing variants);
- route A encrypted with the mock's own K → rejected (tests 6-7);
- route B signed with the **client** pair → rejected (decisive variant-9 test:
  1008B response delivered, sigOk audited, no acceptance).

There is no plaintext downgrade (the client never sends `X-Encryption`; reneg 418
does not yield plaintext). T10's private key does not exist client-side (correct
asymmetry; the 1.18GB scan confirmed) and RSA-2048 is not factorable within any
realistic budget.

The remaining route — patching the runtime verifier — is anti-tamper
circumvention (ban risk + circumvention of technical protection) and **will not
be done in this project**.

## ✅ What works

1. **The protocol is fully mapped and reproducible** — framing, schemas,
   encode/decode grammar, cryptographic envelope. The mock speaks XLS correctly
   up to the cryptographic layer (self-test 175/175; the client *processes* the
   responses — retries stretch to 21-90s on encrypted ones vs 1.5-3s on
   parse-broken ones).
2. **Passive proxy of the real service** (career WORKS): hosts → mock → TLS
   upstream to the real service. The real Logon happens on T10's server. The mock
   **observes** all subsequent methods (headers/methods/sizes).
   - ⚠️ Proxy limits: it cannot decrypt bodies (K travels RSA-OAEP to T10's
     public key) and **cannot rewrite responses** (every response >272B requires
     a T10 signature).
3. **CMS edits** (presentation): the only "edit" the client accepts — changes
   displayed level/price, but not balance/awards (see the CP report).

## 🔑 Verdict on the original goal (CP balance & awards)

**CONFIRMED by static analysis**: the XLS service is the authority for balance and
rewards. `DownloadPlayerProfile` carries per car `carPointsTotal / earned /
purchased / currentLevel / experiencePoints`; purchases are server-confirmed
transactions (`BuyCarPointsForCar` with `expectedPrice` + `creditDelta`).
The local DB (`UPDATE/SELECT CarPoints`) only **mirrors**; CMS only **presents**.
Editing balance therefore requires the server — and a fake server requires
T10's private key. Remaining honest path: passive proxy for observation.

## Design lesson

The protocol is well designed: end-to-end server signature, per-request session
key enveloped to the right public key, unconditional client-side decryption.
The mock fails exactly where the design intends it to fail.
