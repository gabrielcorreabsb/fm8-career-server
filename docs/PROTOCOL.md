# XLS Protocol (Forza Motorsport 2023) — summary

Full source: [../analysis/ENVELOPE-SPEC.md](../analysis/ENVELOPE-SPEC.md) (1459 lines).
This document consolidates the essentials for operating and understanding the mock.

## 1. Transport

- **HTTP POST** to `https://gameservices.fm.forzamotorsport.net/Services/o.xtsw`,
  `Content-Type: bin/xtsw`, UA `Xls Client`.
- **Authentication**: `Authorization: XBL3.0 x=<xuid>;<JWE>` header + `X-UserId`,
  `X-Validation` (32-hex), `X-IdempotencyId`, `X-RequestId` (== trace-id),
  `X-LanguageCodeId` (22 = pt-BR), `X-Platform` (4), `X-ContractVersion: 73`,
  `X-Version: 8.25.06.18.8597102.FMBase_LiveHotFix`.
- **Method routing**: `X-Method` header (e.g. `Logon`,
  `DownloadPlayerProfile`, `KeepAlive`). The mock routes by this header **without
  needing to decrypt the body**.

## 2. Message envelope (serialized payload)

Every XLS body is an **envelope with two wrapper fields**:

- `loginData` (id 0x10) — **request** body (nested, 272B in Logon);
- `responseData` (id 0x08) — **response** body (nested, raw, no prefix).

There is no message prefix at the top of the body — serialization is **positional**
following the descriptor's record order.

## 3. Response frame (13 bytes — NOT 12)

```
[0]     byte0   (1B, not validated by the client)
[1..4]  status  u32 BE   (0 = ok; 2 => 0x80510000|code; other => 0x8050000e)
[5..8]  code    u32 BE
[9..12] length  u32 BE   (ADVISORY — reader FUN_141c093d0 reads exactly 13;
                          wrong length shifts the parse)
```

Error if frame ≠ 13 bytes: `0x80500043`.

## 4. Method registry (dispatch)

`.data` registry of `{classPtr, methodPtr}` pairs per service (User, UserInventory,
PlayerProfile, Notifications, …). Example:

```
UserInventory @0x145b147a0:
  BuyShowroomListing    @0x1448e1970
  AddDebugCredits       @0x1448e1a30
  BuyCarPointsForCar    @0x1448e1aa8
```

Typical facade: `(*param_2+0x18)(param_2, classPtr, methodPtr, payload)` +
`Task::WebCall<...>::CreateAndCall` named `Class.Method`.

## 5. Serialization (kind semantics — wire format)

Field record: stride 0x60 `{kind u32, namePtr, id, …, size @+0x40, nested @+0x48, flags @+0x58}`.
Decode walker: `FUN_141c30860`; encode mirror: `FUN_141c34940`.
**All scalars are BIG-ENDIAN on the wire.**

| kind | type | wire |
|---|---|---|
| 0 / 0x11 | u8 / bool | 1B |
| 1 / 2 | u16 | 2B BE |
| 3 / 4 / 7 | u32 | 4B BE |
| 5 / 6 / 0x13 | i64/u64 | 8B BE |
| 0x15 / 9 | string UTF-8 | u32BE length + bytes (max in chars, no NUL, SSO in struct) |
| 0x10 | datetime | u32BE length + text `%04u-%02u-%02uT%02u:%02u:%02u.%03uZ` |
| 0xc | nested message | inline, NO prefix, positional |
| 0x16 | array | u32BE count + elements (cap 0x2000) |
| 0x17 | vector\<bool\> | u32BE count + count bytes |
| 0x12 | GUID | 16B (Data1 u32BE, Data2/3 u16BE, Data4 raw) |
| 0x14 | large string | cap 0x500000 |
| 8 / 0xa / 0xb / 0xd / 0xf | — | invalid (error 0x8050002a) |

Parse errors: `-0x7faffffc` nulls, `-0x7fafffa4` parse/limit, `-0x7faffff4`
field larger than max, `0x8050000c/4/f/2a/41` on encode.

## 6. Main messages (mock LSP)

- **Logon** (`Forza.WebServices.User`): request = `UserLogonData` (xuid, gamerTag,
  userTier, region, locale, LCID, ipAddress, machineId, macAddress — table
  0x145b28310); response = `UserLogonResponse` (31 fields, see SCHEMAS.md).
- **KeepAlive**: 12B body; class `Xls.WebServices.Utils`.
- **DownloadPlayerProfile** (`PlayerProfile`): response contains **per car**:
  carId, purchasePrice, acquisitionType, carPointsTotal, earnedCarPoints,
  purchasedCarPoints, currentLevel, experiencePoints, tiersAchieved, unredeemed
  — the service is the authority for balance/XP/level (see the CP report).
- **UserInventory**: `BuyCarPointsForCar` (request `carPointAmount` +
  `expectedPrice` client-claimed; response `updatedCar` + `creditDelta`),
  `BuyShowroomListing` (`purchaseDelta`, `priceCorrected`, `useCarKey`),
  `AddDebugCredits` (debug).

## 7. Retry and renegotiation

- Default retry policy: ratio 2.0, initial 2000ms, max 120000ms.
- HTTP **418** → DecryptKey FSM enters renegotiation (~53s pause observed);
  200..206 = ok; other status → error 0x8050xxxx. Do not send `X-Renegotiate` in
  normal responses.
- The client **never** sends `X-Encryption` in observed requests (encryption is
  unconditional on the response path — see CRYPTO.md).
