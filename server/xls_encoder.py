#!/usr/bin/env python3
"""xls_encoder.py — encoder/decoder positional XLS (`bin/xtsw`) do `Logon_Results` FM8.

Fonte de verdade: `ENVELOPE-SPEC.md` (dump de runtime + disassembly), seções 4, 5 e o
Apêndice A (encoder de referência). O mock v2 estava errado em 3 pontos que sozinhos
invalidavam o Logon: frame de 12 B (§1 — são **13**), `permissions` como nested 0x200
zerado (§5.1 — é **array kind 0x16** de `MethodPermission`, 13 B/elemento) e `userData`
com 15 campos (§5.2 — são **17**).

Regras de wire (spec §4):

  byte 0        frame: 1 byte (não validado; mock usa 0x00, knob 0x01)
  bytes 1..4    status  u32 BE (0 = ok; 2 ⇒ erro 0x80510000|code; outro ⇒ 0x8050000e)
  bytes 5..8    code    u32 BE
  bytes 9..12   length  u32 BE (= len(corpo); advisory)
  bytes 13..    corpo = UserLogonResponse cru, inline, sem wrapper

  kind 0           u8                       1 B
  kind 1, 2        u16  BE                  2 B
  kind 3, 4, 7     u32  BE                  4 B
  kind 5, 6, 0x13  u64  BE                  8 B   (bswap64 / FUN_141c3f2f0)
  kind 0x11        bool                     1 B   (cmp byte,0 / setne)
  kind 0x12        GUID 16 B: Data1 u32BE, Data2 u16BE, Data3 u16BE, Data4[8] cru
  kind 0x15, 9     u32 BE len + UTF-8 (len em BYTES; máximo do record em CHARS)
  kind 0x10        datetime TEXTO: u32 BE len + "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ"
  kind 0xc         nested INLINE, sem prefixo (campos do descriptor, em ordem)
  kind 0x16        u32 BE count + elementos (kind/descriptor do elemento)
  kind 0x17        vector<bool>: u32 BE count + count bytes 0/1
  kind 0x14        string "grande" (mesmo wire do 0x15, cap 0x500000)
  kinds 8, 0xa..0xf inválidos no encoder do cliente (0x8050002a) — nunca usados aqui

Tudo BIG-ENDIAN. Não existe prefixo de mensagem no topo do corpo (§4).
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import struct
import sys
from dataclasses import dataclass
from typing import Any, Sequence

# ----------------------------------------------------------------------------------
# kind codes (spec §4.1)
# ----------------------------------------------------------------------------------
KIND_U8 = 0x00
KIND_U16 = 0x01
KIND_U16B = 0x02
KIND_U32 = 0x03
KIND_U32B = 0x04
KIND_U64 = 0x05
KIND_U64B = 0x06
KIND_U32C = 0x07
KIND_U64C = 0x13
KIND_NESTED = 0x0C
KIND_DATETIME = 0x10
KIND_BOOL = 0x11
KIND_GUID = 0x12
KIND_STRING = 0x15
KIND_STRING_WIDE = 0x09
KIND_ARRAY = 0x16
KIND_BOOL_VECTOR = 0x17
KIND_BIG_STRING = 0x14

_U16_KINDS = (KIND_U16, KIND_U16B)
_U32_KINDS = (KIND_U32, KIND_U32B, KIND_U32C)
_U64_KINDS = (KIND_U64, KIND_U64B, KIND_U64C)
_STRING_KINDS = (KIND_STRING, KIND_STRING_WIDE, KIND_BIG_STRING)

STRING_HARD_CAP = 0x2000
BIG_STRING_CAP = 0x500000

FRAME_SIZE = 13
FRAME_SIZE_CONTROL = 12  # variante 5 (controle negativo): 12 B, DEVE ser recusado

ZERO_DATETIME = "1970-01-01T00:00:00.000Z"
DATETIME_FMT = "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ"

DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})?$"
)
_DATETIME_SCAN_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})?"
)


class XlsEncoderError(Exception):
    """Violação de schema/limite ao encodar."""


class XlsDecoderError(Exception):
    """Stream truncado/ilegível ao decodar."""


# ----------------------------------------------------------------------------------
# schema model
# ----------------------------------------------------------------------------------
@dataclass(frozen=True)
class Field:
    """Um record da field table.

    id     — record +0x10 (offset na struct); documentação apenas (wire é posicional)
    kind   — record +0x00
    name   — record +0x08
    size   — tamanho no wire quando escalar/GUID, ou tamanho da struct quando nested
    max    — coluna size/máx do record: maxlen em CHARS (string) ou cap de elementos
    nested — nome do schema nested (kind 0xc) ou do ELEMENTO (kind 0x16)
    elem_kind — kind do elemento quando o array não é de record
    note   — procedência
    """

    id: int
    kind: int
    name: str
    size: int = 0
    max: int = 0
    nested: str | None = None
    elem_kind: int | None = None
    note: str = ""
    default: Any = None

    @property
    def is_nested(self) -> bool:
        return self.kind == KIND_NESTED and self.nested is not None

    @property
    def is_array(self) -> bool:
        return self.kind in (KIND_ARRAY, KIND_BOOL_VECTOR)


# ----------------------------------------------------------------------------------
# §5.3 MethodPermission — tabela 0x1448ec300, 4 campos, 13 B no wire
# ----------------------------------------------------------------------------------
SCHEMA_METHOD_PERMISSION: tuple[Field, ...] = (
    Field(0x08, KIND_U32C, "methodId", 4),
    Field(0x0C, KIND_U32C, "tier", 4),
    Field(0x10, KIND_BOOL, "isEnabled", 1),
    Field(0x14, KIND_U32C, "access", 4),
)

# ----------------------------------------------------------------------------------
# §5.2 userData — descriptor 0x1448dae80 → tabela 0x145b110f0, count = 17 (80 B wire
# com gamerTag "TestDriver"); correção vs notas §8 (que paravam em 15)
# ----------------------------------------------------------------------------------
SCHEMA_USER_DATA: tuple[Field, ...] = (
    Field(0x08, KIND_U64B, "qwXuid", 8),
    Field(0x10, KIND_STRING, "wzGamerTag", max=15),
    Field(0x30, KIND_U8, "flags", 1),
    Field(0x34, KIND_GUID, "clubId", 16),
    Field(0x48, KIND_STRING, "clubTag", max=4),
    Field(0x68, KIND_U32, "clubTopTierCount", 4),
    Field(0x6C, KIND_U32B, "roleInClub", 4),
    Field(0x70, KIND_U16B, "currentBadgeId", 2),
    Field(0x72, KIND_U16B, "currentPlayerTitleId", 2),
    Field(0x74, KIND_U32B, "currentCarCollectionScore", 4),
    Field(0x78, KIND_U16B, "currentCarCollectionTier", 2),
    Field(0x7C, KIND_U32B, "currentDriverLevel", 4, default=1),
    Field(0x80, KIND_U32B, "currentPrestigeRank", 4),
    Field(0x84, KIND_U32, "currentDriverModelId", 4),
    Field(0x88, KIND_ARRAY, "customizationSlotsV2", max=30, elem_kind=KIND_U32B,
          note="30 x u32 (kind 4)"),
    Field(0xA0, KIND_U16, "region", 2, note="CORRECAO vs mock v2 (campo ausente)"),
    Field(0xA2, KIND_BOOL, "recentlySeen", 1, note="CORRECAO vs mock v2 (campo ausente)"),
)

# ----------------------------------------------------------------------------------
# §5.4 allCarDiscount / allPartsDiscount — 5 campos, 68 B no wire
# ----------------------------------------------------------------------------------
SCHEMA_DISCOUNT: tuple[Field, ...] = (
    Field(0x08, KIND_U32C, "TokenDiscountAmount", 4, note="u32-kind7"),
    Field(0x0C, KIND_U32C, "CreditDiscountAmount", 4, note="u32-kind7"),
    Field(0x10, KIND_DATETIME, "StartDate"),
    Field(0x20, KIND_DATETIME, "EndDate"),
    Field(0x30, KIND_U32, "OfferId", 4, note="u32-kind3"),
)

# §5.5 cmsInformation — 5 campos, 20 B no wire (ids não recuperados)
SCHEMA_CMS_INFORMATION: tuple[Field, ...] = (
    Field(0x00, KIND_STRING, "Header", max=60),
    Field(0x00, KIND_STRING, "Override", max=30),
    Field(0x00, KIND_STRING, "SlotId", max=20),
    Field(0x00, KIND_STRING, "SnapId", max=20),
    Field(0x00, KIND_U32, "Version", 4),
)

# §5.5 availabilityInformation — 3 campos, 57 B no wire (ids não recuperados)
SCHEMA_AVAILABILITY_INFORMATION: tuple[Field, ...] = (
    Field(0x00, KIND_BOOL, "IsCurrentlyAvailable", 1),
    Field(0x00, KIND_DATETIME, "NearestWindowOpenTime"),
    Field(0x00, KIND_DATETIME, "NearestWindowCloseTime"),
)

# ----------------------------------------------------------------------------------
# §5.1 UserLogonResponse — descriptor 0x144910420 → tabela 0x145b28af0, count = 31
# ----------------------------------------------------------------------------------
SCHEMA_USER_LOGON_RESPONSE: tuple[Field, ...] = (
    Field(0x008, KIND_BOOL, "isProfileValid", 1, default=True),
    Field(0x010, KIND_ARRAY, "permissions", max=512, nested="MethodPermission",
          note="CORRIGIDO: array kind 0x16 (era nested 0x200 zerado no mock v2)"),
    Field(0x028, KIND_U32B, "featureAreasBanMask", 4),
    Field(0x02C, KIND_U32B, "userFlags", 4),
    Field(0x030, KIND_U64, "upsellOfferId", 8, note="i64 (kind 5)"),
    Field(0x038, KIND_STRING, "upsellText", max=300),
    Field(0x058, KIND_ARRAY, "vipOfferIds", max=16, elem_kind=KIND_U64,
          note="elemento Int64 (kind 5), NAO datetime"),
    Field(0x070, KIND_NESTED, "userData", 168, nested="UserData", note="17 campos (§5.2)"),
    Field(0x118, KIND_GUID, "SecurityId", 16),
    Field(0x128, KIND_U16, "notificationNonce", 2),
    Field(0x12C, KIND_U32, "notificationPollIntervalSeconds", 4, default=60),
    Field(0x130, KIND_U32B, "defaultFriendsPollIntervalSeconds", 4, default=60),
    Field(0x134, KIND_U32B, "maxFriendsPollIntervalSeconds", 4, default=60),
    Field(0x138, KIND_ARRAY, "notificationCategories", max=9,
          nested="XlsNotificationCategory", note="elemento NAO decomposto (88 B) — count=0"),
    Field(0x150, KIND_U32, "defaultTimeoutMs", 4, default=4000),
    Field(0x154, KIND_U32, "defaultContentTimeoutMs", 4, default=60000),
    Field(0x158, KIND_U32, "defaultInGameTimeoutMs", 4, default=60000),
    Field(0x160, KIND_ARRAY, "makeDiscounts", max=100, nested="MakeDiscountData",
          note="elemento NAO decomposto (56 B) — count=0"),
    Field(0x178, KIND_ARRAY, "carDiscounts", max=100, nested="CarDiscountData",
          note="elemento NAO decomposto (56 B) — count=0"),
    Field(0x190, KIND_NESTED, "allCarDiscount", 56, nested="Discount"),
    Field(0x1C8, KIND_ARRAY, "makePartsDiscounts", max=100,
          nested="MakePartDiscountData", note="elemento NAO decomposto — count=0"),
    Field(0x1E0, KIND_ARRAY, "carPartsDiscounts", max=100, nested="CarPartDiscountData",
          note="elemento NAO decomposto — count=0"),
    Field(0x1F8, KIND_NESTED, "allPartsDiscount", 56, nested="Discount"),
    Field(0x230, KIND_ARRAY, "featuredUserEntries", max=10, elem_kind=KIND_U32B,
          note="elemento u32 (kind 4)"),
    Field(0x248, KIND_ARRAY, "pushNotificationTags", max=20, nested="PushNotificationTag",
          note="elemento NAO decomposto (40 B) — count=0"),
    Field(0x260, KIND_NESTED, "cmsInformation", 144, nested="CmsInformation"),
    Field(0x2F0, KIND_NESTED, "availabilityInformation", 48,
          nested="AvailabilityInformation"),
    Field(0x320, KIND_STRING, "FlightRingId", max=64),
    Field(0x340, KIND_DATETIME, "systemTimeUTC"),
    Field(0x350, KIND_DATETIME, "lastZendeskTicketCreateTime"),
    Field(0x360, KIND_ARRAY, "banData", max=20, nested="UserBanData",
          note="elemento NAO decomposto (152 B) — count=0"),
)

# Nested cuja tabela FOI recuperada (§5.2-§5.5, Apêndice A).
NESTED_SCHEMAS: dict[str, tuple[Field, ...]] = {
    "MethodPermission": SCHEMA_METHOD_PERMISSION,
    "UserData": SCHEMA_USER_DATA,
    "Discount": SCHEMA_DISCOUNT,
    "CmsInformation": SCHEMA_CMS_INFORMATION,
    "AvailabilityInformation": SCHEMA_AVAILABILITY_INFORMATION,
}

# Elementos citados pela spec mas NÃO decompostos (§9.4: manter count = 0).
UNDECOMPOSED_ELEMENTS: dict[str, int] = {
    "XlsNotificationCategory": 88,
    "MakeDiscountData": 56,
    "CarDiscountData": 56,
    "MakePartDiscountData": 56,
    "CarPartDiscountData": 56,
    "PushNotificationTag": 40,
    "UserBanData": 152,
}

SCHEMAS: dict[str, tuple[Field, ...]] = {
    "UserLogonResponse": SCHEMA_USER_LOGON_RESPONSE,
    "UserData": SCHEMA_USER_DATA,
    "MethodPermission": SCHEMA_METHOD_PERMISSION,
    "Discount": SCHEMA_DISCOUNT,
    "CmsInformation": SCHEMA_CMS_INFORMATION,
    "AvailabilityInformation": SCHEMA_AVAILABILITY_INFORMATION,
}

ALIASES: dict[str, tuple[str, ...]] = {
    "qwXuid": ("xuid",),
    "wzGamerTag": ("gamerTag", "gamertag"),
    "SecurityId": ("securityId",),
    "systemTimeUTC": ("systemTimeUtc",),
}


@dataclass
class EncodeOptions:
    """Knobs do envelope (as variantes A/B da §7.4). Gramática não é configurável.

    frame_byte0 — byte 0 do frame (variante 4 usa 0x01; default 0x00)
    frame_size  — 13 (spec) ou 12 (variante 5, controle negativo: DEVE falhar)
    body_prefix — prefixo de 2 B {isVip, isUltimateVip} antes de isProfileValid (§9.2)
    status/code — injeção de erro no frame (status 0 = ok; 2 = 0x80510000|code)
    """

    frame_byte0: int = 0x00
    frame_size: int = FRAME_SIZE
    body_prefix: bool = False
    is_vip: bool = False
    is_ultimate_vip: bool = False
    status: int = 0
    code: int = 0

    def validated(self) -> "EncodeOptions":
        if not 0 <= int(self.frame_byte0) <= 0xFF:
            raise XlsEncoderError(f"frame_byte0: {self.frame_byte0!r} fora de 0..0xff")
        if int(self.frame_size) not in (FRAME_SIZE, FRAME_SIZE_CONTROL):
            raise XlsEncoderError(f"frame_size: {self.frame_size!r} (use 13; 12 só como "
                                  "controle negativo)")
        if int(self.status) not in (0, 2):
            raise XlsEncoderError(f"status: {self.status!r} (0 = ok, 2 = erro com code)")
        if int(self.code) > 0xFFFFFFFF:
            raise XlsEncoderError(f"code: {self.code!r} > u32")
        return self

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "EncodeOptions":
        opts = cls()
        for key, value in (data or {}).items():
            attr = {
                "frameByte0": "frame_byte0",
                "frameSize": "frame_size",
                "bodyPrefix": "body_prefix",
                "isVip": "is_vip",
                "isUltimateVip": "is_ultimate_vip",
                "byte0": "frame_byte0",
                "size": "frame_size",
            }.get(key, key)
            if hasattr(opts, attr) and value is not None:
                setattr(opts, attr, value)
        return opts.validated()


# ----------------------------------------------------------------------------------
# variantes A/B da §7.4 (selecionáveis no config, sem editar código)
# ----------------------------------------------------------------------------------
VARIANT_PRESETS: dict[str, dict[str, Any]] = {
    "1": {"frameByte0": 0x00, "frameSize": 13, "xEncryption": None,
          "permissions": "empty", "bodyPrefix": False},
    "2": {"frameByte0": 0x00, "frameSize": 13, "xEncryption": None,
          "permissions": "one", "bodyPrefix": False},
    "3": {"frameByte0": 0x00, "frameSize": 13, "xEncryption": "false",
          "permissions": "empty", "bodyPrefix": False},
    "4": {"frameByte0": 0x01, "frameSize": 13, "xEncryption": None,
          "permissions": "empty", "bodyPrefix": False},
    "5": {"frameByte0": 0x00, "frameSize": FRAME_SIZE_CONTROL, "xEncryption": None,
          "permissions": "empty", "bodyPrefix": False},
    "6": {"frameByte0": 0x00, "frameSize": 13, "xEncryption": None,
          "permissions": "empty", "bodyPrefix": True,
          "note": "§9.2: prefixo de 2 B {isVip,isUltimateVip} no inicio do corpo"},
    "8": {"frameByte0": 0x00, "frameSize": 13, "xEncryption": None,
          "permissions": "one", "bodyPrefix": False, "encrypted": True, "route": "A",
          "note": "mock v3: corpo da variante 2 cifrado (IV||AES-256-CBC||RSA-256); "
                  "o frame 13 B vai DENTRO do plaintext (ENVELOPE-SPEC R6)"},
    "9": {"frameByte0": 0x00, "frameSize": 13, "xEncryption": None,
          "permissions": "one", "bodyPrefix": False, "encrypted": True, "route": "B",
          "note": "mock v3 rota B: OAEP(IV||K||0*16) na frente + AES-256-CBC no meio + "
                  "SIG PKCS#1v1.5/SHA-256 do prefixo no fim (ENVELOPE-SPEC E6/E8.3)"},
}

DEFAULT_PERMISSION = {"methodId": 1, "tier": 0, "isEnabled": 1, "access": 0}


@dataclass
class VariantSettings:
    active: str = "1"
    frame_byte0: int = 0x00
    frame_size: int = FRAME_SIZE
    x_encryption: str | None = None
    permissions: str = "empty"     # "empty" | "one"
    body_prefix: bool = False
    encrypted: bool = False        # variante 8/9: body cifrado
    route: str = "A"               # "A" = IV||ct||RSA256 | "B" = OAEP||ct||SIG

    def describe(self) -> str:
        return (f"variant={self.active} frameSize={self.frame_size} "
                f"b0=0x{self.frame_byte0:02x} perms={self.permissions} "
                f"bodyPrefix={int(self.body_prefix)} "
                f"X-Encryption:{self.x_encryption or '-'}"
                + (" enc=1(OAEP||AES-256-CBC||SIG256) route=B"
                   if self.encrypted and self.route.upper() == "B" else "")
                + (" enc=1(IV||AES-256-CBC||RSA256) route=A"
                   if self.encrypted and self.route.upper() != "B" else ""))


def resolve_variant(config: dict[str, Any]) -> VariantSettings:
    """`variants.active` escolhe um preset; `variants.overrides` sobrescreve chaves."""
    block = config.get("variants") or {}
    active = str(block.get("active", "1")).strip().lower() or "1"
    presets = block.get("presets") or VARIANT_PRESETS
    preset = dict(presets.get(active, {}))
    preset.update({k: v for k, v in (block.get("overrides") or {}).items() if v is not None})
    settings = VariantSettings(active=active)
    if "frameByte0" in preset:
        settings.frame_byte0 = int(preset["frameByte0"])
    if "frameSize" in preset:
        settings.frame_size = int(preset["frameSize"])
    if "xEncryption" in preset:
        settings.x_encryption = preset["xEncryption"]
    if "permissions" in preset:
        settings.permissions = str(preset["permissions"])
    if "bodyPrefix" in preset:
        settings.body_prefix = bool(preset["bodyPrefix"])
    if "encrypted" in preset:
        settings.encrypted = bool(preset["encrypted"])
    if "route" in preset:
        settings.route = str(preset["route"]).upper() or "A"
    if settings.route not in ("A", "B"):
        raise XlsEncoderError(f"route: {settings.route!r} (use 'A' ou 'B')")
    return settings


def options_for(config: dict[str, Any]) -> EncodeOptions:
    """EncodeOptions efetivas = preset de variante + bloco `frame` do config."""
    variant = resolve_variant(config)
    frame = {k: v for k, v in (config.get("frame") or {}).items() if v is not None}
    opts = EncodeOptions(
        frame_byte0=int(frame.get("byte0", variant.frame_byte0)),
        frame_size=int(frame.get("size", variant.frame_size)),
        body_prefix=bool(frame.get("bodyPrefix", variant.body_prefix)),
        is_vip=bool(frame.get("isVip", False)),
        is_ultimate_vip=bool(frame.get("isUltimateVip", False)),
        status=int(frame.get("status", 0)),
        code=int(frame.get("code", 0)),
    )
    return opts.validated()


# ----------------------------------------------------------------------------------
# valores
# ----------------------------------------------------------------------------------
def format_datetime(value: Any) -> str:
    """datetime / epoch / texto -> TEXTO do encoder (`%04u-%02u-%02uT%02u:%02u:%02u.%03uZ`)."""
    if isinstance(value, str):
        text = value.strip()
        if text.lower() in ("auto", "now"):
            value = _dt.datetime.now(tz=_dt.timezone.utc)
        else:
            if not DATETIME_RE.match(text):
                raise XlsEncoderError(
                    f"datetime {value!r}: esperado yyyy-mm-ddThh:mm:ss[.mmm][Z|+HH:MM]")
            return text  # passthrough (como o encoder de referencia: dt = s)
    if isinstance(value, _dt.datetime):
        return DATETIME_FMT % (value.year, value.month, value.day, value.hour,
                               value.minute, value.second, value.microsecond // 1000)
    if isinstance(value, (int, float)):
        stamp = _dt.datetime.fromtimestamp(value, tz=_dt.timezone.utc)
        return DATETIME_FMT % (stamp.year, stamp.month, stamp.day, stamp.hour,
                               stamp.minute, stamp.second, stamp.microsecond // 1000)
    raise XlsEncoderError(f"datetime {value!r}: tipo {type(value).__name__} não suportado")


def guid_wire(value: Any) -> bytes:
    """`guid(h)` do Apêndice A: inverte Data1(4)/Data2(2)/Data3(2), Data4 cru.

    Entrada = 16 B em hex na ordem de STRUCT/arquivo (sem dashes; com dashes é aceito e
    os separadores são ignorados). Wire = Data1/2/3 em BIG-ENDIAN + Data4 (8 B) cru.
    """
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    elif isinstance(value, str) and value:
        raw = bytes.fromhex(value.replace("-", "").replace(" ", ""))
    else:
        raw = b""
    if len(raw) > 16:
        raise XlsEncoderError(f"GUID: {len(raw)} bytes > 16")
    raw = raw.ljust(16, b"\x00")
    return raw[0:4][::-1] + raw[4:6][::-1] + raw[6:8][::-1] + raw[8:16]


def guid_from_wire(raw: bytes) -> str:
    """Inverso de `guid_wire` (volta para a ordem de struct, hex)."""
    if len(raw) != 16:
        raise XlsDecoderError(f"GUID: {len(raw)} bytes != 16")
    return (raw[0:4][::-1] + raw[4:6][::-1] + raw[6:8][::-1] + raw[8:16]).hex()


def _lookup(data: dict[str, Any], name: str) -> tuple[bool, Any]:
    if name in data:
        return True, data[name]
    for alias in ALIASES.get(name, ()):
        if alias in data:
            return True, data[alias]
    lowered = {k.lower(): v for k, v in data.items() if isinstance(k, str)}
    for key in (name, *ALIASES.get(name, ())):
        if key.lower() in lowered:
            return True, lowered[key.lower()]
    return False, None


def _u(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if value is None or value == "":
        return 0
    return int(value)


# ----------------------------------------------------------------------------------
# encoder
# ----------------------------------------------------------------------------------
def _encode_field(f: Field, value: Any, path: list[str], trace: list | None) -> bytes:
    kind = f.kind
    where = ".".join(path + [f.name])

    if f.is_nested:
        payload = value if isinstance(value, dict) else {}
        return _encode_message(NESTED_SCHEMAS[f.nested], payload, path + [f.name], trace)

    if f.is_array:
        items = list(value or [])
        if f.max and len(items) > f.max:
            raise XlsEncoderError(f"{where}: {len(items)} elementos > max {f.max}")
        out = struct.pack(">I", len(items))
        if f.kind == KIND_BOOL_VECTOR:
            out += bytes(1 if item else 0 for item in items)
            return out
        for index, item in enumerate(items):
            item_path = path + [f"{f.name}[{index}]"]
            if f.nested:
                if f.nested in UNDECOMPOSED_ELEMENTS:
                    raise XlsEncoderError(
                        f"{'.'.join(item_path)}: elemento {f.nested} NAO decomposto "
                        f"({UNDECOMPOSED_ELEMENTS[f.nested]} B) - spec 9.4 exige "
                        "count = 0 nesse array")
                out += _encode_nested_by_name(f.nested, item, item_path, trace)
            elif f.elem_kind is not None:
                out += _encode_scalar(f.elem_kind, item, ".".join(item_path))
            else:
                raise XlsEncoderError(f"{'.'.join(item_path)}: elemento sem kind/schema")
        return out

    if kind in _STRING_KINDS:
        text = "" if value is None else str(value)
        raw = text.encode("utf-8")
        if f.max and len(text) > f.max:
            raise XlsEncoderError(f"{where}: {len(text)} chars > maxlen {f.max}")
        cap = BIG_STRING_CAP if kind == KIND_BIG_STRING else STRING_HARD_CAP
        if len(raw) > cap:
            raise XlsEncoderError(f"{where}: {len(raw)} bytes > cap 0x{cap:x}")
        return struct.pack(">I", len(raw)) + raw

    if kind == KIND_DATETIME:
        return (lambda raw: struct.pack(">I", len(raw)) + raw)(
            format_datetime(value if value is not None else ZERO_DATETIME).encode("utf-8"))

    if kind == KIND_GUID:
        return guid_wire(value)

    return _encode_scalar(kind, value, where)


def _encode_scalar(kind: int, value: Any, where: str) -> bytes:
    if kind == KIND_U8:
        num = _u(value)
        if not 0 <= num <= 0xFF:
            raise XlsEncoderError(f"{where}: {num} fora de u8")
        return bytes([num])
    if kind == KIND_BOOL:
        return bytes([1 if _u(value) else 0])
    if kind in _U16_KINDS:
        num = _u(value)
        if not 0 <= num <= 0xFFFF:
            raise XlsEncoderError(f"{where}: {num} fora de u16")
        return struct.pack(">H", num)
    if kind in _U32_KINDS:
        num = _u(value) & 0xFFFFFFFF
        return struct.pack(">I", num)
    if kind in _U64_KINDS:
        return struct.pack(">Q", _u(value) & 0xFFFFFFFFFFFFFFFF)
    raise XlsEncoderError(f"{where}: kind 0x{kind:02x} não suportado pelo encoder")


def _encode_nested_by_name(name: str, value: Any, path: list[str],
                           trace: list | None) -> bytes:
    schema = NESTED_SCHEMAS.get(name)
    if schema is None:
        raise XlsEncoderError(f"nested {name!r}: tabela não modelada")
    payload = value if isinstance(value, dict) else {}
    return _encode_message(schema, payload, path, trace)


def _encode_message(schema: Sequence[Field], data: dict[str, Any] | None,
                    path: list[str] | None = None,
                    trace: list | None = None, base: int = 0) -> bytes:
    data = data or {}
    path = path or []
    parts: list[bytes] = []
    offset = 0
    for f in schema:
        present, value = _lookup(data, f.name)
        if not present or value is None:
            value = _default_for(f)
        entry = None
        if trace is not None:
            entry = {"field": ".".join(path + [f.name]), "kind": f.kind, "id": f.id,
                     "offset": base + offset, "length": 0}
            trace.append(entry)
        chunk = _encode_field(f, value, path, trace)
        if entry is not None:
            entry["length"] = len(chunk)
        parts.append(chunk)
        offset += len(chunk)
    return b"".join(parts)


def _default_for(f: Field) -> Any:
    if f.default is not None:
        return f.default
    if f.is_nested:
        return {}
    if f.is_array:
        return []
    if f.kind in _STRING_KINDS:
        return ""
    if f.kind == KIND_DATETIME:
        return ZERO_DATETIME
    if f.kind == KIND_GUID:
        return b"\x00" * 16
    return 0


def _resolve_user_data(profile: dict[str, Any]) -> dict[str, Any]:
    nested = profile.get("userData") if isinstance(profile.get("userData"), dict) else {}
    merged: dict[str, Any] = {}
    for f in SCHEMA_USER_DATA:
        present, value = _lookup(nested, f.name)
        if not present or value is None:
            present, value = _lookup(profile, f.name)
        if present and value is not None:
            merged[f.name] = value
    return merged


def _body_profile(profile: dict[str, Any], variant: VariantSettings | None) -> dict[str, Any]:
    """Aplica o preset de variante ao profile (permissions empty/one) sem mutar o input."""
    data = {k: v for k, v in profile.items()
            if k not in ("variants", "frame", "encoding", "server", "userData", "permissions")}
    user_data = _resolve_user_data(profile)
    if user_data:
        data["userData"] = user_data
    permissions = profile.get("permissions")
    mode = variant.permissions if variant is not None else "config"
    if mode == "empty":
        data["permissions"] = []
    elif mode == "one":
        data["permissions"] = profile.get("permissions") or [dict(DEFAULT_PERMISSION)]
    elif permissions is not None:
        data["permissions"] = permissions
    return data


def encode_user_logon_response(profile: dict[str, Any] | None = None,
                               options: EncodeOptions | dict | None = None,
                               trace: list | None = None,
                               variant: VariantSettings | None = None) -> bytes:
    """Serializa o corpo do `Logon_Results` = UserLogonResponse cru (§5.1, ordem da tabela).

    `profile` = config.json (chaves planas + `userData`/`permissions`/`variants`). O que
    faltar cai nos defaults: 0 / "" / [] / GUID zerado / `1970-01-01T00:00:00.000Z`.
    Não inclui frame nem prefixo de 2 B (isso é `build_frame` / `encode_response`).
    """
    profile = dict(profile or {})
    if isinstance(options, dict):
        options = EncodeOptions.from_dict(options)
    opts = (options or EncodeOptions()).validated()
    data = _body_profile(profile, variant)
    body = _encode_message(SCHEMA_USER_LOGON_RESPONSE, data, trace=trace)
    if opts.body_prefix:
        body = bytes([1 if opts.is_vip else 0, 1 if opts.is_ultimate_vip else 0]) + body
    return body


def encode_user_data(profile: dict[str, Any] | None = None) -> bytes:
    profile = dict(profile or {})
    return _encode_message(SCHEMA_USER_DATA, _resolve_user_data(profile))


def build_frame(body: bytes, options: EncodeOptions | None = None) -> bytes:
    """Frame do envelope: 13 B = byte0 | status u32 BE | code u32 BE | length u32 BE (§1.4)."""
    opts = (options or EncodeOptions()).validated()
    if opts.frame_size == FRAME_SIZE_CONTROL:  # variante 5: 12 B, de propósito quebrado
        return struct.pack(">III", opts.status, opts.code, len(body)) + body
    return (bytes([opts.frame_byte0])
            + struct.pack(">III", opts.status, opts.code, len(body)) + body)


def encode_response(profile: dict[str, Any] | None = None,
                    options: EncodeOptions | None = None,
                    trace: list | None = None,
                    variant: VariantSettings | None = None) -> bytes:
    """`frame + corpo` (o que vai no HTTP body)."""
    profile = dict(profile or {})
    opts = options or (EncodeOptions.from_dict(profile.get("frame"))
                       if profile.get("frame") else EncodeOptions())
    body = encode_user_logon_response(profile, opts, trace=trace, variant=variant)
    return build_frame(body, opts)


def encode_config(config: dict[str, Any], trace: list | None = None) -> bytes:
    """Atalho para o mock: variante + frame resolvidos do próprio config."""
    variant = resolve_variant(config)
    opts = options_for(config)
    return encode_response(config, opts, trace=trace, variant=variant)


# ----------------------------------------------------------------------------------
# decoder (espelho; só para checagem de roundtrip)
# ----------------------------------------------------------------------------------
def _decode_field(f: Field, buf: bytes, pos: int, path: list[str],
                  trace: list | None) -> tuple[Any, int]:
    kind = f.kind
    where = ".".join(path + [f.name])

    if f.is_nested:
        return _decode_nested_by_name(f.nested, buf, pos, path + [f.name], trace)

    if f.is_array:
        count, pos = _read_u32(buf, pos, where)
        if f.max and count > f.max:
            raise XlsDecoderError(f"{where}: count {count} > max {f.max}")
        if f.kind == KIND_BOOL_VECTOR:
            if pos + count > len(buf):
                raise XlsDecoderError(f"{where}: vector<bool> truncado")
            return [bool(b) for b in buf[pos:pos + count]], pos + count
        items = []
        for index in range(count):
            item_path = path + [f"{f.name}[{index}]"]
            if f.nested:
                item, pos = _decode_nested_by_name(f.nested, buf, pos, item_path, trace)
            elif f.elem_kind is not None:
                item, pos = _decode_scalar(f.elem_kind, buf, pos, ".".join(item_path))
            else:
                raise XlsDecoderError(f"{'.'.join(item_path)}: elemento sem kind/schema")
            items.append(item)
        return items, pos

    if kind in _STRING_KINDS:
        length, pos = _read_u32(buf, pos, where)
        if length > BIG_STRING_CAP:
            raise XlsDecoderError(f"{where}: len {length} > cap")
        if pos + length > len(buf):
            raise XlsDecoderError(f"{where}: string truncada em {pos}")
        return buf[pos:pos + length].decode("utf-8", "replace"), pos + length

    if kind == KIND_DATETIME:
        length, pos = _read_u32(buf, pos, where)
        if length > 64 or pos + length > len(buf):
            raise XlsDecoderError(f"{where}: datetime truncada em {pos}")
        text = buf[pos:pos + length].decode("ascii", "replace")
        if not DATETIME_RE.match(text):
            raise XlsDecoderError(f"{where}: datetime ilegível {text!r}")
        return text, pos + length

    if kind == KIND_GUID:
        if pos + 16 > len(buf):
            raise XlsDecoderError(f"{where}: GUID truncado")
        return guid_from_wire(buf[pos:pos + 16]), pos + 16

    return _decode_scalar(kind, buf, pos, where)


def _decode_scalar(kind: int, buf: bytes, pos: int, where: str) -> tuple[Any, int]:
    if kind == KIND_U8:
        if pos + 1 > len(buf):
            raise XlsDecoderError(f"{where}: truncado")
        return buf[pos], pos + 1
    if kind == KIND_BOOL:
        if pos + 1 > len(buf):
            raise XlsDecoderError(f"{where}: truncado")
        return bool(buf[pos]), pos + 1
    if kind in _U16_KINDS:
        if pos + 2 > len(buf):
            raise XlsDecoderError(f"{where}: truncado")
        return struct.unpack_from(">H", buf, pos)[0], pos + 2
    if kind in _U32_KINDS:
        value, pos = _read_u32(buf, pos, where)
        return value, pos
    if kind in _U64_KINDS:
        if pos + 8 > len(buf):
            raise XlsDecoderError(f"{where}: truncado")
        return struct.unpack_from(">Q", buf, pos)[0], pos + 8
    raise XlsDecoderError(f"{where}: kind 0x{kind:02x} não suportado")


def _read_u32(buf: bytes, pos: int, where: str) -> tuple[int, int]:
    if pos + 4 > len(buf):
        raise XlsDecoderError(f"{where}: u32 truncado em {pos}")
    return struct.unpack_from(">I", buf, pos)[0], pos + 4


def _decode_nested_by_name(name: str, buf: bytes, pos: int, path: list[str],
                           trace: list | None) -> tuple[Any, int]:
    schema = NESTED_SCHEMAS.get(name)
    if schema is None:
        raise XlsDecoderError(f"nested {name!r}: tabela não modelada")
    return _decode_message(schema, buf, pos, path, trace)


def _decode_message(schema: Sequence[Field], buf: bytes, pos: int,
                    path: list[str] | None = None,
                    trace: list | None = None) -> tuple[dict[str, Any], int]:
    path = path or []
    out: dict[str, Any] = {}
    for f in schema:
        start = pos
        value, pos = _decode_field(f, buf, pos, path, trace)
        out[f.name] = value
        if trace is not None:
            trace.append({"field": ".".join(path + [f.name]), "offset": start,
                          "length": pos - start})
    return out, pos


def decode_user_logon_response(buf: bytes, trace: list | None = None) -> dict[str, Any]:
    data, pos = _decode_message(SCHEMA_USER_LOGON_RESPONSE, buf, 0, trace=trace)
    if pos != len(buf):
        raise XlsDecoderError(f"{len(buf) - pos} byte(s) sobrando depois do último campo")
    return data


def decode_frame(resp: bytes) -> tuple[dict[str, Any], bytes]:
    """Separa frame (13 B) de corpo e devolve os campos do frame."""
    if len(resp) < FRAME_SIZE:
        raise XlsDecoderError(f"resposta {len(resp)} B < 13 (frame)")
    byte0 = resp[0]
    status, code, length = struct.unpack_from(">III", resp, 1)
    return ({"byte0": byte0, "status": status, "code": code, "length": length},
            resp[FRAME_SIZE:])


# ----------------------------------------------------------------------------------
# introspecção
# ----------------------------------------------------------------------------------
def schema_table(schema_name: str = "UserLogonResponse") -> list[dict[str, Any]]:
    schema = SCHEMAS[schema_name]
    return [
        {"index": i + 1, "id": f"0x{f.id:02x}", "kind": f"0x{f.kind:02x}", "name": f.name,
         "size": f.size, "max": f.max, "nested": f.nested,
         "elemKind": None if f.elem_kind is None else f"0x{f.elem_kind:02x}"}
        for i, f in enumerate(schema)
    ]


def load_config(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _main(argv: list[str]) -> int:
    if "--schema" in argv:
        name = "UserLogonResponse"
        for index, arg in enumerate(argv):
            if arg == "--schema" and index + 1 < len(argv) and not argv[index + 1].startswith("-"):
                name = argv[index + 1]
        print(json.dumps(schema_table(name), indent=2))
        return 0
    print("usage: python xls_encoder.py --schema [UserLogonResponse|UserData|MethodPermission|"
          "Discount|CmsInformation|AvailabilityInformation]")
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
