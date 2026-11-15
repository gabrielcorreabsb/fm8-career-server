#!/usr/bin/env python3
"""self_test.py — valida o encoder do mock v2.1 contra a receita da ENVELOPE-SPEC §7.

100% offline: não abre socket, não toca REA/MCP, não mexe em hosts/CA.

Checagens:
  [1] transcrição das tabelas (§5.1/§5.2/§5.3/§5.4/§5.5) + tamanhos de wire por nested
  [2] corpo BYTE-A-BYTE contra o hex de referência da §7.3 (469 B, 1 permissão)
  [3] offsets de campo exatamente como a tabela de offsets da §7.3
  [4] frame de 13 B (§1.4): byte0/status/code/length BE, controle negativo de 12 B
  [5] roundtrip decode -> encode byte-a-byte (referência e config)
  [6] valores do config.json no decode (inclui region/recentlySeen e array de permissions)
  [7] gramática: string u32 BE + UTF-8, datetime TEXTO, GUID (Data1/2/3 revertidos como
      no Apêndice A), arrays com count u32 BE
  [8] limites (maxlen/máx) e elementos não decompostos (count = 0 obrigatório)
  [9] variantes A/B da §7.4 (presets 1..6) selecionáveis no config
  [10] envelope CIFRADO (mock v3, variante 8 / ENVELOPE-SPEC R6): chave do cliente
       derivada do blob 'RSA2' do dump, receita byte-a-byte (IV||AES-256-CBC||RSA-OAEP),
       W = IV||K^mask||0*16 (mask=0 e mask!=0), tamanho 768 B, backends AES (puro vs
       biblioteca), preset 8/probe do mock e rollover (decifrar request do cliente)
  [11] variante 9 ROTA B (ENVELOPE-SPEC E6/E8.3): OAEP(IV2||K||0*16) na frente + AES no
       meio + SIG PKCS#1v1.5/SHA-256 do prefixo no fim (1008 B); roundtrip OAEP/ct,
       verify com client_public (+ caminho puro deterministico), request real de 896 B
       (sig sobre body[0:640]) e probe do mock (1008 B route=B)

Uso: python self_test.py [--config config.json] [--no-hex]
Exit: 0 = tudo ok · 1 = divergência (diff na saída) · 2 = config/env inválido.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import struct
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from xls_encoder import (  # noqa: E402
    FRAME_SIZE,
    FRAME_SIZE_CONTROL,
    NESTED_SCHEMAS,
    SCHEMA_AVAILABILITY_INFORMATION,
    SCHEMA_CMS_INFORMATION,
    SCHEMA_DISCOUNT,
    SCHEMA_METHOD_PERMISSION,
    SCHEMA_USER_DATA,
    SCHEMA_USER_LOGON_RESPONSE,
    EncodeOptions,
    XlsEncoderError,
    build_frame,
    decode_frame,
    decode_user_logon_response,
    encode_config,
    encode_user_logon_response,
    guid_wire,
    load_config,
    options_for,
    resolve_variant,
)

FAILS: list[str] = []
CHECKS = 0

# ----------------------------------------------------------------------------------
# hex de referência da ENVELOPE-SPEC §7.3 (corpo de 469 B, 1 permissão) — EMBUTIDO
# ----------------------------------------------------------------------------------
REF_BODY_HEX = (
    "0100000001000000010000000001000000000000000000000000000000000000"
    "000000000000000000000009000009fed8690000000a54657374447269766572"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000001000000000000000000000000000000000000000000"
    "0000000000000000000000000000003c0000003c0000003c0000000000000fa0"
    "0000ea600000ea60000000000000000000000000000000000000001831393730"
    "2d30312d30315430303a30303a30302e3030305a00000018313937302d30312d"
    "30315430303a30303a30302e3030305a00000000000000000000000000000000"
    "0000000000000018313937302d30312d30315430303a30303a30302e3030305a"
    "00000018313937302d30312d30315430303a30303a30302e3030305a00000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "18313937302d30312d30315430303a30303a30302e3030305a00000018313937"
    "302d30312d30315430303a30303a30302e3030305a0000000000000018323032"
    "362d31312d31355430313a30323a30332e3435365a00000018313937302d3031"
    "2d30315430303a30303a30302e3030305a00000000"
)

# Profile exato que reproduz o hex acima (derivado dele campo a campo).
REF_PROFILE = {
    "isProfileValid": True,
    "permissions": [{"methodId": 1, "tier": 0, "isEnabled": 1, "access": 0}],
    "xuid": 2533274958092393,
    "gamerTag": "TestDriver",
    "currentDriverLevel": 1,
    "systemTimeUTC": "2026-11-15T01:02:03.456Z",
}

# --- 2ª transcrição independente: §5.1 (UserLogonResponse, 31 campos) --------------
EXPECTED_LOGON = [
    (0x008, 0x11, "isProfileValid"),
    (0x010, 0x16, "permissions"),
    (0x028, 0x04, "featureAreasBanMask"),
    (0x02C, 0x04, "userFlags"),
    (0x030, 0x05, "upsellOfferId"),
    (0x038, 0x15, "upsellText"),
    (0x058, 0x16, "vipOfferIds"),
    (0x070, 0x0C, "userData"),
    (0x118, 0x12, "SecurityId"),
    (0x128, 0x01, "notificationNonce"),
    (0x12C, 0x03, "notificationPollIntervalSeconds"),
    (0x130, 0x04, "defaultFriendsPollIntervalSeconds"),
    (0x134, 0x04, "maxFriendsPollIntervalSeconds"),
    (0x138, 0x16, "notificationCategories"),
    (0x150, 0x03, "defaultTimeoutMs"),
    (0x154, 0x03, "defaultContentTimeoutMs"),
    (0x158, 0x03, "defaultInGameTimeoutMs"),
    (0x160, 0x16, "makeDiscounts"),
    (0x178, 0x16, "carDiscounts"),
    (0x190, 0x0C, "allCarDiscount"),
    (0x1C8, 0x16, "makePartsDiscounts"),
    (0x1E0, 0x16, "carPartsDiscounts"),
    (0x1F8, 0x0C, "allPartsDiscount"),
    (0x230, 0x16, "featuredUserEntries"),
    (0x248, 0x16, "pushNotificationTags"),
    (0x260, 0x0C, "cmsInformation"),
    (0x2F0, 0x0C, "availabilityInformation"),
    (0x320, 0x15, "FlightRingId"),
    (0x340, 0x10, "systemTimeUTC"),
    (0x350, 0x10, "lastZendeskTicketCreateTime"),
    (0x360, 0x16, "banData"),
]

# --- §5.2 userData, 17 campos -----------------------------------------------------
EXPECTED_USER_DATA = [
    (0x08, 0x06, "qwXuid"),
    (0x10, 0x15, "wzGamerTag"),
    (0x30, 0x00, "flags"),
    (0x34, 0x12, "clubId"),
    (0x48, 0x15, "clubTag"),
    (0x68, 0x03, "clubTopTierCount"),
    (0x6C, 0x04, "roleInClub"),
    (0x70, 0x02, "currentBadgeId"),
    (0x72, 0x02, "currentPlayerTitleId"),
    (0x74, 0x04, "currentCarCollectionScore"),
    (0x78, 0x02, "currentCarCollectionTier"),
    (0x7C, 0x04, "currentDriverLevel"),
    (0x80, 0x04, "currentPrestigeRank"),
    (0x84, 0x03, "currentDriverModelId"),
    (0x88, 0x16, "customizationSlotsV2"),
    (0xA0, 0x01, "region"),
    (0xA2, 0x11, "recentlySeen"),
]

# --- tabela de offsets da §7.3 (nome, offset, tamanho no wire) ---------------------
EXPECTED_LAYOUT = [
    ("isProfileValid", 0x0000, 1),
    ("permissions", 0x0001, 17),
    ("featureAreasBanMask", 0x0012, 4),
    ("userFlags", 0x0016, 4),
    ("upsellOfferId", 0x001A, 8),
    ("upsellText", 0x0022, 4),
    ("vipOfferIds", 0x0026, 4),
    ("userData", 0x002A, 80),
    ("SecurityId", 0x007A, 16),
    ("notificationNonce", 0x008A, 2),
    ("notificationPollIntervalSeconds", 0x008C, 4),
    ("defaultFriendsPollIntervalSeconds", 0x0090, 4),
    ("maxFriendsPollIntervalSeconds", 0x0094, 4),
    ("notificationCategories", 0x0098, 4),
    ("defaultTimeoutMs", 0x009C, 4),
    ("defaultContentTimeoutMs", 0x00A0, 4),
    ("defaultInGameTimeoutMs", 0x00A4, 4),
    ("makeDiscounts", 0x00A8, 4),
    ("carDiscounts", 0x00AC, 4),
    ("allCarDiscount", 0x00B0, 68),
    ("makePartsDiscounts", 0x00F4, 4),
    ("carPartsDiscounts", 0x00F8, 4),
    ("allPartsDiscount", 0x00FC, 68),
    ("featuredUserEntries", 0x0140, 4),
    ("pushNotificationTags", 0x0144, 4),
    ("cmsInformation", 0x0148, 20),
    ("availabilityInformation", 0x015C, 57),
    ("FlightRingId", 0x0195, 4),
    ("systemTimeUTC", 0x0199, 28),
    ("lastZendeskTicketCreateTime", 0x01B5, 28),
    ("banData", 0x01D1, 4),
]


def check(condition: bool, label: str, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if condition:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}" + (f"  [{detail}]" if detail else ""))
        FAILS.append(label + (f" ({detail})" if detail else ""))


def hexdump_lines(buf: bytes, width: int = 16) -> list[str]:
    lines = []
    for offset in range(0, len(buf), width):
        chunk = buf[offset:offset + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hexpart}  |{text}|")
    return lines


def with_variant(config: dict, active: str) -> dict:
    clone = json.loads(json.dumps(config))
    clone.setdefault("variants", {})["active"] = active
    return clone


def main() -> int:
    ap = argparse.ArgumentParser(description="mock LSP v2.1 encoder self-test")
    ap.add_argument("--config", default=os.path.join(BASE, "config.json"))
    ap.add_argument("--no-hex", action="store_true")
    args = ap.parse_args()

    config_path = os.path.abspath(args.config)
    print(f"config: {config_path}")
    try:
        config = load_config(config_path)
    except (OSError, ValueError) as exc:
        print(f"ERRO: config ilegivel: {exc}", file=sys.stderr)
        return 2

    variant = resolve_variant(config)
    options = options_for(config)
    print(f"variante ativa: {variant.describe()}")
    print()

    # ---------------- [1] transcrição ----------------
    print("[1] transcricao das tabelas (ENVELOPE-SPEC 5.1-5.5)")
    for name, schema, expected in (
        ("UserLogonResponse", SCHEMA_USER_LOGON_RESPONSE, EXPECTED_LOGON),
        ("UserData", SCHEMA_USER_DATA, EXPECTED_USER_DATA),
    ):
        got = [(f.id, f.kind, f.name) for f in schema]
        check(len(got) == len(expected), f"{name}: {len(expected)} campos",
              f"encoder tem {len(got)}")
        check(got == expected, f"{name}: (id, kind, name) na ordem da spec")
        if got != expected:
            for line in difflib.unified_diff(
                    [f"0x{i:03x} 0x{k:02x} {n}" for i, k, n in expected],
                    [f"0x{i:03x} 0x{k:02x} {n}" for i, k, n in got],
                    "spec", "encoder", lineterm="", n=1):
                print("       " + line)
    check([f.name for f in SCHEMA_METHOD_PERMISSION] ==
          ["methodId", "tier", "isEnabled", "access"], "MethodPermission: 4 campos")
    check([f.name for f in SCHEMA_DISCOUNT] ==
          ["TokenDiscountAmount", "CreditDiscountAmount", "StartDate", "EndDate", "OfferId"],
          "Discount: 5 campos")
    check([f.name for f in SCHEMA_CMS_INFORMATION] ==
          ["Header", "Override", "SlotId", "SnapId", "Version"], "cmsInformation: 5 campos")
    check([f.name for f in SCHEMA_AVAILABILITY_INFORMATION] ==
          ["IsCurrentlyAvailable", "NearestWindowOpenTime", "NearestWindowCloseTime"],
          "availabilityInformation: 3 campos")
    check(len(NESTED_SCHEMAS) == 5, "5 nested decompostos (MethodPermission, UserData, "
                                    "Discount, CmsInformation, AvailabilityInformation)")

    # tamanhos de wire por campo, lidos do trace do corpo de referência
    ref_trace: list[dict] = []
    encode_user_logon_response(REF_PROFILE, trace=ref_trace)
    sizes = {e["field"]: e["length"] for e in ref_trace
             if "." not in e["field"] and "[" not in e["field"]}
    for name, expected in (("isProfileValid", 1), ("permissions", 17),
                           ("vipOfferIds", 4), ("userData", 80), ("SecurityId", 16),
                           ("notificationNonce", 2), ("allCarDiscount", 68),
                           ("cmsInformation", 20), ("availabilityInformation", 57),
                           ("systemTimeUTC", 28), ("banData", 4)):
        check(sizes.get(name) == expected, f"{name} = {expected} B no wire",
              str(sizes.get(name)))
    check(len(encode_user_logon_response({"gamerTag": "TestDriver"})) == 456,
          "corpo com permissions count=0 (gamerTag TestDriver) = 456 B")
    print()

    # ---------------- [2] byte-a-byte contra a referência ----------------
    print("[2] corpo byte-a-byte vs ENVELOPE-SPEC 7.3")
    ref = bytes.fromhex(REF_BODY_HEX) if "@@" not in REF_BODY_HEX else b""
    ref_body = encode_user_logon_response(REF_PROFILE)
    check(len(ref) == 469, "hex de referencia tem 469 B", f"{len(ref)}B")
    check(ref_body == ref, "encode(REF_PROFILE) == hex de referencia")
    if ref_body != ref:
        first = next((i for i in range(min(len(ref), len(ref_body)))
                      if ref[i] != ref_body[i]), min(len(ref), len(ref_body)))
        print(f"       primeiro byte divergente: 0x{first:x}")
        print(f"       spec : {ref[max(0, first - 8):first + 16].hex()}")
        print(f"       nos  : {ref_body[max(0, first - 8):first + 16].hex()}")
        for line in difflib.unified_diff(hexdump_lines(ref), hexdump_lines(ref_body),
                                         "ENVELOPE-SPEC 7.3", "encoder", lineterm="", n=2):
            print("       " + line)
    print()

    # ---------------- [3] offsets da §7.3 ----------------
    print("[3] layout: offsets e tamanhos da tabela 7.3")
    trace: list[dict] = []
    body = encode_user_logon_response(REF_PROFILE, trace=trace)
    top = [e for e in trace if "." not in e["field"] and "[" not in e["field"]]
    check(len(top) == 31, "trace cobre os 31 campos", f"{len(top)}")
    got_layout = [(e["field"], e["offset"], e["length"]) for e in top]
    check(got_layout == EXPECTED_LAYOUT, "offset+length de cada campo batem com a 7.3")
    if got_layout != EXPECTED_LAYOUT:
        for line in difflib.unified_diff(
                [f"{n:<32} 0x{o:04x} {l:>3}" for n, o, l in EXPECTED_LAYOUT],
                [f"{n:<32} 0x{o:04x} {l:>3}" for n, o, l in got_layout],
                "spec", "encoder", lineterm="", n=1):
            print("       " + line)
    check(top[-1]["offset"] + top[-1]["length"] == 469, "ultimo campo fecha em 469 B")
    print()
    print("  #  campo                          off  len")
    for index, entry in enumerate(top, 1):
        print(f"  {index:2d} {entry['field']:<30} 0x{entry['offset']:04x} {entry['length']:4d}")
    print()

    # ---------------- [4] frame ----------------
    print("[4] frame de 13 B (spec 1.4)")
    resp = build_frame(body, EncodeOptions())
    check(len(resp) == FRAME_SIZE + len(body), "total == 13 + corpo",
          f"{len(resp)}B")
    frame, decoded_body = decode_frame(resp)
    check(frame["byte0"] == 0x00, "byte0 = 0x00 (default)")
    check(frame["status"] == 0, "status = 0 (sucesso)")
    check(frame["code"] == 0, "code = 0")
    check(frame["length"] == len(body), "length = len(corpo)", str(frame["length"]))
    check(resp[1:5] == struct.pack(">I", 0), "status e' u32 BIG-ENDIAN")
    check(resp[9:13] == struct.pack(">I", len(body)), "length e' u32 BIG-ENDIAN")
    check(decoded_body == body, "corpo apos o frame e' o corpo inteiro")
    control = build_frame(body, EncodeOptions(frame_size=FRAME_SIZE_CONTROL))
    check(len(control) == FRAME_SIZE_CONTROL + len(body) and
          len(control) < len(resp), "controle negativo: frame de 12 B (variante 5)")
    check(control[:4] == b"\x00\x00\x00\x00",
          "controle: com 12 B o 1o byte do corpo e' lido como status (spec 1.4)")
    error_frame = decode_frame(build_frame(body, EncodeOptions(status=2, code=0x51)))[0]
    check(error_frame["status"] == 2 and error_frame["code"] == 0x51,
          "injecao de erro: status 2 + code (0x80510000|code)")
    for bad in ({"status": 1}, {"frame_size": 11}, {"frame_byte0": 0x100}):
        try:
            EncodeOptions(**bad).validated()
            raised = False
            message = ""
        except XlsEncoderError as exc:
            raised = True
            message = str(exc)
        check(raised, f"opcao invalida rejeitada: {bad}", message or "aceitou")
    print()

    # ---------------- [5] roundtrip ----------------
    print("[5] roundtrip decode -> encode")
    decoded = decode_user_logon_response(body)
    check(list(decoded.keys()) == [f.name for f in SCHEMA_USER_LOGON_RESPONSE],
          "decode devolve os 31 campos na ordem do schema")
    reencoded = encode_user_logon_response(decoded)
    if reencoded != body:
        check(False, "roundtrip byte-a-byte (referencia)",
              f"{len(reencoded)}B != {len(body)}B")
        first = next((i for i in range(min(len(body), len(reencoded)))
                      if body[i] != reencoded[i]), min(len(body), len(reencoded)))
        print(f"       primeiro byte divergente: 0x{first:x}")
        for line in difflib.unified_diff(hexdump_lines(body), hexdump_lines(reencoded),
                                         "encode", "encode(decode(...))", lineterm="", n=2):
            print("       " + line)
    else:
        check(True, "roundtrip byte-a-byte (referencia)")
    cfg_body = encode_user_logon_response(config, options, variant=variant)
    cfg_decoded = decode_user_logon_response(cfg_body)
    cfg_reencoded = encode_user_logon_response(cfg_decoded, options, variant=variant)
    check(cfg_reencoded == cfg_body, "roundtrip byte-a-byte (config.json)",
          f"{len(cfg_reencoded)}B vs {len(cfg_body)}B")
    print()

    # ---------------- [6] valores do config ----------------
    print("[6] valores do config.json no decode")
    ud = decoded["userData"]
    checks = [
        ("userData.qwXuid", ud["qwXuid"] == 2533274958092393, str(ud["qwXuid"])),
        ("userData.wzGamerTag", ud["wzGamerTag"] == "TestDriver", ud["wzGamerTag"]),
        ("userData.currentDriverLevel", ud["currentDriverLevel"] == 1),
        ("userData.region (novo)", "region" in ud),
        ("userData.recentlySeen (novo)", ud["recentlySeen"] is False),
        ("permissions e' LISTA", isinstance(decoded["permissions"], list)
         and len(decoded["permissions"]) == 1, str(decoded["permissions"])),
        ("permissions[0]", decoded["permissions"][0] ==
         {"methodId": 1, "tier": 0, "isEnabled": True, "access": 0},
         str(decoded["permissions"][0])),
        ("isProfileValid", decoded["isProfileValid"] is True),
        ("notificationPollIntervalSeconds", decoded["notificationPollIntervalSeconds"] == 60),
        ("timeouts 4000/60000/60000",
         (decoded["defaultTimeoutMs"], decoded["defaultContentTimeoutMs"],
          decoded["defaultInGameTimeoutMs"]) == (4000, 60000, 60000)),
        ("systemTimeUTC == config", decoded["systemTimeUTC"] == REF_PROFILE["systemTimeUTC"]),
        ("lastZendeskTicketCreateTime", decoded["lastZendeskTicketCreateTime"] ==
         "1970-01-01T00:00:00.000Z"),
        ("allCarDiscount.EndDate", decoded["allCarDiscount"]["EndDate"] ==
         "1970-01-01T00:00:00.000Z"),
        ("availabilityInformation.IsCurrentlyAvailable",
         decoded["availabilityInformation"]["IsCurrentlyAvailable"] is False),
        ("cmsInformation.Version", decoded["cmsInformation"]["Version"] == 0),
        ("vipOfferIds vazio", decoded["vipOfferIds"] == []),
        ("banData vazio", decoded["banData"] == []),
    ]
    for item in checks:
        check(item[1], item[0], item[2] if len(item) > 2 else "")
    print()

    # ---------------- [7] gramática ----------------
    print("[7] gramatica do wire (spec 4)")
    raw_tag = b"TestDriver"
    needle = struct.pack(">I", len(raw_tag)) + raw_tag
    check(body.find(needle) >= 0, "string: u32 BE len + UTF-8", needle.hex())
    check(body.find(struct.pack("<I", len(raw_tag)) + raw_tag) < 0,
          "string: prefixo LE ausente (confirma BE)")
    dt_needle = struct.pack(">I", 24) + b"2026-11-15T01:02:03.456Z"
    check(body.find(dt_needle) >= 0, "datetime: u32 BE len + texto .mmmZ",
          dt_needle.hex())
    check(body[0x0001:0x0005] == struct.pack(">I", 1),
          "array: count u32 BE em permissions")
    check(body[0x0005:0x0009] == struct.pack(">I", 1),
          "MethodPermission.methodId em u32 BE")
    check(body[0x000D] == 0x01, "MethodPermission.isEnabled = 1 byte")
    check(body[0x0000] == 0x01, "isProfileValid = 1 byte no inicio do corpo")
    check(guid_wire("12345678abcd00112233445566778899") ==
          bytes.fromhex("78563412cdab11002233445566778899"),
          "GUID: Data1/2/3 revertidos, Data4 cru (fiel ao Apendice A)",
          guid_wire("12345678abcd00112233445566778899").hex())
    check(guid_wire("00" * 16) == b"\x00" * 16, "GUID zerado permanece zerado")
    check(len(body) == 469, "corpo de referencia = 469 B", str(len(body)))
    print()

    # ---------------- [8] limites ----------------
    print("[8] limites e elementos nao decompostos (spec 9.4)")
    cases = [
        ("gamerTag 16 chars > maxlen 15", {"gamerTag": "x" * 16}, True),
        ("gamerTag 15 chars ok", {"gamerTag": "x" * 15}, False),
        ("clubTag 5 chars > maxlen 4", {"clubTag": "AAAAA"}, True),
        ("upsellText 301 chars > maxlen 300", {"upsellText": "y" * 301}, True),
        ("permissions 513 > max 512", {"permissions": [{}] * 513}, True),
        ("banData 1 elemento (nao decomposto)", {"banData": [{}]}, True),
        ("pushNotificationTags 1 elemento", {"pushNotificationTags": [{}]}, True),
        ("banData count=0 ok", {"banData": []}, False),
        ("datetime invalido", {"systemTimeUTC": "2026-11-15 00:00:00"}, True),
        ("datetime epoch aceito", {"systemTimeUTC": 1763168400}, False),
    ]
    for label, patch, expect_error in cases:
        variant_cfg = json.loads(json.dumps(config))
        variant_cfg["variants"]["overrides"] = {"permissions": "config"}
        variant_cfg.update(patch)
        try:
            encode_user_logon_response(variant_cfg, variant=resolve_variant(variant_cfg))
            raised = False
            message = ""
        except XlsEncoderError as exc:
            raised = True
            message = str(exc)
        check(raised == expect_error, label, message or "nenhum erro")
        if raised:
            print(f"       -> {message}")
    print()

    # ---------------- [9] variantes ----------------
    print("[9] variantes A/B selecionaveis no config (spec 7.4)")
    empty_body = encode_user_logon_response(config, options,
                                           variant=resolve_variant(with_variant(config, "1")))
    one_body = encode_user_logon_response(config, options,
                                         variant=resolve_variant(with_variant(config, "2")))
    check(len(empty_body) == 456, "v1/v3/v4/v5: corpo 456 B (permissions count=0)",
          f"{len(empty_body)}B")
    check(len(one_body) == 469, "v2: corpo 469 B (1 MethodPermission)", f"{len(one_body)}B")
    expectations = {
        "1": dict(frame=13, b0=0, body=456, xenc=None, prefix=0),
        "2": dict(frame=13, b0=0, body=469, xenc=None, prefix=0),
        "3": dict(frame=13, b0=0, body=456, xenc="false", prefix=0),
        "4": dict(frame=13, b0=1, body=456, xenc=None, prefix=0),
        "5": dict(frame=12, b0=None, body=456, xenc=None, prefix=0),
        "6": dict(frame=13, b0=0, body=458, xenc=None, prefix=2),
    }
    for active, expected in expectations.items():
        cfg = with_variant(config, active)
        v = resolve_variant(cfg)
        opts = options_for(cfg)
        payload = encode_config(cfg)
        body_len = len(payload) - expected["frame"]
        ok = (opts.frame_size == expected["frame"]
              and (expected["b0"] is None or opts.frame_byte0 == expected["b0"])
              and body_len == expected["body"]
              and v.x_encryption == expected["xenc"]
              and (2 if opts.body_prefix else 0) == expected["prefix"])
        check(ok, f"variante {active}: {v.describe()}", f"payload={len(payload)}B")
    check("variant=3" in resolve_variant(with_variant(config, "3")).describe() and
          "X-Encryption:false" in resolve_variant(with_variant(config, "3")).describe(),
          "label de log descreve a variante (X-Encryption)")
    prefix_probe = encode_user_logon_response(config, EncodeOptions(body_prefix=True),
                                              variant=resolve_variant(config))
    check(prefix_probe[:2] == b"\x00\x00", "prefixo 2 B {isVip,isUltimateVip} = 00 00")
    active_body = encode_user_logon_response(config, options,
                                            variant=resolve_variant(config))
    check(len(prefix_probe) == len(active_body) + 2,
          "prefixo soma exatamente 2 B (variante ativa)",
          f"{len(prefix_probe)} vs {len(active_body)}+2")
    print()

    # ---------------- [10] envelope cifrado (mock v3) ----------------
    print("[10] envelope cifrado (variante 8) - ENVELOPE-SPEC R6")
    import math

    import xls_crypto as xc

    print(f"       aes backend: {xc.AES_BACKEND}")

    # (a) chave do cliente derivada do blob 'RSA2' do dump
    blob_main = xc.read_rsa2_blob(os.path.join(BASE, "dump_text.bin"),
                                  xc.DEFAULT_BLOB_OFFSET)
    blob_dup = xc.read_rsa2_blob(os.path.join(BASE, "dump_text.bin"),
                                 xc.DEFAULT_BLOB_OFFSET_DUP)
    check(len(blob_main) == xc.BLOB_SIZE and blob_main[:4] == b"RSA2",
          "blob 'RSA2' em 0x0491f9a0 (VA-0x140001000): magic + 542 B",
          f"{len(blob_main)}B {blob_main[:4]!r}")
    check(blob_main == blob_dup, "duplicata em 0x0491fbd0 identica")
    parsed = xc.parse_bcrypt_rsa_private_blob(blob_main)
    check(parsed["n_hex"] == xc.CLIENT_N_HEX, "n do blob == n da ENVELOPE-SPEC R6",
          parsed["n_hex"][:16])
    check(parsed["e"] == 0x10001, "e = 0x10001", hex(parsed["e"]))
    check(parsed["p"] * parsed["q"] == parsed["n"], "p*q == n")
    check(parsed["bitlen"] == 2048, "bitlen 2048")
    check((parsed["cb_exp"], parsed["cb_mod"], parsed["cb_p1"], parsed["cb_p2"]) ==
          (3, 257, 129, 129), "header CNG: e 3 B / n 257 B / p 129 B / q 129 B",
          str((parsed["cb_exp"], parsed["cb_mod"], parsed["cb_p1"], parsed["cb_p2"])))
    check(parsed["d"] * parsed["e"] %
          ((parsed["p"] - 1) * (parsed["q"] - 1) //
           math.gcd(parsed["p"] - 1, parsed["q"] - 1)) == 1,
          "d derivado de p,q,e (inverso de e mod lcm(p-1,q-1))")
    key_dir = os.path.join(BASE, "keys")
    check(os.path.exists(os.path.join(key_dir, "client_private.pem")) and
          os.path.exists(os.path.join(key_dir, "client_public.pem")),
          "client_private.pem + client_public.pem salvos em keys/")
    material = xc.load_client_key_material(os.path.join(BASE, "dump_text.bin"), key_dir)
    check(material["n"] == parsed["n"] and material["e"] == parsed["e"],
          "load_client_key_material devolve n/e do cliente")

    # (b) receita byte-a-byte para o corpo de 469 B
    plain_body = encode_user_logon_response(REF_PROFILE)          # 469 B
    payload = build_frame(plain_body, EncodeOptions())            # 13 + 469 = 482 B
    check(len(payload) == 13 + 469, "plaintext P = frame13 || corpo = 482 B",
          f"{len(payload)}B")
    key = bytes(range(32))
    iv = bytes(range(16))
    mask0 = b"\x00" * 32
    crypto = xc.MockCrypto(material, mask=mask0, key=key, iv=iv)
    wire = crypto.wrap(payload, rotate_iv=False)
    check(len(wire) == 768, "body cifrado = 768 B (16 + 496 + 256)", f"{len(wire)}B")
    ct_len = len(wire) - xc.IV_SIZE - xc.RSA_BLOCK
    check(ct_len == 496 and ct_len % 16 == 0,
          "ct = 496 B = ceil(482/16)*16 (PKCS#7: 14 B de pad)")
    check(len(wire) == 16 + int(math.ceil(482 / 16)) * 16 + 256,
          "formula 16 + ceil(482/16)*16 + 256 = 768")
    enc_iv, enc_ct, enc_w = wire[:16], wire[16:len(wire) - 256], wire[len(wire) - 256:]
    check(enc_iv == iv and enc_ct == wire[16:16 + ct_len] and len(enc_w) == 256,
          "layout IV(16) || ct(496) || RSAct(256)")
    if xc._HAS_CRYPTOGRAPHY:
        unwrapped = xc.oaep_decrypt_with_private(material, enc_w)
        check(len(unwrapped) == 64, "OAEP(W) decifra em 64 B exatos", f"{len(unwrapped)}B")
        check(unwrapped[:16] == iv, "W: IV(16) verbatim")
        check(unwrapped[16:48] == key, "W: chave AES (32 B) == K^mask (mask=0)")
        check(unwrapped[48:] == b"\x00" * 16, "W: 16 B de sobra zerados")
        check(len(xc.rsa_oaep_sha1_encrypt(material["n"], material["e"], unwrapped)) == 256,
              "OAEP re-encrypt volta a 256 B")
    else:
        print("       skip: `cryptography` ausente - unwrap de W nao verificado")
    decrypted = xc.aes256_cbc_decrypt(key, enc_iv, enc_ct)
    check(decrypted == payload, "AES-256-CBC(K,IV,ct) == frame13 || corpo")
    dec_frame, dec_body = decode_frame(decrypted)
    check(len(decrypted[:13]) == 13 and dec_frame["length"] == 469,
          "frame 13 B DENTRO do ciphertext: status=0 length=469", str(dec_frame))
    check(dec_body == bytes.fromhex(REF_BODY_HEX) and dec_body == plain_body,
          "corpo decifrado byte-a-byte == ENVELOPE-SPEC 7.3 (469 B, hex de referencia)")
    raw_plain = xc.aes256_cbc_decrypt(key, enc_iv, enc_ct, unpad=False)
    check(raw_plain[-1] == 0x0E and raw_plain[-14:] == b"\x0e" * 14,
          "PKCS#7: 14 B de padding 0x0e (482 -> 496)")

    # (c) mask != 0 (desconhecido #1)
    mask = bytes([0x11] * 32)
    masked = xc.MockCrypto(material, mask=mask, key=key, iv=iv)
    wire_masked = masked.wrap(payload, rotate_iv=False)
    if xc._HAS_CRYPTOGRAPHY:
        pt_masked = xc.oaep_decrypt_with_private(
            material, wire_masked[len(wire_masked) - 256:])
        check(pt_masked[16:48] == bytes(a ^ b for a, b in zip(key, mask)),
              "mask != 0: W leva K^mask (cliente faz XOR de volta)")
        check(pt_masked[16:48] != key, "mask != 0: material != K (prova a XOR)")
        check(xc.aes256_cbc_decrypt(key, pt_masked[:16],
                                    wire_masked[16:len(wire_masked) - 256]) == payload,
              "ct continua cifrado com K efetiva (mask so' no key material)")
    bad_mask = xc.MockCrypto(material, mask=b"\x00" * 32, key=key, iv=iv)
    if xc._HAS_CRYPTOGRAPHY:
        pt_bad = xc.oaep_decrypt_with_private(
            material, bad_mask.wrap(payload, rotate_iv=False)[-256:])
        wrong_key = bytes(a ^ b for a, b in zip(pt_bad[16:48], mask))
        check(wrong_key != key, "mask errada => cliente deriva chave diferente de K")

    # (d) outros tamanhos (o parser exige body >= 272 B)
    big_body = b"\x00" * 888
    big_wire = xc.MockCrypto(material, mask=mask0, key=key, iv=iv).wrap(
        build_frame(big_body), rotate_iv=False)
    expected_big = 16 + int(math.ceil(901 / 16)) * 16 + 256
    check(len(big_wire) == expected_big == 1184,
          "corpo de 888 B -> 1184 B cifrado (16 + 912 + 256)", f"{len(big_wire)}B")
    tiny = xc.MockCrypto(material, mask=mask0, key=key, iv=iv).wrap(
        build_frame(b""), rotate_iv=False)
    check(len(tiny) == 288 >= xc.MIN_DECRYPT_BODY,
          "resposta vazia -> 288 B (>= 272 B do parser)", f"{len(tiny)}B")

    # (e) backends AES: implementacao pura == cryptography/pycryptodome
    ref_backend = xc.AES_BACKEND
    if ref_backend != "pure":
        vectors = [(b"", 1), (b"a" * 15, 16), (b"b" * 17, 32), (os.urandom(149), 160)]
        for data, blocks in vectors[:3]:
            plain = data + b"x" * 5
            ref_ct = xc.aes256_cbc_encrypt(key, iv, plain)
            xc.set_aes_backend("pure")
            pure_ct = xc.aes256_cbc_encrypt(key, iv, plain)
            pure_back = xc.aes256_cbc_decrypt(key, iv, ref_ct)
            xc.set_aes_backend(ref_backend)
            check(pure_ct == ref_ct and pure_back == plain,
                  f"AES puro == {ref_backend} ({blocks} bloco(s))")
        check(len(xc.aes256_cbc_encrypt(key, iv, b"c" * 17)) == 32,
              "AES-256-CBC: 17 B -> 32 B (PKCS#7)")
    else:
        print("       skip: sem biblioteca de AES para comparar com a implementacao pura")

    # (f) variante 8 no encoder + preset/defaults
    cfg8 = with_variant(config, "8")
    v8 = resolve_variant(cfg8)
    check(v8.encrypted and v8.permissions == "one" and v8.frame_size == FRAME_SIZE,
          "preset 8: cifrada + corpo da variante 2 (1 permissao)", v8.describe())
    check("enc=1" in v8.describe(), "label de log anuncia enc=1")
    body8 = encode_user_logon_response(cfg8, options_for(cfg8), variant=v8)
    check(len(body8) == 469, "variante 8: corpo = 469 B (== variante 2)", f"{len(body8)}B")
    import mock_server as ms
    ms._config_path = config_path
    total, label, body_len, encrypted = ms._probe(cfg8)
    check(encrypted and total == body_len == 768,
          "_probe(variante 8): wire de 768 B e cifrado", f"{total}B {label}")
    total_p, label_p, body_len_p, encrypted_p = ms._probe(with_variant(config, "2"))
    check(not encrypted_p and total_p == 482 and body_len_p == 469,
          "_probe(variante 2): plaintext 13 + 469 (comparacao)", f"{total_p}B")
    check(ms._crypto_session(cfg8)[0] is not None, "mock_server._crypto_session ativa")

    # (g) rollover: request do cliente (IV_sessao || rand16 || ct || RSA256)
    req_plain = build_frame(b"") + b"\xAA" * 64
    req_rand = os.urandom(16)
    req_ct = xc.aes256_cbc_encrypt(key, req_rand, req_plain)
    req_body = iv + req_rand + req_ct + b"\x00" * 256
    unwrapped_req, how = xc.MockCrypto(material, mask=mask0, key=key, iv=iv).unwrap_request(
        req_body)
    check(unwrapped_req == req_plain, "request do cliente decifrado (rollover da chave)",
          f"{len(req_body)}B via {how}")
    check(how.startswith("head=32"), "shape do request = [IV 16][rand 16][ct][RSA 256]", how)
    try:
        xc.MockCrypto(material, mask=mask0, key=b"\x00" * 32, iv=iv).unwrap_request(req_body)
        failed = False
        message = "decifrou?!"
    except xc.CryptoError as exc:
        failed = True
        message = str(exc)
    check(failed, "request com chave errada NAO decifra (PKCS#7 rejeita)", message)

    # (h) config: mask hex e overrides
    cfg_crypto = xc.CryptoConfig.from_config(config, BASE)
    check(cfg_crypto.mask == b"\x00" * 32, "config.json: crypto.mask default = zeros",
          cfg_crypto.mask.hex())
    check(cfg_crypto.skip_pre_step is True and cfg_crypto.encrypt_echo is True,
          "config.json: skipPreStep=true (desconhecido #2) e encryptEcho=true")
    bad_cfg = {"crypto": {"mask": "00" * 16}}
    try:
        xc.CryptoConfig.from_config(bad_cfg, BASE)
        raised = False
        message = ""
    except xc.CryptoError as exc:
        raised = True
        message = str(exc)
    check(raised, "mask de 16 B rejeitada (precisa de 32 B)", message)
    check(xc.CryptoConfig.from_config({"crypto": {"mask": "AA" * 32}}, BASE).mask ==
          b"\xaa" * 32, "mask hex 'AA'*32 aceita")
    print()

    # ---------------- [11] variante 9: rota B (OAEP||ct||SIG) ----------------
    print("[11] variante 9 - rota B (ENVELOPE-SPEC E6/E8.3)")
    cfg9 = with_variant(config, "9")
    v9 = resolve_variant(cfg9)
    check(v9.encrypted and v9.route == "B" and v9.permissions == "one",
          "preset 9: cifrada, route=B, corpo da variante 2", v9.describe())
    check("route=B" in v9.describe() and "enc=1" in v9.describe(),
          "label da variante 9 anuncia enc=1 route=B", v9.describe())
    body9 = encode_user_logon_response(cfg9, options_for(cfg9), variant=v9)
    check(len(body9) == 469, "variante 9: corpo = 469 B (== 7.3/variante 2)", f"{len(body9)}B")
    ref9 = encode_user_logon_response(REF_PROFILE)          # 469 B, hex da 7.3 (fixo)
    payload9 = build_frame(ref9, EncodeOptions())           # 13 + 469 = 482
    iv2 = bytes(range(16))
    crypto9 = xc.MockCrypto(material, mask=mask0, key=key, iv=iv2)
    wire9 = crypto9.wrap_route_b(payload9, rotate_iv=False)
    oaep9, ct9, sig9 = wire9[:256], wire9[256:-256], wire9[-256:]
    check(len(wire9) == 1008, "body rota B = 1008 B (256 + 496 + 256)", f"{len(wire9)}B")
    check((len(oaep9), len(ct9), len(sig9)) == (256, 496, 256),
          "layout OAEP(256) || ct(496) || SIG(256) (OAEP na FRENTE)",
          f"{len(oaep9)}/{len(ct9)}/{len(sig9)}")
    check(len(wire9) == 256 + int(math.ceil(482 / 16)) * 16 + 256,
          "formula 256 + ceil(482/16)*16 + 256 = 1008")

    # (a) OAEP do FRONT decifra com a privada do cliente -> IV2 || K || zeros
    pt9 = xc.oaep_decrypt_with_private(material, oaep9)
    check(len(pt9) == 64, "OAEP(body[0:256]) decifra em 64 B", f"{len(pt9)}B")
    check(pt9[:16] == iv2, "OAEP pt: IV2 (16 B) verbatim")
    check(pt9[16:48] == key, "OAEP pt: K (32 B) == K^mask (mask=0)")
    check(pt9[48:] == b"\x00" * 16, "OAEP pt: 16 B de sobra zerados")
    check(len(xc.rsa_oaep_sha1_encrypt(material["n"], material["e"], pt9)) == 256,
          "OAEP re-encrypt volta a 256 B")

    # (b) ct do MEIO decifra com K/IV2 -> frame13 || corpo 7.3
    plain9 = xc.aes256_cbc_decrypt(pt9[16:48], pt9[:16], ct9)
    check(plain9 == payload9, "AES-256-CBC(K, IV2, ct) == frame13 || corpo")
    frame9, dec9 = decode_frame(plain9)
    check(frame9["status"] == 0 and frame9["length"] == 469,
          "frame 13 B DENTRO do ct: status=0 length=469", str(frame9))
    check(dec9 == bytes.fromhex(REF_BODY_HEX) and dec9 == ref9,
          "corpo decifrado byte-a-byte == ENVELOPE-SPEC 7.3 (469 B)")
    raw9 = xc.aes256_cbc_decrypt(pt9[16:48], pt9[:16], ct9, unpad=False)
    check(raw9[-1] == 0x0E and raw9[-14:] == b"\x0e" * 14,
          "PKCS#7: 14 B de padding 0x0e (482 -> 496)")

    # (c) assinatura do TAIL cobre o prefixo inteiro (OAEP + ct), com a publica
    check(xc.rsa_verify_pkcs1v15_sha256(material, sig9, wire9[:-256]),
          "SIG verifica sobre body[0:752] (prefixo inteiro) com client_public")
    em9 = xc.rsa_recover_pkcs1v15_sha256(material, sig9)
    check(em9[:2] == b"\x00\x01" and em9.find(b"\x00", 2) == 204,
          "EM = 00 01 FF*202 00 || DigestInfo (PS len=202)", em9[:4].hex())
    check(em9[205:] == xc.DIGESTINFO_SHA256_PREFIX + hashlib.sha256(wire9[:-256]).digest(),
          "DigestInfo(3031300d...0420) || SHA256(body[0:752])")
    if xc._HAS_CRYPTOGRAPHY:
        from cryptography.hazmat.primitives import hashes as _h
        from cryptography.hazmat.primitives import serialization as _s
        from cryptography.hazmat.primitives.asymmetric import padding as _p
        with open(os.path.join(BASE, "keys", "client_public.pem"), "rb") as handle_pub:
            pub = _s.load_pem_public_key(handle_pub.read())
        try:
            pub.verify(sig9, wire9[:-256], _p.PKCS1v15(), _h.SHA256())
            sig_by_crypto = True
            sig_message = ""
        except Exception as exc:  # pragma: no cover
            sig_by_crypto = False
            sig_message = str(exc)
        check(sig_by_crypto, "cryptography: client_public.verify(PKCS1v15/SHA256) OK",
              sig_message)
        # assinatura PKCS#1v1.5 e' deterministica: caminho puro == cryptography
        forced_pure = False
        try:
            xc._HAS_CRYPTOGRAPHY = False
            sig_pure = xc.rsa_sign_pkcs1v15_sha256(material, wire9[:-256])
            forced_pure = True
        finally:
            xc._HAS_CRYPTOGRAPHY = True
        check(forced_pure and sig_pure == sig9,
              "assinatura pura-Python (pow(EM,d,n)) == cryptography (deterministica)")
        check(xc.rsa_verify_pkcs1v15_sha256(material, sig_pure, wire9[:-256]),
              "verify estrutural aceita a assinatura do caminho puro")
    else:
        print("       skip: `cryptography` ausente - cross-check de assinatura")
    tampered = bytearray(wire9)
    tampered[300] ^= 0x01                                     # dentro do ct
    check(not xc.rsa_verify_pkcs1v15_sha256(material, bytes(tampered[-256:]),
                                            bytes(tampered[:-256])),
          "assinatura NAO verifica se 1 byte do ct muda")
    bad_sig = bytearray(sig9)
    bad_sig[10] ^= 0xFF
    check(not xc.rsa_verify_pkcs1v15_sha256(material, bytes(bad_sig), wire9[:-256]),
          "assinatura NAO verifica se 1 byte da SIG muda")

    # (d) request REAL capturado: sig do tail (E3) verificavel com a publica
    real_req = os.path.join(BASE, "unwrap", "logon_1.bin")
    if os.path.exists(real_req):
        with open(real_req, "rb") as handle_req:
            req_body_real = handle_req.read()
        check(len(req_body_real) == 896, "request real capturado tem 896 B",
              f"{len(req_body_real)}B")
        check(xc.rsa_verify_pkcs1v15_sha256(material, req_body_real[-256:],
                                            req_body_real[:-256]),
              "request real: SIG sobre body[0:640] verifica (E3/E4)")
        mc_real = xc.MockCrypto(material, mask=mask0, key=key, iv=iv2)
        check(mc_real.verify_message_signature(req_body_real) and
              mc_real.requests_sig_ok == 1,
              "MockCrypto.verify_message_signature(request real) -> True",
              str(mc_real.requests_sig_ok))
    else:
        print("       skip: unwrap/logon_1.bin ausente (sem captura real nesta maquina)")

    # (e) OAEP e' randomizado por natureza: ct e SIG sao deterministicos para o mesmo
    #     prefixo; o OAEP muda (seed aleatorio) e a SIG acompanha.
    first = xc.MockCrypto(material, mask=mask0, key=key, iv=iv2).wrap_route_b(
        payload9, rotate_iv=False)
    second = xc.MockCrypto(material, mask=mask0, key=key, iv=iv2).wrap_route_b(
        payload9, rotate_iv=False)
    check(len(first) == len(second) == 1008 and len(first) == len(wire9),
          "wrap_route_b: 1008 B em toda chamada (K/IV2 fixos)")
    check(first[256:-256] == second[256:-256],
          "ct e' deterministico com K/IV2 fixos (AES-CBC)")
    check(first[:256] != second[:256] and first[-256:] != second[-256:],
          "OAEP/SIG variam por mensagem (seed RSA-OAEP aleatorio)")
    check(xc.rsa_verify_pkcs1v15_sha256(material, first[-256:], first[:-256]) and
          xc.rsa_verify_pkcs1v15_sha256(material, second[-256:], second[:-256]),
          "cada assinatura confere com o seu proprio prefixo")
    check(first[256:-256] == wire9[256:-256],
          "wrap_route_b reproduz o ct do body de referencia")
    check(crypto9.responses == 1 and crypto9.signatures == 1,
          "contadores: responses=1 signatures=1",
          f"{crypto9.responses}/{crypto9.signatures}")
    echo9 = xc.MockCrypto(material, mask=mask0, key=key, iv=iv2).wrap_route_b(
        build_frame(b""), rotate_iv=False)
    check(len(echo9) == 528 and 528 >= 0x200,
          "echo vazio rota B = 528 B (256 + 16 + 256, >= 0x200)", f"{len(echo9)}B")

    # (f) mock_server: probe rota B (valida tamanhos + a propria assinatura)
    ms._config_path = config_path
    total9, label9, body_len9, encrypted9 = ms._probe(cfg9)
    check(encrypted9 and total9 == body_len9 == 1008,
          "_probe(variante 9): wire de 1008 B, cifrado route=B", f"{total9}B {label9}")
    check("route=B" in label9, "label do _probe(variante 9) tem route=B", label9)
    total8, label8, body_len8, encrypted8 = ms._probe(with_variant(config, "8"))
    check(encrypted8 and total8 == 768 and "route=A" in label8,
          "_probe(variante 8) continua 768 B route=A", f"{total8}B {label8}")
    check(config.get("variants", {}).get("active") == "8",
          "config.json mantem variants.active = 8 (o orquestrador troca)",
          str(config.get("variants", {}).get("active")))
    print()

    # ---------------- hexdump ----------------
    cfg_payload = encode_config(config)
    cfg_frame, cfg_body = decode_frame(cfg_payload)
    if not args.no_hex:
        print("[hex] corpo Logon_Results do config.json (variante ativa)")
        for line in hexdump_lines(cfg_body):
            print("  " + line)
        print()
        print(f"  frameHex={cfg_payload[:13].hex()}  bodyLen={len(cfg_body)} "
              f"totalLen={len(cfg_payload)}")
        print(f"  bodyHex={cfg_body.hex()}")
        print()
        print("[hex] corpo de referencia 7.3 (469 B, 1 permissao)")
        print(f"  bodyHex={body.hex()}")
        print()

    # ---------------- resumo ----------------
    print(f"RESULTADO: {CHECKS - len(FAILS)}/{CHECKS} checagens ok")
    if FAILS:
        print("FALHAS:")
        for fail in FAILS:
            print(f"  - {fail}")
        return 1
    print("TODAS AS CHECAGENS PASSARAM (roundtrip + receita 7.3 byte-a-byte)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
