#!/usr/bin/env python3
"""xls_crypto.py — envelope CIFRADO da resposta Xls (mock v3, FM8).

Receita (ENVELOPE-SPEC.md, R6 + RUNTIME DUMP ANALYSIS R3.2/R3.3):

    P  = PKCS#7(frame13 || UserLogonResponse_body)      # frame 13 B DENTRO do ciphertext
    K  = 32 B aleatorios (chave AES-256 da RESPOSTA; o cliente aceita qualquer uma)
    ct = AES-256-CBC(key=K, iv=IV, P)                   # IV = 16 B aleatorios
    W  = RSA-OAEP-SHA1(client_pub, IV || K^mask || 16 B zeros)   # 64 B -> 256 B
    body_no_fio = IV(16) || ct || W(256)                # NAO tem frame de transporte

Variante 9 — ROTA B (ENVELOPE-SPEC §E6/E8.3, `MockCrypto.wrap_route_b`):

    body_no_fio = OAEP(client_pub, IV2 || K^mask || 0*16)[256]
                || AES-256-CBC(K, IV2, P)[ct]
                || SIG = PKCS#1v1.5-SHA256(client_private, body[0:len-256])[256]

O OAEP fica na FRENTE (o cliente chama BCryptDecrypt com `pbInput = body+0`, 0x100 B) e a
assinatura no FIM, cobrindo o prefixo inteiro — mesmo esquema do request real
(`[0:16] session value | [16:32] IV | [32:640] ct | [640:896] SIG`, E4).

O `mask` (32 B) e o estado vivo `crypto_ctx+0x20` que o cliente aplica ao material de
chave (R3.3: `KEY[i] = pt[0x10+i] ^ crypto[0x20+i]`). Desconhecido #1: o default e' zeros
(`crypto.mask` no config.json).

Desconhecido #2: `FUN_141c552f0` (ciphertext) roda no cliente ANTES do BCryptDecrypt,
sobre o bloco RSA (`0x141c539e3`). Nao e' emulavel por RE estatica; o mock apenas
registra um TODO (`crypto.skipPreStep`). Se ele validar o bloco (ex.: contra a publica do
servidor em +0x1a0), a resposta cifrada ainda pode ser recusada.

Chave publica do cliente: o binario embute o par RSA-2048 PRIVADO do cliente
(`BCRYPT_RSAPRIVATE_BLOB` magic 'RSA2', 542 B) em 0x1449209a0 e 0x144920bd0 do VA, ou
seja file offsets 0x0491f9a0 / 0x0491fbd0 em `dump_text.bin` (VA = file + 0x140001000).
Layout CNG (DWORDs little-endian):

    u32 magic 'RSA2' | u32 bitlen | u32 cbPublicExp | u32 cbModulus
    | u32 cbPrime1 | u32 cbPrime2 | exp | modulus | prime1 | prime2

(este blob NAO traz exp1/coeff1/coeff2 — sao derivados de p, q, e).

Sem dependencias obrigatorias: AES e RSA-OAEP-SHA1 tem implementacao pura em Python;
`cryptography` / `pycryptodome` sao usados quando presentes (a implementacao pura fica
como fallback e e' validada contra eles no self_test).
"""
from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass

# ----------------------------------------------------------------------------------
# constantes do binario / do envelope
# ----------------------------------------------------------------------------------
MAGIC_RSA2 = b"RSA2"
BLOB_SIZE = 542                       # 24 (header) + 3 (e) + 257 (n) + 129 (p) + 129 (q)
DEFAULT_BLOB_OFFSET = 0x0491F9A0      # VA 0x1449209a0 - 0x140001000
DEFAULT_BLOB_OFFSET_DUP = 0x0491FBD0  # VA 0x144920bd0 - 0x140001000

# n do cliente (ENVELOPE-SPEC R6) — usado para conferir que o offset do blob esta certo
CLIENT_N_HEX = (
    "00b3854ed10bbb6a996f488d9fed8660080d79b44cc1c829ec530a525ead8c4b1bff59ac"
    "5a089e601131f96908eea0ecf35aad668595669dcf8051ba1d681a936a76a828afafe6"
    "c32c4becda97f6f9abd984334e0dea2b112e0d3c1c5690c6eba6befe5434c27ec12e08"
    "b4ecd596c7c80e72f886a3c56224e2b86009de34910f18898a8a340931e07d901652b7"
    "081bd6033e6db132b5822ec49b8fdfb977fbbccdb6c747e0636f5956da66d819de3b62"
    "c5ebf19c8ea3f19db43a15bac774988ecea751e28381853e72685109bbfc99ab2c191a"
    "3af4f78d122b2d4b429e0f2c4ae4567ac2f617873f82211612d9f45b206d507b1daebc"
    "94f7610d0e1587903bfeab"
)

AES_KEY_SIZE = 32
IV_SIZE = 16
RSA_BLOCK = 256
MIN_DECRYPT_BODY = 0x110  # 272 B: minimo do parser de resposta (FUN_141c54050)


class CryptoError(Exception):
    """Erro de configuracao/parse/cripto do envelope (mensagem pronta para o log)."""


# ----------------------------------------------------------------------------------
# AES-256-CBC (cryptography -> pycryptodome -> Python puro)
# ----------------------------------------------------------------------------------
try:  # pragma: no cover - depende do ambiente
    from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms as _algorithms
    from cryptography.hazmat.primitives.ciphers import modes as _modes

    _HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    _HAS_CRYPTOGRAPHY = False

try:  # pragma: no cover
    from Crypto.Cipher import AES as _PyCryptoAES

    _HAS_PYCRYPTODOME = True
except Exception:  # pragma: no cover
    _HAS_PYCRYPTODOME = False

if _HAS_CRYPTOGRAPHY:
    AES_BACKEND = "cryptography"
elif _HAS_PYCRYPTODOME:
    AES_BACKEND = "pycryptodome"
else:
    AES_BACKEND = "pure"

# ------------------------------------------------------------------ AES puro (fallback)
_SBOX = None
_INV_SBOX = None


def _gmul(a: int, b: int) -> int:
    """Multiplicacao em GF(2^8) modulo 0x11b."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _sboxes() -> tuple[list[int], list[int]]:
    global _SBOX, _INV_SBOX
    if _SBOX is not None:
        return _SBOX, _INV_SBOX
    inv = [0] * 256
    for i in range(1, 256):  # i^254 = i^-1 (i^255 = 1 em GF(2^8))
        result = 1
        base, exp = i, 254
        while exp:
            if exp & 1:
                result = _gmul(result, base)
            base = _gmul(base, base)
            exp >>= 1
        inv[i] = result
    sbox = []
    for i in range(256):
        x = inv[i]
        s = x
        for shift in (1, 2, 3, 4):
            s ^= ((x << shift) | (x >> (8 - shift))) & 0xFF
        sbox.append(s ^ 0x63)
    inverse = [0] * 256
    for i, value in enumerate(sbox):
        inverse[value] = i
    _SBOX, _INV_SBOX = sbox, inverse
    return _SBOX, _INV_SBOX


def _expand_key(key: bytes) -> tuple[list[list[int]], int]:
    sbox, _ = _sboxes()
    nk = len(key) // 4
    nr = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [sbox[b] for b in temp]
            temp[0] ^= rcon
            rcon = _gmul(rcon, 2)
        elif nk > 6 and i % nk == 4:
            temp = [sbox[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    return words, nr


def _add_round_key(state: list[int], words: list[list[int]], rnd: int) -> None:
    for c in range(4):
        word = words[rnd * 4 + c]
        for r in range(4):
            state[4 * c + r] ^= word[r]


def _encrypt_block(block: bytes, words: list[list[int]], nr: int) -> bytes:
    sbox, _ = _sboxes()
    state = list(block)
    _add_round_key(state, words, 0)
    for rnd in range(1, nr + 1):
        for i in range(16):
            state[i] = sbox[state[i]]
        state = [state[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows
        if rnd != nr:
            mixed = []
            for c in range(4):
                col = state[4 * c:4 * c + 4]
                mixed.extend([
                    _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3],
                    col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3],
                    col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3),
                    _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2),
                ])
            state = mixed
        _add_round_key(state, words, rnd)
    return bytes(state)


def _decrypt_block(block: bytes, words: list[list[int]], nr: int) -> bytes:
    _, inverse = _sboxes()
    state = list(block)
    _add_round_key(state, words, nr)
    for rnd in range(nr - 1, -1, -1):
        # InvShiftRows
        state = [state[(i - 4 * (i % 4)) % 16] for i in range(16)]
        for i in range(16):
            state[i] = inverse[state[i]]
        _add_round_key(state, words, rnd)
        if rnd != 0:
            unmixed = []
            for c in range(4):
                col = state[4 * c:4 * c + 4]
                unmixed.extend([
                    _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13) ^ _gmul(col[3], 9),
                    _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11) ^ _gmul(col[3], 13),
                    _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14) ^ _gmul(col[3], 11),
                    _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9) ^ _gmul(col[3], 14),
                ])
            state = unmixed
    return bytes(state)


def _pure_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    words, nr = _expand_key(key)
    out = bytearray()
    prev = bytes(iv)
    for offset in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[offset:offset + 16], prev))
        prev = _encrypt_block(block, words, nr)
        out.extend(prev)
    return bytes(out)


def _pure_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    words, nr = _expand_key(key)
    out = bytearray()
    prev = bytes(iv)
    for offset in range(0, len(data), 16):
        block = bytes(data[offset:offset + 16])
        plain = _decrypt_block(block, words, nr)
        out.extend(bytes(a ^ b for a, b in zip(plain, prev)))
        prev = block
    return bytes(out)


def set_aes_backend(name: str | None) -> str:
    """Forca o backend ('cryptography' | 'pycryptodome' | 'pure') — usado no self_test."""
    global AES_BACKEND
    if name is None:
        AES_BACKEND = ("cryptography" if _HAS_CRYPTOGRAPHY
                       else "pycryptodome" if _HAS_PYCRYPTODOME else "pure")
        return AES_BACKEND
    if name == "cryptography" and not _HAS_CRYPTOGRAPHY:
        raise CryptoError("backend 'cryptography' indisponivel")
    if name == "pycryptodome" and not _HAS_PYCRYPTODOME:
        raise CryptoError("backend 'pycryptodome' indisponivel")
    if name not in ("cryptography", "pycryptodome", "pure"):
        raise CryptoError(f"backend desconhecido: {name!r}")
    AES_BACKEND = name
    return AES_BACKEND


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad


def pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data or len(data) % block:
        raise CryptoError(f"PKCS#7: tamanho {len(data)} nao e' multiplo de {block}")
    pad = data[-1]
    if not 1 <= pad <= block:
        raise CryptoError(f"PKCS#7: byte de padding invalido ({pad})")
    if data[-pad:] != bytes([pad]) * pad:
        raise CryptoError("PKCS#7: padding inconsistente")
    return data[:-pad]


def _aes_cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    if len(key) != AES_KEY_SIZE:
        raise CryptoError(f"chave AES: {len(key)} B (esperado {AES_KEY_SIZE})")
    if len(iv) != IV_SIZE:
        raise CryptoError(f"IV: {len(iv)} B (esperado {IV_SIZE})")
    if len(data) % 16:
        raise CryptoError(f"CBC: {len(data)} B nao e' multiplo de 16")
    if AES_BACKEND == "cryptography":
        cipher = _Cipher(_algorithms.AES(key), _modes.CBC(iv))
        worker = cipher.encryptor() if encrypt else cipher.decryptor()
        return worker.update(data) + worker.finalize()
    if AES_BACKEND == "pycryptodome":
        worker = _PyCryptoAES.new(key, _PyCryptoAES.MODE_CBC, iv)
        return worker.encrypt(data) if encrypt else worker.decrypt(data)
    return _pure_cbc_encrypt(key, iv, data) if encrypt else _pure_cbc_decrypt(key, iv, data)


def aes256_cbc_encrypt(key: bytes, iv: bytes, data: bytes, pad: bool = True) -> bytes:
    """AES-256-CBC com PKCS#7 (a receita do envelope cifrado)."""
    if pad:
        data = pkcs7_pad(data)
    return _aes_cbc(key, iv, data, encrypt=True)


def aes256_cbc_decrypt(key: bytes, iv: bytes, data: bytes, unpad: bool = True) -> bytes:
    plain = _aes_cbc(key, iv, data, encrypt=False)
    return pkcs7_unpad(plain) if unpad else plain


# ----------------------------------------------------------------------------------
# RSA-OAEP-SHA1 (encrypt puro-python; decrypt com `cryptography` quando disponivel)
# ----------------------------------------------------------------------------------
def _mgf1_sha1(seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha1(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(out[:length])


def rsa_oaep_sha1_encrypt(n: int, e: int, message: bytes, label: bytes = b"") -> bytes:
    """RSA-OAEP (MGF1-SHA1) — retorna exatamente k = (bitlen(n)+7)//8 bytes."""
    if n <= 0 or e <= 0:
        raise CryptoError("RSA: n/e invalidos")
    k = (n.bit_length() + 7) // 8
    hlen = hashlib.sha1().digest_size
    if len(message) > k - 2 * hlen - 2:
        raise CryptoError(f"OAEP: mensagem {len(message)} B > {k - 2 * hlen - 2} B")
    lhash = hashlib.sha1(label).digest()
    ps = b"\x00" * (k - len(message) - 2 * hlen - 2)
    db = lhash + ps + b"\x01" + message
    seed = os.urandom(hlen)
    db_mask = _mgf1_sha1(seed, k - hlen - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = _mgf1_sha1(masked_db, hlen)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    encoded = b"\x00" + masked_seed + masked_db
    cipher = pow(int.from_bytes(encoded, "big"), e, n)
    return cipher.to_bytes(k, "big")


def rsa_oaep_sha1_encrypt_block(n: int, e: int, data: bytes, size: int = RSA_BLOCK) -> bytes:
    """Como acima, mas exige que o ciphertext tenha exatamente `size` bytes (256 B)."""
    out = rsa_oaep_sha1_encrypt(n, e, data)
    if len(out) != size:
        raise CryptoError(f"RSA: ciphertext {len(out)} B (esperado {size} B)")
    return out


# ----------------------------------------------------------------------------------
# chave do cliente (BCRYPT_RSAPRIVATE_BLOB 'RSA2')
# ----------------------------------------------------------------------------------
def parse_bcrypt_rsa_private_blob(blob: bytes) -> dict:
    """Parseia o 'RSA2' do binario e deriva d / dp / dq / qinv (ausentes no blob)."""
    if len(blob) < 24:
        raise CryptoError(f"blob RSA2 truncado: {len(blob)} B")
    if blob[:4] != MAGIC_RSA2:
        raise CryptoError(f"magic {blob[:4]!r} != {MAGIC_RSA2!r} "
                          f"(offset errado: use VA - 0x140001000)")
    magic, bitlen, cb_exp, cb_mod, cb_p1, cb_p2 = struct.unpack("<IIIIII", blob[:24])
    need = 24 + cb_exp + cb_mod + cb_p1 + cb_p2
    if len(blob) < need:
        raise CryptoError(f"blob RSA2 truncado: {len(blob)} B < {need} B do header")
    pos = 24
    exp = blob[pos:pos + cb_exp]; pos += cb_exp
    mod = blob[pos:pos + cb_mod]; pos += cb_mod
    prime1 = blob[pos:pos + cb_p1]; pos += cb_p1
    prime2 = blob[pos:pos + cb_p2]; pos += cb_p2
    e = int.from_bytes(exp, "big")
    n = int.from_bytes(mod, "big")
    p = int.from_bytes(prime1, "big")
    q = int.from_bytes(prime2, "big")
    if e < 3 or e % 2 == 0:
        raise CryptoError(f"expoente publico invalido: {e}")
    if n.bit_length() != bitlen:
        raise CryptoError(f"bitlen do header ({bitlen}) != bits de n ({n.bit_length()})")
    if p * q != n:
        raise CryptoError("p*q != n (blob inconsistente)")
    if any(x <= 1 for x in (p, q)):
        raise CryptoError("primo invalido no blob")
    # d = e^-1 mod lcm(p-1, q-1)  (equivale a mod (p-1)(q-1); CNG usa o lcm)
    lam = (p - 1) * (q - 1) // _gcd(p - 1, q - 1)
    d = pow(e, -1, lam)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = pow(q, -1, p)
    return {
        "n": n, "e": e, "d": d, "p": p, "q": q, "dp": dp, "dq": dq, "qinv": qinv,
        "bitlen": bitlen, "size": need, "cb_exp": cb_exp, "cb_mod": cb_mod,
        "cb_p1": cb_p1, "cb_p2": cb_p2, "n_hex": mod.hex(),
    }


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def read_rsa2_blob(dump_path: str, offset: int = DEFAULT_BLOB_OFFSET,
                   size: int = BLOB_SIZE) -> bytes:
    """Le o blob 'RSA2' do dump (offset de ARQUIVO = VA - 0x140001000)."""
    if not os.path.exists(dump_path):
        raise CryptoError(f"dump nao encontrado: {dump_path}")
    with open(dump_path, "rb") as handle:
        handle.seek(offset)
        blob = handle.read(size)
    if len(blob) != size:
        raise CryptoError(f"dump truncado em 0x{offset:x}: {len(blob)} B < {size} B")
    if blob[:4] != MAGIC_RSA2:
        raise CryptoError(f"offset 0x{offset:x}: magic {blob[:4]!r} != {MAGIC_RSA2!r}")
    return blob


_PEM_CACHE: dict[str, dict] = {}


def _pem_paths(key_dir: str) -> tuple[str, str]:
    return (os.path.join(key_dir, "client_private.pem"),
            os.path.join(key_dir, "client_public.pem"))


def _write_pem(key_dir: str, material: dict) -> tuple[str, str]:
    """Escreve client_private.pem/client_public.pem (precisa de `cryptography`)."""
    if not _HAS_CRYPTOGRAPHY:
        return ("", "")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    public_numbers = rsa.RSAPublicNumbers(material["e"], material["n"])
    private_numbers = rsa.RSAPrivateNumbers(
        p=material["p"], q=material["q"], d=material["d"],
        dmp1=material["dp"], dmq1=material["dq"], iqmp=material["qinv"],
        public_numbers=public_numbers,
    )
    key = private_numbers.private_key()  # valida p*q == n e d*e == 1 mod lcm
    os.makedirs(key_dir, exist_ok=True)
    priv_path, pub_path = _pem_paths(key_dir)
    with open(priv_path, "wb") as handle:
        handle.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    with open(pub_path, "wb") as handle:
        handle.write(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv_path, pub_path


def load_client_key_material(dump_path: str = "dump_text.bin",
                             key_dir: str = "keys",
                             blob_offset: int = DEFAULT_BLOB_OFFSET,
                             write_pem: bool = True) -> dict:
    """Devolve {n, e, d, p, q, ...} do cliente.

    Ordem: PEM ja' derivado em `key_dir` -> blob 'RSA2' do dump (offset principal e,
    se o magic falhar, a duplicata 0x0491fbd0). `write_pem` grava client_private.pem +
    client_public.pem (so' quando `cryptography` esta' disponivel).
    """
    cache_key = f"{os.path.abspath(dump_path)}|{blob_offset}|{os.path.abspath(key_dir)}"
    if cache_key in _PEM_CACHE:
        return _PEM_CACHE[cache_key]

    priv_path, _ = _pem_paths(key_dir)
    if os.path.exists(priv_path):
        try:
            material = _material_from_pem(priv_path)
            material["source"] = f"pem:{priv_path}"
            _PEM_CACHE[cache_key] = material
            return material
        except Exception as exc:  # PEM corrompido -> re-derivar do dump
            print(f"[crypto] aviso: {priv_path} ilegivel ({exc}); re-derivando do dump")

    errors = []
    blob = None
    for offset in (blob_offset, DEFAULT_BLOB_OFFSET_DUP):
        try:
            blob = read_rsa2_blob(dump_path, offset)
            material = parse_bcrypt_rsa_private_blob(blob)
            material["source"] = f"dump:0x{offset:x}"
            material["blob_offset"] = offset
            break
        except (CryptoError, OSError) as exc:
            errors.append(f"0x{offset:x}: {exc}")
            blob = None
    if blob is None:
        raise CryptoError("nao foi possivel ler o blob 'RSA2' do cliente -> " +
                          " | ".join(errors))
    if material["n_hex"] != CLIENT_N_HEX:
        raise CryptoError("n do blob nao bate com o da ENVELOPE-SPEC (offset errado?)")
    if write_pem:
        priv_path, pub_path = _write_pem(key_dir, material)
        material["pem_private"] = priv_path
        material["pem_public"] = pub_path
    _PEM_CACHE[cache_key] = material
    return material


def _material_from_pem(path: str) -> dict:
    if not _HAS_CRYPTOGRAPHY:
        raise CryptoError("`cryptography` ausente: nao consigo ler PEM")
    from cryptography.hazmat.primitives import serialization

    with open(path, "rb") as handle:
        key = serialization.load_pem_private_key(handle.read(), password=None)
    numbers = key.private_numbers()
    public = numbers.public_numbers
    n_hex = public.n.to_bytes((public.n.bit_length() + 7) // 8, "big").hex()
    return {
        "n": public.n, "e": public.e,
        "d": numbers.d, "p": numbers.p, "q": numbers.q,
        "dp": numbers.dmp1, "dq": numbers.dmq1, "qinv": numbers.iqmp,
        "bitlen": public.n.bit_length(), "n_hex": n_hex,
    }


def oaep_decrypt_with_private(material: dict, ciphertext: bytes) -> bytes:
    """Decifra W com a privada do cliente (so' para verificar a receita no self_test)."""
    if _HAS_CRYPTOGRAPHY:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        key = rsa.RSAPrivateNumbers(
            p=material["p"], q=material["q"], d=material["d"],
            dmp1=material["dp"], dmq1=material["dq"], iqmp=material["qinv"],
            public_numbers=rsa.RSAPublicNumbers(material["e"], material["n"]),
        ).private_key()
        return key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                         algorithm=hashes.SHA1(), label=None))
    # fallback puro: RAWTYPE sem verificacao de padding OAEP (nao recomendado)
    k = (material["n"].bit_length() + 7) // 8
    if len(ciphertext) != k:
        raise CryptoError(f"RSA: ciphertext {len(ciphertext)} B (esperado {k} B)")
    m = pow(int.from_bytes(ciphertext, "big"), material["d"], material["n"])
    encoded = m.to_bytes(k, "big")
    hlen = hashlib.sha1().digest_size
    if encoded[0] != 0:
        raise CryptoError("OAEP: prefixo != 0")
    masked_seed = encoded[1:1 + hlen]
    masked_db = encoded[1 + hlen:]
    seed = bytes(a ^ b for a, b in zip(masked_seed, _mgf1_sha1(masked_db, hlen)))
    db = bytes(a ^ b for a, b in zip(masked_db, _mgf1_sha1(seed, k - hlen - 1)))
    if db[:hlen] != hashlib.sha1(b"").digest():
        raise CryptoError("OAEP: lHash invalido")
    pos = hlen
    while pos < len(db) and db[pos] == 0:
        pos += 1
    if pos >= len(db) or db[pos] != 1:
        raise CryptoError("OAEP: separador 0x01 ausente")
    return db[pos + 1:]


# ----------------------------------------------------------------------------------
# RSA PKCS#1 v1.5 + SHA-256 (ASSINATURA — shape do request e da rota B, E3/E4/E6)
# ----------------------------------------------------------------------------------
# DigestInfo DER de SHA-256: SEQUENCE{SEQUENCE{OID sha256, NULL}, OCTET STRING(32)}
DIGESTINFO_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

_PRIV_KEY_CACHE: dict[tuple[int, int], object] = {}


def _private_key_object(material: dict):
    """Constroi (e cacheia) o objeto RSA privado do cliente via `cryptography`."""
    if not _HAS_CRYPTOGRAPHY:
        raise CryptoError("`cryptography` ausente: assinatura usaria o caminho puro")
    from cryptography.hazmat.primitives.asymmetric import rsa

    cache_key = (material["n"], material["d"])
    key = _PRIV_KEY_CACHE.get(cache_key)
    if key is None:
        key = rsa.RSAPrivateNumbers(
            p=material["p"], q=material["q"], d=material["d"],
            dmp1=material["dp"], dmq1=material["dq"], iqmp=material["qinv"],
            public_numbers=rsa.RSAPublicNumbers(material["e"], material["n"]),
        ).private_key()
        _PRIV_KEY_CACHE[cache_key] = key
    return key


def _pkcs1v15_sha256_em(data: bytes, k: int) -> bytes:
    """EMSA-PKCS1-v1_5 para SHA-256: 00 01 FF..FF 00 || DigestInfo || digest."""
    if k < len(DIGESTINFO_SHA256_PREFIX) + 32 + 11:
        raise CryptoError(f"RSA: modulo de {k} B e' curto para PKCS#1v1.5-SHA256")
    digest_info = DIGESTINFO_SHA256_PREFIX + hashlib.sha256(data).digest()
    ps = b"\xff" * (k - 3 - len(digest_info))
    return b"\x00\x01" + ps + b"\x00" + digest_info


def rsa_sign_pkcs1v15_sha256(material: dict, data: bytes) -> bytes:
    """Assina `data` com a PRIVADA do cliente (PKCS#1 v1.5 + SHA-256).

    `cryptography` quando disponivel (caminho autoritativo); senao RSASSA puro:
    `sig = pow(int(EM), d, n)` com EM = 00 01 FF.. 00 || DigestInfo(SHA-256) || digest.
    """
    n = material["n"]
    k = (n.bit_length() + 7) // 8
    if _HAS_CRYPTOGRAPHY:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        signature = _private_key_object(material).sign(
            data, padding.PKCS1v15(), hashes.SHA256())
    else:
        if "d" not in material:
            raise CryptoError("assinatura pura precisa de `d` no material da chave")
        em = _pkcs1v15_sha256_em(data, k)
        signature = pow(int.from_bytes(em, "big"), material["d"], n).to_bytes(k, "big")
    if len(signature) != k:
        raise CryptoError(f"assinatura {len(signature)} B != modulo {k} B")
    return signature


def rsa_recover_pkcs1v15_sha256(material: dict, signature: bytes) -> bytes:
    """Recupera o EM (k bytes) de uma assinatura: pow(sig, e, n). Diagnostico/verify."""
    k = (material["n"].bit_length() + 7) // 8
    if len(signature) != k:
        raise CryptoError(f"assinatura {len(signature)} B != modulo {k} B")
    return pow(int.from_bytes(signature, "big"), material["e"],
               material["n"]).to_bytes(k, "big")


def rsa_verify_pkcs1v15_sha256(material: dict, signature: bytes, data: bytes) -> bool:
    """Verifica a assinatura com a PUBLICA (so' precisa de n/e). Estrutura estrita."""
    try:
        em = rsa_recover_pkcs1v15_sha256(material, signature)
    except (CryptoError, KeyError):
        return False
    if len(em) < 11 or em[0] != 0 or em[1] != 1:
        return False
    index = em.find(b"\x00", 2)
    if index < 0 or index - 2 < 8:
        return False
    if em[2:index] != b"\xff" * (index - 2):
        return False
    return em[index + 1:] == DIGESTINFO_SHA256_PREFIX + hashlib.sha256(data).digest()


# ----------------------------------------------------------------------------------
# config do mock (bloco "crypto" do config.json)
# ----------------------------------------------------------------------------------
def _hex_bytes(value, size: int, name: str) -> bytes | None:
    if value is None:
        return None
    text = str(value).strip().lower().replace(" ", "").replace(":", "")
    if text.startswith("0x"):
        text = text[2:]
    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise CryptoError(f"crypto.{name}: hex invalido ({exc})") from exc
    if len(raw) != size:
        raise CryptoError(f"crypto.{name}: {len(raw)} B (esperado {size} B)")
    return raw


def _int_value(value, default: int, name: str) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    try:
        return int(text, 0)
    except ValueError as exc:
        raise CryptoError(f"crypto.{name}: inteiro invalido ({value!r})") from exc


@dataclass
class CryptoConfig:
    """Knobs do envelope cifrado (mock v3)."""

    mask: bytes = b"\x00" * AES_KEY_SIZE
    aes_key: bytes | None = None      # None = aleatoria por sessao
    iv: bytes | None = None           # None = aleatoria por mensagem
    key_dir: str = "keys"
    dump_path: str = "dump_text.bin"
    blob_offset: int = DEFAULT_BLOB_OFFSET
    skip_pre_step: bool = True
    encrypt_echo: bool = True
    write_pem: bool = True

    def describe(self) -> str:
        return (f"mask={self.mask.hex()} preStep={'skip' if self.skip_pre_step else 'todo'} "
                f"echo={'enc' if self.encrypt_echo else 'plain'} "
                f"keyDir={os.path.basename(self.key_dir) or self.key_dir}")

    @classmethod
    def from_config(cls, config: dict | None, base_dir: str | None = None) -> "CryptoConfig":
        base = os.path.abspath(base_dir or os.path.dirname(os.path.abspath(__file__)))
        block = dict((config or {}).get("crypto") or {})
        cfg = cls()
        if "mask" in block:
            mask = _hex_bytes(block.get("mask"), AES_KEY_SIZE, "mask")
            if mask is not None:
                cfg.mask = mask
        cfg.aes_key = _hex_bytes(block.get("aesKeyHex"), AES_KEY_SIZE, "aesKeyHex")
        cfg.iv = _hex_bytes(block.get("ivHex"), IV_SIZE, "ivHex")
        if block.get("keyDir"):
            cfg.key_dir = os.path.join(base, str(block["keyDir"]))
        else:
            cfg.key_dir = os.path.join(base, "keys")
        cfg.dump_path = (os.path.join(base, str(block["dump"]))
                         if block.get("dump") else os.path.join(base, "dump_text.bin"))
        cfg.blob_offset = _int_value(block.get("blobOffset"), DEFAULT_BLOB_OFFSET,
                                     "blobOffset")
        if "skipPreStep" in block:
            cfg.skip_pre_step = bool(block["skipPreStep"])
        if "encryptEcho" in block:
            cfg.encrypt_echo = bool(block["encryptEcho"])
        if "writePem" in block:
            cfg.write_pem = bool(block["writePem"])
        return cfg


# ----------------------------------------------------------------------------------
# sessao do mock: escolhe K/IV, embrulha respostas, decifra requests
# ----------------------------------------------------------------------------------
class MockCrypto:
    """Estado criptografico do mock (chave de sessao + IV que o cliente adota)."""

    def __init__(self, material: dict, mask: bytes | None = None,
                 key: bytes | None = None, iv: bytes | None = None,
                 key_is_effective: bool = True) -> None:
        self.n = material["n"]
        self.e = material["e"]
        self.material = material
        self.mask = mask if mask is not None else b"\x00" * AES_KEY_SIZE
        if len(self.mask) != AES_KEY_SIZE:
            raise CryptoError(f"mask: {len(self.mask)} B (esperado {AES_KEY_SIZE} B)")
        self.aes_key = key or os.urandom(AES_KEY_SIZE)
        self.iv = iv or os.urandom(IV_SIZE)
        if len(self.aes_key) != AES_KEY_SIZE:
            raise CryptoError(f"chave AES: {len(self.aes_key)} B")
        if len(self.iv) != IV_SIZE:
            raise CryptoError(f"IV: {len(self.iv)} B")
        self.key_is_effective = key_is_effective
        self.responses = 0
        self.signatures = 0
        self.requests_ok = 0
        self.requests_fail = 0
        self.requests_sig_ok = 0

    # -- material de chave que viaja dentro do RSA (64 B) -------------------------
    def key_material(self, key: bytes | None = None, iv: bytes | None = None) -> bytes:
        key = key or self.aes_key
        iv = iv or self.iv
        masked = bytes(a ^ b for a, b in zip(key, self.mask))
        return iv + masked + b"\x00" * 16

    # -- resposta: IV || AES-CBC(P) || RSA-OAEP(IV || K^mask || 0*16) -------------
    def wrap(self, plaintext: bytes, rotate_iv: bool = True,
             key: bytes | None = None) -> bytes:
        key = key or self.aes_key
        iv = os.urandom(IV_SIZE) if rotate_iv else self.iv
        if rotate_iv:
            self.iv = iv
        ciphertext = aes256_cbc_encrypt(key, iv, plaintext)
        wrapped = rsa_oaep_sha1_encrypt_block(self.n, self.e,
                                             self.key_material(key, iv), RSA_BLOCK)
        self.responses += 1
        return iv + ciphertext + wrapped

    def rotate(self, key: bytes | None = None, iv: bytes | None = None) -> None:
        self.aes_key = key or os.urandom(AES_KEY_SIZE)
        self.iv = iv or os.urandom(IV_SIZE)

    # -- ROTA B: OAEP(64B) || AES-CBC(P) || SIG(PKCS1v15-SHA256 do prefixo) -------
    def wrap_route_b(self, plaintext: bytes, rotate_iv: bool = True,
                     key: bytes | None = None) -> bytes:
        """Envelope da rota B (`FUN_141c53920` + `FUN_141c543f0`, min 0x200).

        O bloco OAEP fica **na frente** (o cliente faz BCryptDecrypt em
        `pbInput = body+0`, `0x100 B`) e a ASSINATURA no fim, cobrindo tudo antes dela
        (`body[0:len-0x100]`), exatamente como no request (E4/E6).
        """
        key = key or self.aes_key
        iv = os.urandom(IV_SIZE) if rotate_iv else self.iv
        if rotate_iv:
            self.iv = iv
        oaep = rsa_oaep_sha1_encrypt_block(self.n, self.e,
                                           self.key_material(key, iv), RSA_BLOCK)
        ciphertext = aes256_cbc_encrypt(key, iv, plaintext)
        prefix = oaep + ciphertext
        signature = rsa_sign_pkcs1v15_sha256(self.material, prefix)
        self.responses += 1
        self.signatures += 1
        return prefix + signature

    def verify_message_signature(self, body: bytes) -> bool:
        """Verifica a assinatura do tail (PKCS#1v1.5/SHA-256) sobre `body[:-256]`.

        Vale para o REQUEST real (E3: sig em `body[640:896]` sobre `body[0:640]`) e para
        a resposta da rota B (mesma convencao). Nao precisa de chave simetrica.
        """
        if len(body) <= RSA_BLOCK:
            return False
        if not rsa_verify_pkcs1v15_sha256(self.material, body[-RSA_BLOCK:],
                                          body[:-RSA_BLOCK]):
            return False
        self.requests_sig_ok += 1
        return True

    # -- request do cliente: [IV_sessao 16][rand 16][ct][RSA 256] (R3.2) ----------
    def unwrap_request(self, body: bytes) -> tuple[bytes, str]:
        """Decifra um request do cliente com a chave/IV de sessao do mock.

        Shape do encrypt (FUN_141c547a0): out[0..16) = IV da sessao,
        out[16..32) = 16 B aleatorios (IV real do CBC), ct a partir de 32, RSA no fim.
        O parser de resposta (FUN_141c54050) usa o shape curto [IV][ct][RSA]; os dois
        sao tentados (32 primeiro) e o resultado tem de passar no PKCS#7 e parecer frame.
        """
        if len(body) < MIN_DECRYPT_BODY:
            raise CryptoError(f"body {len(body)} B < {MIN_DECRYPT_BODY} B")
        last = "sem tentativa valida"
        for head in (32, 16):
            if len(body) <= head + RSA_BLOCK:
                continue
            ct = body[head:len(body) - RSA_BLOCK]
            if not ct or len(ct) % 16:
                continue
            candidates = [(f"body[{head - 16}:{head}]", body[head - 16:head])]
            if head == 32:
                candidates.append(("body[0:16]", body[0:16]))
            candidates.append(("session_iv", self.iv))
            for label, iv in candidates:
                try:
                    plain = aes256_cbc_decrypt(self.aes_key, iv, ct)
                except CryptoError as exc:
                    last = f"head={head} {label}: {exc}"
                    continue
                if len(plain) < 13 or plain[0] > 2:
                    last = f"head={head} {label}: plaintext nao parece frame"
                    continue
                self.requests_ok += 1
                return plain, f"head={head} iv={label}"
        self.requests_fail += 1
        raise CryptoError(f"nao decifrou request ({last})")

    def describe(self) -> str:
        return (f"mask={self.mask.hex()[:8]}.. key={self.aes_key.hex()[:8]}.. "
                f"iv={self.iv.hex()[:8]}.. rsa={self.n.bit_length()}b "
                f"e=0x{self.e:x} sigs={self.signatures}")


def build_mock_crypto(config: dict | None = None, base_dir: str | None = None,
                      rotate: bool = True) -> tuple[MockCrypto, CryptoConfig]:
    """Monta o MockCrypto a partir do config.json (deriva a chave do cliente 1x).

    `crypto.aesKeyHex`/`ivHex` no config fixam K/IV (util para debug/reproducao);
    ausentes => chave nova por sessao de Logon (`rotate=True`) e IV novo por mensagem.
    """
    cfg = CryptoConfig.from_config(config, base_dir)
    material = load_client_key_material(cfg.dump_path, cfg.key_dir,
                                        cfg.blob_offset, cfg.write_pem)
    key = cfg.aes_key
    if rotate and key is None:
        key = os.urandom(AES_KEY_SIZE)
    return MockCrypto(material, mask=cfg.mask, key=key, iv=cfg.iv), cfg


def self_check() -> list[str]:
    """Sanidade barata (sem dump): AES backend + OAEP roundtrip com chave de teste."""
    notes = [f"aes_backend={AES_BACKEND}"]
    key = bytes(range(32))
    iv = bytes(range(16))
    plain = b"xls-mock-v3 self-check"
    blob = aes256_cbc_encrypt(key, iv, plain)
    if aes256_cbc_decrypt(key, iv, blob) != plain:
        raise CryptoError("AES roundtrip falhou")
    notes.append(f"aes_roundtrip=ok ({len(blob)} B)")
    return notes
