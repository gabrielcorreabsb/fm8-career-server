#!/usr/bin/env python3
"""mock_server.py — mock LSP v3 (Forza Motorsport / FM8) com `Logon_Results` CIFRADOS.

Base: `ENVELOPE-SPEC.md` §7 + RUNTIME DUMP ANALYSIS (R3-R6). Decifrado em runtime, o
cliente NAO tem caminho de plaintext: o provider de mensagem decifra incondicionalmente
IV + AES-256-CBC + PKCS#7 + RSA-OAEP-SHA1 no fim do body. Logo a resposta tem de ser
cifrada com a publica do CLIENTE (embutida no binario, blob 'RSA2').

Receita (variante 8, `xls_crypto.py`):
  P  = PKCS#7(frame13 || UserLogonResponse_body)     # frame 13 B DENTRO do ciphertext
  ct = AES-256-CBC(K, IV, P)                          # K/IV aleatorios por Logon
  W  = RSA-OAEP-SHA1(client_pub, IV || K^mask || 16 B zeros)    # 256 B, no FIM do body
  body_no_fio = IV(16) || ct || W(256)                # 768 B para o corpo de 469 B
  Content-Length = 768 (o frame NAO vai em claro no wire; §7.1 vale so' para plaintext)

Efeito colateral a favor do mock: ao desembrulhar, o cliente grava K/IV da resposta em
session+0x208/+0x238 e passa a cifrar os requests seguintes com eles (rollover) — por
isso o mock consegue decifrar os requests e logar o frame (sinal de ACEITE).

Presets default do ciclo (um boot testa): 8,8,8,8,8 — todas cifradas.
Controle ao vivo: /preset/N (1..8), /auto, /status em :5080.

Uso:
  python mock_server.py                       # 127.0.0.1:443, certs do config
  python mock_server.py --variant 8           # forca a variante cifrada
  python mock_server.py --variant 2           # volta ao plaintext (comparacao)
  python mock_server.py --port 8443 --variant 8
  python mock_server.py --tls C:\\certs\\cert.pem C:\\certs\\key.pem --port 443

Protocolo de teste (1 boot por variante, §7.4):
  aceite  = 1x Logon e depois KeepAlive/DownloadPlayerProfile/UpdatePlayerProfile;
  recusa  = Logon repetido (~2,5 s de intervalo, até ~4x).

100% local: serviço real nunca é contatado; nada é instalado, nenhum hosts/CA tocado.
"""
import argparse
import json
import os
import ssl
import sys
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from xls_encoder import (  # noqa: E402
    EncodeOptions,
    FRAME_SIZE,
    FRAME_SIZE_CONTROL,
    XlsEncoderError,
    build_frame,
    decode_frame,
    encode_config,
    load_config,
    options_for,
    resolve_variant,
)
import xls_crypto  # noqa: E402
from xls_crypto import CryptoError, MockCrypto  # noqa: E402

DEFAULT_CONFIG = os.path.join(BASE, "config.json")
DEFAULT_LOG = os.path.join(BASE, "capture_log.jsonl")

_lock = threading.Lock()
_method_counts: Counter = Counter()
_logon_count = 0
_first_other_method: str | None = None
_last_body_len = 0
_last_variant = ""
_response_error: str | None = None
_config_path = DEFAULT_CONFIG
_log_path = DEFAULT_LOG
_variant_override: str | None = None
_cycling_enabled = True
_cycle_index = 0
_pending_http_status = 200
_last_real_logon_ts = 0.0

_crypto_lock = threading.Lock()
_crypto: MockCrypto | None = None
_crypto_cfg: xls_crypto.CryptoConfig | None = None
_crypto_sig = ""
_crypto_note = ""


def _variant_label(config: dict) -> str:
    return resolve_variant(config).describe()


def _effective_config() -> dict:
    """config.json + `--variant` / `/preset/N` (o override vale para o processo todo)."""
    config = load_config(_config_path)
    if _variant_override:
        config.setdefault("variants", {})["active"] = _variant_override
    return config


def _crypto_session(config: dict, create: bool = True) -> tuple[MockCrypto | None,
                                                             xls_crypto.CryptoConfig | None]:
    """Sessão cripto do mock (1 por bloco `crypto` do config; recriada se o bloco mudar)."""
    global _crypto, _crypto_cfg, _crypto_sig, _crypto_note
    sig = json.dumps(config.get("crypto") or {}, sort_keys=True, default=str)
    with _crypto_lock:
        if _crypto is not None and sig == _crypto_sig:
            return _crypto, _crypto_cfg
        if not create:
            return None, None
        crypto, cfg = xls_crypto.build_mock_crypto(config, BASE)
        _crypto, _crypto_cfg, _crypto_sig = crypto, cfg, sig
        _crypto_note = (f"mask={cfg.mask.hex()} aes={xls_crypto.AES_BACKEND} "
                        f"key={crypto.aes_key.hex()[:12]}.. iv={crypto.iv.hex()[:12]}.. "
                        f"rsa={crypto.n.bit_length()}b source={crypto.material.get('source')}")
        print(f"[mock] crypto: {_crypto_note}")
        if cfg.skip_pre_step:
            print("[mock] TODO: FUN_141c552f0 (pre-passo RSA do cliente, ciphertext) NAO "
                  "emulado - se ele validar o bloco W, a resposta cifrada sera recusada")
        if cfg.mask == b"\x00" * xls_crypto.AES_KEY_SIZE:
            print("[mock] TODO: mask = 0 (desconhecido #1). Se o cliente recusar, ler "
                  "crypto_ctx+0x20 do processo e por no config crypto.mask")
        return _crypto, _crypto_cfg


class ControlHandler(BaseHTTPRequestHandler):
    """Controle ao vivo (HTTP simples, sem TLS): /preset/N, /auto, /status."""

    def _reply(self, text: str, status: int = 200) -> None:
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        global _variant_override, _cycle_index, _pending_http_status
        if self.path.startswith("/preset/"):
            preset = self.path.split("/preset/", 1)[1].strip().rstrip("/")
            if preset in {"1", "2", "3", "4", "5", "6", "7", "8", "9"}:
                with _lock:
                    _variant_override = preset
                    _cycle_index = 0
                    _pending_http_status = 200
                extra = {"8": " (CIFRADA rota A: IV||ct||RSA256)",
                         "9": " (CIFRADA rota B: OAEP||ct||SIG256)"}.get(preset, "")
                self._reply(f"preset fixo = {preset}{extra} "
                            f"(o proximo Logon do jogo usa essa variante)")
            else:
                self._reply("preset invalido (use 1..9 ou /auto)", 400)
        elif self.path.startswith("/auto"):
            with _lock:
                _variant_override = None
                _cycle_index = 0
                _pending_http_status = 200
            self._reply("auto-cycle reativado (presets 8,8,8,8,8 = todas cifradas)")
        elif self.path.startswith("/status"):
            crypto, cfg = _crypto_session(_effective_config(), create=False)
            self._reply(json.dumps({
                "variant_override": _variant_override,
                "cycling": _variant_override is None,
                "cycle_index": _cycle_index,
                "logon_count": _logon_count,
                "last_variant": _last_variant,
                "last_body_len": _last_body_len,
                "first_other_method": _first_other_method,
                "pending_http_status": _pending_http_status,
                "crypto": {
                    "active": crypto is not None,
                    "route": resolve_variant(_effective_config()).route,
                    "mask_zero": bool(cfg and cfg.mask == b"\x00" * xls_crypto.AES_KEY_SIZE),
                    "skip_pre_step": bool(cfg and cfg.skip_pre_step),
                    "encrypt_echo": bool(cfg and cfg.encrypt_echo),
                    "aes_backend": xls_crypto.AES_BACKEND,
                    "session_key": crypto.aes_key.hex() if crypto else None,
                    "session_iv": crypto.iv.hex() if crypto else None,
                    "responses": crypto.responses if crypto else 0,
                    "responses_signed": crypto.signatures if crypto else 0,
                    "requests_decrypted": crypto.requests_ok if crypto else 0,
                    "requests_failed": crypto.requests_fail if crypto else 0,
                    "requests_signature_verified": (crypto.requests_sig_ok
                                                    if crypto else 0),
                },
            }, indent=1))
        else:
            self._reply("usos: /preset/N (1..9; 8 = cifrada rota A, 9 = rota B) | /auto | /status")

    def log_message(self, fmt, *args):
        pass  # silencioso


def build_logon_payload() -> tuple[bytes, str, int]:
    """Payload HTTP do Logon. Devolve (wire, label, len do corpo que vai no fio).

    Variante 8 (rota A): `wire` = IV||AES-256-CBC(frame13||corpo)||RSA-256 (768 B).
    Variante 9 (rota B): `wire` = OAEP(IV2||K||0*16)||AES-256-CBC(...)||SIG (1008 B).
    Em ambas o frame 13 B vai DENTRO do ciphertext. Sem cycle_on (--variant/ override)
    cada resposta usa a variante fixada.
    """
    global _cycling_enabled, _cycle_index, _pending_http_status
    config = _effective_config()
    if not _variant_override:
        presets = ["8", "8", "8", "8", "8"]  # mock v3: todas as tentativas cifradas
        with _lock:
            idx = _cycle_index
        preset = presets[idx]
        if preset == "7":
            if _logon_count <= 1:
                _pending_http_status = 418
                print("[mock] Logon response -> HTTP 418 (renegotiate probe, tentativa 1)")
                return (build_frame(b"", EncodeOptions().validated()),
                        "variant=7 reneg-418 attempt1", 13)
            with _lock:
                _cycle_index = (idx + 1) % len(presets)
            preset = "8"
            print("[mock] Logon response -> variante 8 (cifrada) apos probe 418")
        else:
            with _lock:
                _cycle_index = (idx + 1) % len(presets)
        config.setdefault("variants", {})["active"] = preset
        print(f"[mock] Logon response -> variante {preset}")
    _pending_http_status = 200
    variant = resolve_variant(config)
    opts = options_for(config)
    payload = encode_config(config)  # plaintext: frame 13 B + corpo (UserLogonResponse)
    frame_size = FRAME_SIZE if opts.frame_size == FRAME_SIZE else FRAME_SIZE_CONTROL
    body_len = len(payload) - frame_size
    if variant.encrypted:
        crypto, crypto_cfg = _crypto_session(config)
        if crypto is None:
            raise CryptoError("sessao cripto indisponivel")
        if crypto_cfg is not None and crypto_cfg.aes_key is None:
            crypto.rotate()  # K/IV novos por Logon: o cliente aceita qualquer chave
        if variant.route.upper() == "B":
            wire = crypto.wrap_route_b(payload)
            oaep_len = xls_crypto.RSA_BLOCK
            sig_len = xls_crypto.RSA_BLOCK
            ct_len = len(wire) - oaep_len - sig_len
            print(f"[mock] Logon rota B: plain={len(payload)}B "
                  f"(frame 13 + corpo {body_len}) -> wire={len(wire)}B "
                  f"oaepLen={oaep_len} ctLen={ct_len} sigLen={sig_len} "
                  f"bodyLen={len(wire)} key={crypto.aes_key.hex()[:12]}..")
            label = (f"{variant.describe()} oaepLen={oaep_len} ctLen={ct_len} "
                     f"sigLen={sig_len} bodyLen={len(wire)} "
                     f"sessionKey={crypto.aes_key.hex()[:12]}")
        else:
            wire = crypto.wrap(payload)
            print(f"[mock] Logon cifrado: plain={len(payload)}B "
                  f"(frame 13 + corpo {body_len}) -> wire={len(wire)}B "
                  f"ct={len(wire) - 16 - 256}B key={crypto.aes_key.hex()[:12]}..")
            label = variant.describe()
        return wire, label, len(wire)
    return payload, variant.describe(), body_len


def _logon_response() -> tuple[bytes, str, int]:
    """Payload do Logon, re-serializado a cada request (editar o config vale na hora)."""
    global _last_body_len, _last_variant, _response_error
    try:
        payload, label, body_len = build_logon_payload()
    except (XlsEncoderError, CryptoError, ValueError, KeyError, OSError) as exc:
        message = f"{type(exc).__name__}: {exc}"
        with _lock:
            already = _response_error == message
            _response_error = message
        if not already:
            print(f"[mock] ERRO ao serializar/cifrar config.json: {message}", file=sys.stderr)
        frame = build_frame(b"", EncodeOptions().validated())
        return frame, "encoder-error", len(frame)
    with _lock:
        _last_body_len = body_len
        _last_variant = label
        _response_error = None
    return payload, label, body_len


def _echo_response(config: dict, variant) -> tuple[bytes, str]:
    """Resposta default (frame 13 B vazio), cifrada na rota da variante ativa.

    O DEC do cliente decifra incondicionalmente (R7.2), logo depois de um Logon aceito
    os outros metodos precisam do mesmo envelope — senao o cliente tenta decifrar 13 B
    de plaintext e falha (0x80500060 / 0x80500063). Rota A = IV||ct||RSA256 (288 B);
    rota B = OAEP||ct||SIG (528 B).
    """
    frame = build_frame(b"", EncodeOptions().validated())
    if variant.encrypted:
        crypto, cfg = _crypto_session(config, create=False)
        if crypto is not None and cfg is not None and cfg.encrypt_echo:
            route_b = variant.route.upper() == "B"
            try:
                wire = crypto.wrap_route_b(frame) if route_b else crypto.wrap(frame)
            except CryptoError as exc:
                print(f"[mock] echo cifrado falhou ({exc}) - enviando plaintext",
                      file=sys.stderr)
            else:
                return wire, f"echo-enc route={'B' if route_b else 'A'} ({len(wire)}B)"
    return frame, "echo"


def _save_logon_evidence(body: bytes, crypto) -> None:
    """Salva o request bruto + o unwrap RSA do tail (independente do AES)."""
    try:
        outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "unwrap")
        os.makedirs(outdir, exist_ok=True)
        seq = len([f for f in os.listdir(outdir) if f.endswith(".bin")]) + 1
        tail = body[-xls_crypto.RSA_BLOCK:]
        with open(os.path.join(outdir, f"logon_{seq}.bin"), "wb") as f:
            f.write(body)
        try:
            plain64 = oaep_decrypt_with_private(crypto.material, tail)
        except CryptoError as exc:
            plain64 = b""
        with open(os.path.join(outdir, f"logon_{seq}.unwrap.bin"), "wb") as f:
            f.write(plain64)
        meta = {"bodyLen": len(body), "unwrapOk": bool(plain64)}
        if plain64:
            meta["iv0"] = plain64[:16].hex()
            meta["km32"] = plain64[16:48].hex()
        with open(os.path.join(outdir, f"logon_{seq}.meta.json"), "w") as f:
            json.dump(meta, f, indent=1)
        print(f"[mock] evidencia Logon salva: unwrap/logon_{seq}.* "
              f"(unwrapOk={meta['unwrapOk']})")
    except Exception as exc:  # nunca quebrar o servidor por causa do log
        print(f"[mock] _save_logon_evidence falhou: {exc}")


def _try_decrypt_request(body: bytes, variant, label: str) -> dict | None:
    """Best-effort: decifra o request com a chave de sessao (sinal de ACEITE).

    Se o cliente desembrulhou a resposta, ele adotou K/IV do mock (session+0x208/+0x238)
    e passou a cifrar os requests seguintes com essa chave — decifrar aqui prova o
    rollover (ENVELOPE-SPEC R6, efeito colateral).
    """
    if not variant.encrypted or len(body) < xls_crypto.MIN_DECRYPT_BODY:
        return None
    crypto, _cfg = _crypto_session(_effective_config(), create=False)
    if crypto is None:  # nenhum Logon cifrado respondido ainda
        return None
    _save_logon_evidence(body, crypto)
    # assinatura do request (E3): sig no tail sobre body[:-256] — nao precisa de K
    sig_ok = crypto.verify_message_signature(body)
    try:
        plain, how = crypto.unwrap_request(body)
    except CryptoError as exc:
        return {"ok": False, "sigOk": sig_ok, "error": str(exc),
                "note": ("esperado no 1o Logon: a chave de sessao do cliente ainda nao "
                         "existe (ela viaja embrulhada com a publica do servidor)"
                         if crypto.responses <= 1 else
                         "chave/mask divergentes: ver crypto.mask e FUN_141c552f0")}
    frame = plain[:13]
    info = {
        "ok": True,
        "sigOk": sig_ok,
        "how": how,
        "plainLen": len(plain),
        "frameHex": frame.hex(),
        "frameStatus": int.from_bytes(frame[1:5], "big") if len(frame) >= 5 else None,
        "frameLength": int.from_bytes(frame[9:13], "big") if len(frame) >= 13 else None,
        "bodyHeadHex": plain[13:45].hex(),
    }
    print(f"[mock] request DECIFRADO {label} ({how}) frame={info['frameHex']} "
          f"plain={len(plain)}B")
    return info


class MockLspHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        global _logon_count, _first_other_method
        global _last_real_logon_ts, _cycle_index, _cycling_enabled, _pending_http_status

        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        method = self.headers.get("X-Method", "(none)")
        cls = self.headers.get("X-ClassName", "?")
        ts = time.time()
        req_headers = {key: value for key, value in self.headers.items()}

        extra_headers: dict[str, str] = {}
        config = _effective_config()
        variant = resolve_variant(config)
        decrypted = None
        if method == "Logon":
            if len(body) < 400:
                # smoke/test request: echo sem consumir o ciclo do jogo
                with _lock:
                    _method_counts["Logon-smoke"] += 1
                    seq = _method_counts["Logon-smoke"]
                resp = build_frame(b"", EncodeOptions().validated())
                label = "smoke-echo"
                note = "smoke (nao consome ciclo)"
            else:
                with _lock:
                    now = time.time()
                    if now - _last_real_logon_ts > 60:
                        _cycle_index = 0
                        _logon_count = 0
                        _cycling_enabled = True
                        _pending_http_status = 200
                        print("[mock] novo boot detectado (gap >60s) - ciclo resetado")
                    _last_real_logon_ts = now
                    _logon_count += 1
                    seq = _logon_count
                resp, label, body_len = _logon_response()
                if "X-Encryption:false" in label:
                    extra_headers["X-Encryption"] = "false"
                note = f"{label} bodyLen={body_len} totalLen={len(resp)}"
                decrypted = _try_decrypt_request(body, variant, label)
        else:
            with _lock:
                _method_counts[method] += 1
                seq = _method_counts[method]
                if method != "(none)" and _first_other_method is None:
                    _first_other_method = method
            resp, note = _echo_response(config, variant)
            label = "-"
            decrypted = _try_decrypt_request(body, variant, "")

        entry = {
            "ts": ts,
            "method": method,
            "class": cls,
            "path": self.path,
            "bodyLen": len(body),
            "nonceHex": body[:12].hex() if len(body) >= 12 else body.hex(),
            "responseLen": len(resp),
            "seq": seq,
            "note": note,
            "variant": label if method == "Logon" else "-",
            "headers": req_headers,
        }
        if decrypted is not None:
            entry["decrypted"] = decrypted
        with _lock:
            with open(_log_path, "ab") as handle:
                handle.write((json.dumps(entry) + "\n").encode())

        self.send_response(_pending_http_status)
        self.send_header("Content-Type", "bin/xtsw")
        self.send_header("Content-Length", str(len(resp)))
        self.send_header("Connection", "keep-alive")
        for name, value in extra_headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(resp)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass  # log silencioso; capture_log.jsonl guarda tudo estruturado


def _summary() -> None:
    print("\nSessao encerrada - resumo:")
    print(f"  Logon: {_logon_count}x  variante={_last_variant or '-'}  "
          f"bodyNoFio={_last_body_len}B")
    for method, count in _method_counts.most_common():
        print(f"  {method}: {count}")
    if _crypto is not None:
        print(f"  crypto: respostas cifradas={_crypto.responses} "
              f"assinadas={_crypto.signatures} "
              f"requests decifrados={_crypto.requests_ok} falhas={_crypto.requests_fail} "
              f"sig-verified={_crypto.requests_sig_ok}")
    if _response_error:
        print(f"  ENCODER/CRYPTO ERROR: {_response_error}")
    if _first_other_method is not None and _logon_count <= 1:
        print("  LEITURA: Logon ACEITO - cliente seguiu para outros metodos.")
        if _crypto is not None and _crypto.requests_ok:
            print("           requests seguintes DECIFRADOS => chave de sessao rotacionou.")
    elif _logon_count > 1:
        print("  LEITURA: cliente reenviou Logon => RECUSA (cripto/schema).")
        print("           se as requests seguintes nao decifram: mask != 0 ou preStep.")
    else:
        print("  LEITURA: apenas Logon, sem outros metodos - inconclusivo.")


def _probe(config: dict) -> tuple[int, str, int, bool]:
    """Valida o encoder e o envelope cifrado antes de abrir o socket.

    Devolve (tamanho_no_fio, label, len(corpo_no_fio), cifrado?).
    """
    variant = resolve_variant(config)
    opts = options_for(config)
    payload = encode_config(config)  # plaintext: frame 13 B + corpo
    size = opts.frame_size
    body_len = len(payload) - size
    if size == FRAME_SIZE:
        frame, _ = decode_frame(payload)
        if frame["length"] != body_len:
            raise XlsEncoderError(f"frame.length={frame['length']} != corpo {body_len}")
        if len(payload) != FRAME_SIZE + body_len:
            raise XlsEncoderError("payload != 13 + corpo")
    if not variant.encrypted:
        return len(payload), variant.describe(), body_len, False

    crypto, cfg = _crypto_session(config)
    if crypto is None or cfg is None:
        raise CryptoError("sessao cripto nao inicializada")
    expected_ct = len(payload) + (16 - len(payload) % 16 or 16)

    if variant.route.upper() == "B":
        wire = crypto.wrap_route_b(payload)
        oaep_len = sig_len = xls_crypto.RSA_BLOCK
        ct_len = len(wire) - oaep_len - sig_len
        if ct_len != expected_ct:
            raise CryptoError(f"rota B: ct {ct_len}B != PKCS#7({len(payload)}B)="
                              f"{expected_ct}B")
        if ct_len % 16:
            raise CryptoError(f"rota B: ct {ct_len}B nao e' multiplo de 16")
        if len(wire) != oaep_len + ct_len + sig_len:
            raise CryptoError("rota B: body != OAEP + ct + SIG256")
        if len(wire) < 0x200:
            raise CryptoError(f"rota B: body {len(wire)}B < minimo 0x200")
        if not xls_crypto.rsa_verify_pkcs1v15_sha256(crypto.material, wire[-sig_len:],
                                                     wire[:-sig_len]):
            raise CryptoError("rota B: a propria assinatura nao verifica com a publica "
                              "(PEM/keys invalidos)")
        print(f"[mock] rota B: oaepLen={oaep_len} ctLen={ct_len} sigLen={sig_len} "
              f"bodyLen={len(wire)} sig=ok(publica do cliente)")
        return len(wire), variant.describe(), len(wire), True

    wire = crypto.wrap(payload)
    ct_len = len(wire) - xls_crypto.IV_SIZE - xls_crypto.RSA_BLOCK
    if ct_len != expected_ct:
        raise CryptoError(f"ct {ct_len}B != PKCS#7({len(payload)}B)={expected_ct}B")
    if ct_len % 16:
        raise CryptoError(f"ct {ct_len}B nao e' multiplo de 16")
    if len(wire) < xls_crypto.MIN_DECRYPT_BODY:
        raise CryptoError(f"body cifrado {len(wire)}B < minimo {xls_crypto.MIN_DECRYPT_BODY}B")
    if len(wire) != xls_crypto.IV_SIZE + ct_len + xls_crypto.RSA_BLOCK:
        raise CryptoError("body != IV + ct + RSA256")
    return len(wire), variant.describe(), len(wire), True


def main() -> int:
    global _config_path, _log_path, _variant_override

    ap = argparse.ArgumentParser(
        description="FM8 mock LSP v3 (Logon_Results cifrado: IV||AES-256-CBC||RSA-OAEP)")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--log", default=None)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--tls", nargs=2, metavar=("CERT", "KEY"), default=None,
                    help="HTTPS (reuse E:\\Projetos\\fm8-lsp-server\\certs\\)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--variant", default=None,
                    help="forca variants.active (1..9; 8 = rota A, 9 = rota B cifradas) "
                         "sem editar o config")
    args = ap.parse_args()

    _config_path = os.path.abspath(args.config)
    _variant_override = args.variant
    config = load_config(_config_path)
    if _variant_override:
        config.setdefault("variants", {})["active"] = _variant_override
    server_cfg = config.get("server", {}) or {}
    _log_path = os.path.abspath(args.log or server_cfg.get("log") or DEFAULT_LOG)

    port = args.port if args.port is not None else int(server_cfg.get("port", 443))
    tls = args.tls
    if tls is None and server_cfg.get("cert") and server_cfg.get("key"):
        if os.path.exists(server_cfg["cert"]) and os.path.exists(server_cfg["key"]):
            tls = (server_cfg["cert"], server_cfg["key"])
        else:
            print("[mock] certs do config nao existem - use --tls CERT KEY", file=sys.stderr)

    try:
        total, label, body_len, encrypted = _probe(config)
    except (XlsEncoderError, CryptoError, ValueError, KeyError) as exc:
        print(f"[mock] config invalida, nao vou subir: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 2

    print(f"[mock] {label}")
    if encrypted:
        if resolve_variant(config).route.upper() == "B":
            ct_len = body_len - 2 * xls_crypto.RSA_BLOCK
            print(f"[mock] payload Logon CIFRADO rota B = {body_len}B "
                  f"(OAEP {xls_crypto.RSA_BLOCK} + ct {ct_len} + SIG "
                  f"{xls_crypto.RSA_BLOCK})")
        else:
            ct_len = body_len - xls_crypto.IV_SIZE - xls_crypto.RSA_BLOCK
            print(f"[mock] payload Logon CIFRADO = {body_len}B "
                  f"(IV {xls_crypto.IV_SIZE} + ct {ct_len} + RSA {xls_crypto.RSA_BLOCK})")
        print("[mock] plaintext = frame13 + corpo; Content-Length = "
              f"{body_len} (frame NAO vai em claro)")
    else:
        print(f"[mock] payload Logon = {total}B "
              f"(frame {total - body_len} + corpo {body_len})")
    if body_len:
        print(f"[mock] parametros logon: frame13={FRAME_SIZE} negControl={FRAME_SIZE_CONTROL}")

    httpd = ThreadingHTTPServer((args.host, port), MockLspHandler)
    httpd.daemon_threads = True
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls[0], tls[1])
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"[mock] FM8 mock LSP v3 em {args.host}:{port} tls={bool(tls)}")
    print(f"[mock] config: {_config_path}")
    print(f"[mock] log:    {_log_path}")
    if tls:
        try:
            control = ThreadingHTTPServer((args.host, 5080), ControlHandler)
            control.daemon_threads = True
            threading.Thread(target=control.serve_forever, daemon=True).start()
            print(f"[mock] controle ao vivo: http://{args.host}:5080/preset/N | /auto | /status")
        except OSError as exc:
            print(f"[mock] controle 5080 indisponivel ({exc}) - segue sem controle", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[mock] Ctrl+C")
    finally:
        httpd.server_close()
        _summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
