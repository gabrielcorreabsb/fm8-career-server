#!/usr/bin/env python3
"""FM8 local LSP/Xls CAPTURE server — record full request bodies, no forwarding.

Derived from fm8-lsp-server/server.py (09/11 harness). Differences:
- saves every request body to capture/<method>_<ts>.bin (full bytes)
- saves request headers per request to capture/<method>_<ts>.headers.txt
- jsonl entry references the saved file instead of only the 12B prefix
- response is the same accept-and-echo 12B success frame (client rejects Logon
  without Results; that is expected — we only need the request bytes)

Uso:
  python capture_server.py --tls <path-to-certs>\cert.pem <path-to-certs>\key.pem --port 443

Aviso: ambiente de teste local; o servico real nunca e' contatado por este server.
"""
import argparse
import json
import os
import ssl
import struct
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
CAPTURE_DIR = os.path.join(BASE, "capture")
LOG_PATH = os.path.join(BASE, "capture_log.jsonl")
os.makedirs(CAPTURE_DIR, exist_ok=True)
_lock = threading.Lock()
_counts = Counter()


def build_response_frame(status=0, code=0, msg=b""):
    return struct.pack(">III", status, code, len(msg)) + msg


class CaptureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        method = self.headers.get("X-Method", "(none)")
        cls = self.headers.get("X-ClassName", "?")
        ua = self.headers.get("User-Agent", "?")
        contract = self.headers.get("X-ContractVersion", "?")
        ts = time.time()
        tag = f"{int(ts)}_{method.replace('/', '_')}"
        body_path = os.path.join(CAPTURE_DIR, f"{tag}.bin")
        headers_path = os.path.join(CAPTURE_DIR, f"{tag}.headers.txt")

        if method == "(none)":
            _counts["(keepalive/no-header)"] += 1
        else:
            _counts[method] += 1

        with open(body_path, "wb") as f:
            f.write(body)
        with open(headers_path, "w", encoding="utf-8") as f:
            f.write(f"path={self.path}\nmethod={method}\nclass={cls}\n"
                    f"ua={ua}\ncontract={contract}\nbodyLen={len(body)}\n\n")
            for k, v in self.headers.items():
                f.write(f"{k}: {v}\n")

        entry = {
            "ts": ts, "path": self.path, "method": method, "class": cls,
            "ua": ua, "contract": contract, "bodyLen": len(body),
            "nonceHex": body[:12].hex() if len(body) >= 12 else body.hex(),
            "bodyFile": os.path.basename(body_path),
        }
        with _lock:
            with open(LOG_PATH, "ab") as f:
                f.write((json.dumps(entry) + "\n").encode())

        resp = build_response_frame()
        self.send_response(200)
        self.send_header("Content-Type", "bin/xtsw")
        self.send_header("Content-Length", str(len(resp)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(resp)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


def main():
    ap = argparse.ArgumentParser(description="FM8 LSP/Xls full-body capture server")
    ap.add_argument("--port", type=int, default=5080)
    ap.add_argument("--tls", nargs=2, metavar=("CERT", "KEY"), default=None)
    args = ap.parse_args()

    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), CaptureHandler)
    httpd.daemon_threads = True
    if args.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls[0], args.tls[1])
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"FM8 LSP CAPTURE on 127.0.0.1:{args.port} tls={bool(args.tls)}")
    print(f"Capture dir: {CAPTURE_DIR}")
    print(f"Log: {LOG_PATH}")
    try:
        httpd.serve_forever()
    finally:
        print("\nSessao encerrada — resumo por X-Method:")
        for m, c in _counts.most_common():
            print(f"  {m}: {c}")


if __name__ == "__main__":
    main()
