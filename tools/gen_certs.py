#!/usr/bin/env python3
"""Gera CA local + cert TLS para gameservices.fm.forzamotorsport.net (rota A).

Saida em certs/:
  ca.pem    — CA raiz autoassinada (importar no trust store do Windows)
  cert.pem  — leaf p/ gameservices.fm.forzamotorsport.net (server.py --tls)
  key.pem   — chave privada do leaf
Sem admin: geracao pura em arquivos; confianca instalada depois (setup_ca.ps1).
"""
import datetime as dt
import os
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HOST = "gameservices.fm.forzamotorsport.net"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
os.makedirs(OUT, exist_ok=True)

now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=dt.timezone.utc)

# --- CA raiz ----------------------------------------------------------------
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "FM8 Local LSP CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FM8 LSP Lab"),
])
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - dt.timedelta(minutes=5))
    .not_valid_after(now + dt.timedelta(days=365 * 10))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=None, decipher_only=None,
        ),
        critical=True,
    )
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
    .sign(ca_key, hashes.SHA256())
)

# --- Leaf -------------------------------------------------------------------
leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
leaf_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, HOST),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FM8 LSP Lab"),
    ]))
    .issuer_name(ca_cert.subject)
    .public_key(leaf_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - dt.timedelta(minutes=5))
    .not_valid_after(now + dt.timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=None, decipher_only=None,
        ),
        critical=True,
    )
    .add_extension(
        x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False,
    )
    .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False,
    )
    .sign(ca_key, hashes.SHA256())
)

def pem_ir(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

for fname, data in (
    ("ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM)),
    ("cert.pem", leaf_cert.public_bytes(serialization.Encoding.PEM)),
    ("key.pem", pem_ir(leaf_key)),
):
    path = os.path.join(OUT, fname)
    with open(path, "wb") as f:
        f.write(data)
    print(f"wrote {path}")

# Sanity: chain valida a nivel de objeto
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_verify_locations(os.path.join(OUT, "ca.pem"))
print("chain loads into SSLContext: OK")
