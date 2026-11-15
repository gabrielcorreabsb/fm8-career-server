#!/usr/bin/env python3
"""FM8 runtime memory dumper (read-only, no debugger attach).

Modos:
  dump-text <pid|auto>  -> salva todo o image .text do modulo em dump_text.bin
  scan-keys <pid|auto>  -> varre regioes RW committed procurando instancias do
                           engine AES (padrao: 32B key em p, e bytes p+0x20..+0x30
                           == p..+0x10 porque round key 0 do schedule == key),
                           imprime candidatos (offset, key hex, iv hex @+0xf0)
                           e salva em key_candidates.json
  dump-extents <pid|auto> -> salva os extents dos stages opacos (decifrados em
                           memoria) em dump_extents.bin com mapa JSON

Sem admin; processo do mesmo usuario. Uso: python dumper.py <modo> [pid]
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import sys

psapi = ctypes.WinDLL("psapi")
k32 = ctypes.WinDLL("kernel32")

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

# preferred base do exe (ASLR -> reloc)
PREFERRED_BASE = 0x140000000
IMAGE_LOW = 0x140001000
IMAGE_HIGH = 0x145c00000  # fim aproximado do .data (secoes conhecidas)

OPAQUE_EXTENTS = [
    (0x141c4a2a0, 0x81), (0x141c4ae40, 0x162), (0x141c4afb0, 0x19e),
    (0x141c09520, 0x12f), (0x141c16f90, 0xa0),
    (0x141c2f000, 0x6000),  # familia walker encode/decode + sub-walkers
    (0x141c38000, 0x1000),  # margem
    # rodada 2 (pos-Logon): cadeia de cifra real do provider da sessao
    (0x141c54260, 0x600), (0x141c535d0, 0x400), (0x141c552f0, 0x400),
    (0x141ada800, 0x800),
]

MEM_COMMIT = 0x1000
PAGE_READABLE = {0x02, 0x04, 0x06, 0x20, 0x40}


def open_process(pid):
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        raise OSError("OpenProcess falhou pid=%d err=%d" % (pid, k32.GetLastError()))
    return h


def find_pid():
    import subprocess
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-Process | Where-Object { $_.Path -like '*forza*' -or $_.ProcessName -like '*forza*' } | Select-Object -First 1 -ExpandProperty Id"],
        capture_output=True, text=True).stdout.strip()
    return int(out) if out.isdigit() else None


def module_base(h):
    LIST_MODULES_ALL = 0x03
    need = wt.DWORD()
    psapi.EnumProcessModulesEx(h, None, 0, ctypes.byref(need), LIST_MODULES_ALL)
    buf = (wt.HMODULE * (need.value))()
    psapi.EnumProcessModulesEx(h, buf, ctypes.sizeof(buf), ctypes.byref(need), LIST_MODULES_ALL)
    for i in range(need.value):
        name = ctypes.create_unicode_buffer(512)
        psapi.GetModuleFileNameExW(h, ctypes.c_void_p(int(buf[i])), name, 512)
        if "forza" in name.value.lower() and name.value.lower().endswith(".exe"):
            return ctypes.cast(buf[i], ctypes.c_void_p).value
    raise RuntimeError("modulo forza nao encontrado")


def read_mem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
    return (buf.raw if ok else None), got.value


def dump_text(h, base, outdir):
    delta = base - PREFERRED_BASE
    lo = IMAGE_LOW + delta
    hi = IMAGE_HIGH + delta
    path = os.path.join(outdir, "dump_text.bin")
    total = 0
    with open(path, "wb") as f:
        chunk = 0x100000
        addr = lo
        while addr < hi:
            data, got = read_mem(h, addr, min(chunk, hi - addr))
            if data:
                f.write(data)
                total += got
            else:
                f.write(b"\x00" * min(chunk, hi - addr))
            addr += chunk
    print("dump_text.bin: %d bytes (base=0x%x delta=0x%x)" % (total, base, delta))


def dump_extents(h, base, outdir):
    delta = base - PREFERRED_BASE
    out = {}
    with open(os.path.join(outdir, "dump_extents.bin"), "wb") as f:
        off = 0
        for rva, size in OPAQUE_EXTENTS:
            data, got = read_mem(h, rva + delta, size)
            data = data or b"\x00" * size
            out["0x%x" % rva] = {"file_offset": off, "size": size, "read": got}
            f.write(data)
            off += size
    with open(os.path.join(outdir, "dump_extents.json"), "w") as f:
        json.dump({"base": base, "delta": delta, "extents": out}, f, indent=1)
    print("dump_extents.bin: %d bytes" % off)


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


def uniq(a):
    return len(set(a))


# Standard AES S-box (Rijndael). Used to verify the full 240B key schedule.
SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16])


def aes256_round_keys(key32):
    """Return the 240 bytes of AES-256 round keys (15 RKs x 16B)."""
    W = [list(key32[4*i:4*i+4]) for i in range(8)]
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]
    ri = 0
    for i in range(8, 60):
        t = list(W[i-1])
        if i % 8 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[ri]
            ri += 1
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        W.append([W[i-8][j] ^ t[j] for j in range(4)])
    return b''.join(bytes(W[4*i+j]) for i in range(15) for j in range(4))


def scan_keys(h, outdir):
    cand = []
    addr = 0x10000
    mbi = MBI()
    scanned = 0
    regions = 0
    # engine pattern (AES-256 schedule): RK0=key[0:16] at +0x20, RK1=key[16:32] at +0x30
    # => bytes[p]==bytes[p+0x20] AND bytes[p+0x10]==bytes[p+0x30]; high entropy key
    while addr < 0x7FFFFFFEFFFF:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        size = mbi.RegionSize
        if (mbi.State == MEM_COMMIT and mbi.Protect in PAGE_READABLE
                and size <= 0x8000000 and mbi.Type == 0x20000):
            data, got = read_mem(h, mbi.BaseAddress, size)
            if data:
                scanned += got
                regions += 1
                print("region 0x%x size=0x%x (%d done)" % (mbi.BaseAddress, size, regions), flush=True)
                for i in range(0, len(data) - 0x120, 8):
                    if (data[i:i+16] == data[i+0x20:i+0x30]
                            and data[i+0x10:i+0x20] == data[i+0x30:i+0x40]
                            and uniq(data[i:i+32]) >= 20):
                        rk = aes256_round_keys(data[i:i+32])
                        if rk == data[i+0x20:i+0x20+240]:
                            cand.append({"region_base": hex(mbi.BaseAddress),
                                         "offset": hex(mbi.BaseAddress + i),
                                         "key": data[i:i+32].hex(),
                                         "iv": data[i+0x110:i+0x120].hex()})
                        if len(cand) >= 200:
                            break
        if len(cand) >= 200:
            break
        addr = mbi.BaseAddress + size
        if addr <= mbi.BaseAddress:
            break
    with open(os.path.join(outdir, "key_candidates.json"), "w") as f:
        json.dump({"scanned_bytes": scanned, "candidates": cand}, f, indent=1)
    print("scan: %d bytes in %d regions, %d candidatos" % (scanned, regions, len(cand)))
    for c in cand[:10]:
        print(" key@%s: %s iv=%s" % (c["offset"], c["key"][:32] + "...", c["iv"]))


def poll_extents(h, base, outdir, max_hits=8):
    """Loop continuo: le os 4 extents e salva snapshot quando diferem do arquivo
    (decifrados ou re-chaveados). Rodar enquanto o jogo processa respostas."""
    delta = base - PREFERRED_BASE
    targets = [(0x141c54260, 0x600), (0x141c535d0, 0x400),
               (0x141c552f0, 0x400), (0x141ada800, 0x800),
               (0x141c4ae40, 0x162), (0x141c4afb0, 0x19e),
               (0x141c4a2a0, 0x81), (0x141c09520, 0x12f),
               (0x141c16f90, 0xa0)]
    with open(os.path.join(outdir, "dump_text.bin"), "rb") as f:
        text = f.read()
    def base_bytes(va, size):
        off = va - PREFERRED_BASE - 0x1000
        return text[off:off + size] if off >= 0 and off + size <= len(text) else None
    baselines = {va: base_bytes(va, sz) for va, sz in targets}
    hits = 0
    seen = set()
    print("poll-extents: lendo %d unidades a cada 10ms (Ctrl+C para parar)" % len(targets))
    try:
        while hits < max_hits:
            time.sleep(0.01)
            for va, sz in targets:
                data, got = read_mem(h, va + delta, sz)
                if not data or not baselines[va] or data == baselines[va]:
                    continue
                # heuristica de codigo decifrado: prologo x64 comum
                prologue = data[:4] in (b"\x48\x89\x5c\x24", b"\x40\x53",
                                        b"\x48\x83\xec", b"\x40\x55")
                tag = (va, data[:16])
                if tag in seen:
                    continue
                seen.add(tag)
                hits += 1
                name = "hot_0x%x_%d.bin" % (va, hits)
                with open(os.path.join(outdir, name), "wb") as f:
                    f.write(data)
                print("HIT %d: 0x%x size=0x%x prologo=%s -> %s"
                      % (hits, va, sz, prologue, name))
                if prologue:
                    with open(os.path.join(outdir, "hot_hits.json"), "a") as f:
                        f.write(json.dumps({"va": hex(va), "size": sz,
                                            "prologue": True, "file": name,
                                            "ts": time.time()}) + "\n")
    except KeyboardInterrupt:
        pass
    print("fim: %d snapshots" % hits)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    mode = sys.argv[1]
    pid = int(sys.argv[2]) if len(sys.argv) > 2 else find_pid()
    if not pid:
        print("jogo nao encontrado (procure 'forza' nos processos)")
        return 1
    outdir = os.path.dirname(os.path.abspath(__file__))
    h = open_process(pid)
    try:
        if mode == "dump-text":
            dump_text(h, module_base(h), outdir)
        elif mode == "scan-keys":
            scan_keys(h, outdir)
        elif mode == "hunt-key":
            _dispatch_hunt(mode, pid, outdir)
        elif mode == "dump-extents":
            dump_extents(h, module_base(h), outdir)
        else:
            print("modo desconhecido: %s" % mode)
            return 2
    finally:
        k32.CloseHandle(h)
    return 0

def _latest_evidence(outdir):
    import glob
    ups = sorted(glob.glob(os.path.join(outdir, "unwrap", "logon_*.meta.json")),
                 key=lambda p: int(p.rsplit("_", 1)[1].split(".")[0]) if p.rsplit("_", 1)[1].split(".")[0].isdigit() else 0)
    for p in reversed(ups):
        with open(p) as f:
            meta = json.load(f)
        if not meta.get("unwrapOk"):
            continue
        base = p[:-10]  # strip .meta.json
        binp = base + ".bin"
        with open(binp, "rb") as f:
            body = f.read()
        iv0 = bytes.fromhex(meta["iv0"]) if isinstance(meta["iv0"], str) else meta["iv0"]
        ct = body[32:-256]
        return {"iv0": iv0, "ct": ct, "km": bytes.fromhex(meta["km32"]), "meta": meta, "path": binp}
    return None


def _aes_decrypt_block(ks_rks, iv, block):
    # rks: list of 15 keys of 16B (round 0..14) computed by caller? we need decrypt: reverse
    # minimal pure-python AES-256 decrypt using precomputed round keys (forward list)
    from dumper_aes import aes256_decrypt_block  # optional module
    return aes256_decrypt_block(ks_rks, iv, block)


def hunt_key(h, outdir):
    import subprocess
    ev = _latest_evidence(outdir)
    iv0 = ev["iv0"] if ev else b""
    print("evidence: %s iv0=%s" % (bool(ev), (ev["iv0"].hex() if ev else "-")))
    cands = []
    # pattern A: KDBM blob
    # pattern B: schedule XOR relation W8=W7^W0, W9=W8^W1 at p (8-aligned)
    addr = 0x10000
    mbi = MBI()
    scanned = 0
    import numpy as np
    while addr < 0x7FFFFFFEFFFF:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        size = mbi.RegionSize
        if mbi.State == MEM_COMMIT and mbi.Protect in PAGE_READABLE and size <= 0x8000000:
            data, got = read_mem(h, mbi.BaseAddress, size)
            if data and got > 0x100:
                scanned += got
                b = np.frombuffer(data[:got], dtype=np.uint32)
                # A: KDBM
                idx = 0
                magic = b"KDBM"
                while True:
                    i = data.find(magic, idx)
                    if i < 0 or i + 44 > got:
                        break
                    if struct.unpack_from("<I", data, i + 4)[0] == 1 and \
                       struct.unpack_from("<I", data, i + 8)[0] == 32:
                        cands.append({"how": "KDBM", "offset": hex(mbi.BaseAddress + i),
                                      "key": data[i+12:i+44].hex(),
                                      "iv": data[i+44:i+60].hex()})
                    idx = i + 4
                    if len(cands) >= 32:
                        break
                if len(cands) >= 32:
                    break
                # B: schedule relations, 8-aligned -> dword step 2
                if got >= 0x60:
                    n = (got - 0x40) // 4
                    U = b[: n * 4]
                    A = U[:-12]; B7 = U[7:-5]; C8 = U[8:-4]; W1 = U[1:-11]; D9 = U[9:-3]
                    c1 = (C8 == (B7 ^ A))
                    c2 = (D9 == (C8 ^ W1))
                    hits = np.nonzero(c1 & c2)[0]
                    for i in hits[:8]:
                        p = int(i) * 4
                        cands.append({"how": "sched-relu", "offset": hex(mbi.BaseAddress + p),
                                      "key": data[p:p+32].hex(),
                                      "iv": data[p+0x110:p+0x120].hex()})
                    if len(hits) > 8:
                        print("regiao %s: %d hits sched (mostrando 8)" % (hex(mbi.BaseAddress), len(hits)))
        if len(cands) >= 32:
            break
        nxt = mbi.BaseAddress + size
        if nxt <= mbi.BaseAddress:
            break
        addr = nxt
    with open(os.path.join(outdir, "hunt_candidates.json"), "w") as f:
        json.dump({"scanned_bytes": scanned, "candidates": cands}, f, indent=1)
    print("hunt: %d bytes, %d candidatos" % (scanned, len(cands)))
    for c in cands[:16]:
        print(" %s key@%s %s..." % (c["how"], c["offset"], c["key"][:16]))


def _dispatch_hunt(mode, pid, outdir):
    h = open_process(pid)
    try:
        hunt_key(h, outdir)
    finally:
        k32.CloseHandle(h)


if __name__ == "__main__":
    sys.exit(main())
