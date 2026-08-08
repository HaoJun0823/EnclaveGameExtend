# -*- coding: utf-8 -*-
"""核对 GameWorld.dll 三个 hook 点的原始指令边界是否与蹦床重放/覆盖长度精确一致。"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

PATH = r"I:\SteamLibrary\steamapps\common\Enclave\Sbz1\GameWorld.dll"
d = open(PATH, "rb").read()
e = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, e+6)[0]
optsz = struct.unpack_from("<H", d, e+20)[0]
imgbase = struct.unpack_from("<I", d, e+24+28)[0]
secs = []
for i in range(nsec):
    o = e + 24 + optsz + i*40
    name = d[o:o+8].rstrip(b"\x00").decode()
    vsz, va, rsz, ra = struct.unpack_from("<IIII", d, o+8)
    secs.append((name, va, vsz, ra, rsz))

def rva2off(rva):
    for name, va, vsz, ra, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return ra + (rva - va)
    return None

md = Cs(CS_ARCH_X86, CS_MODE_32)

sites = [
    ("hook[0] Localize_Str 调用点", 0x20FB2, 5, 0x20FB7),
    ("hook[1] TFStr 宽构造",        0x54F00, 7, None),
    ("hook[3] 拼接长度修正",        0x8ED1A, 5, 0x8ED1F),
]

for label, rva, patchlen, retrva in sites:
    off = rva2off(rva)
    code = d[off:off+24]
    print(f"\n=== {label}  RVA={rva:#x}  拟覆盖 {patchlen} 字节 ===")
    print("   原始字节:", code[:patchlen].hex(" "))
    total = 0
    ok_boundary = False
    for ins in md.disasm(code, imgbase + rva):
        mark = ""
        total += ins.size
        if total == patchlen:
            mark = "   <<< 覆盖边界正好落在指令边界 ✓"
            ok_boundary = True
        print(f"   {ins.address:#010x} +{total - ins.size:<2d} {ins.bytes.hex():<14s} {ins.mnemonic} {ins.op_str}{mark}")
        if total >= patchlen + 6:
            break
    if not ok_boundary:
        print("   !!! 警告：覆盖长度未落在指令边界，会把半条指令打碎 → 必崩")
    if retrva:
        print(f"   返回目标 RVA={retrva:#x} = {rva:#x}+{patchlen} -> {'一致 ✓' if retrva == rva + patchlen else '不一致 ✗'}")

# hook1 四个调用者核对：call 0x54F00 的调用点 → 返回地址
print("\n=== hook[1] 调用者核对（.text 中所有 call 0x54F00）===")
text = [s for s in secs if s[0] == ".text"][0]
_, tva, tvsz, tra, trsz = text
tb = d[tra:tra+trsz]
target = 0x54F00
hits = []
for i in range(len(tb) - 5):
    if tb[i] == 0xE8:
        rel = struct.unpack_from("<i", tb, i+1)[0]
        site = tva + i
        if site + 5 + rel == target:
            hits.append((site, site + 5))
print(f"   共 {len(hits)} 个调用点")
WHITELIST = {0x8DD09, 0x8DD31, 0x8E362, 0x8DDE3}
for site, ret in hits:
    insub = 0x8D000 <= ret < 0x8F000
    inwl = ret in WHITELIST
    flag = "白名单✓" if inwl else ("★字幕区但不在白名单!" if insub else "非字幕区")
    print(f"   call@{site:#x} -> 返回 {ret:#x}   {flag}")
