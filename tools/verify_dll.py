# -*- coding: utf-8 -*-
"""
v16 EnclaveCJK.dll 静态验证：
  1) 定位 hook3 蹦床 cjk_concat_len_trampoline_impl
     特征：call dword ptr [edx+0x64]  (FF 52 64) 开头
     必须包含：lea eax,[eax+4]（不是 mov eax,[eax+4]）
               cmp eax, 0x8D000 / cmp eax, 0x8F000  调用者过滤
  2) 检查句号替换常量 0x3002 -> 0x2E
  3) 检查 hook1 第 4 个调用者 0x8DDE3
"""
import sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

PATH = r"G:\Projects\EnclaveGameExtend\EnclaveCJK\EnclaveCJK.dll"
d = open(PATH, "rb").read()
print("file size:", len(d))

# ---- PE 节表 ----
e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
assert d[e_lfanew:e_lfanew+4] == b"PE\x00\x00"
nsec = struct.unpack_from("<H", d, e_lfanew+6)[0]
optsz = struct.unpack_from("<H", d, e_lfanew+20)[0]
imgbase = struct.unpack_from("<I", d, e_lfanew+24+28)[0]
sect0 = e_lfanew + 24 + optsz
secs = []
for i in range(nsec):
    o = sect0 + i*40
    name = d[o:o+8].rstrip(b"\x00").decode()
    vsz, va, rsz, ra = struct.unpack_from("<IIII", d, o+8)
    secs.append((name, va, vsz, ra, rsz))
    print(f"  {name:8s} VA={va:#08x} VSZ={vsz:#08x} RAW={ra:#08x} RSZ={rsz:#08x}")
print("ImageBase =", hex(imgbase))

def off2rva(off):
    for name, va, vsz, ra, rsz in secs:
        if ra <= off < ra + rsz:
            return va + (off - ra)
    return None

def rva2off(rva):
    for name, va, vsz, ra, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return ra + (rva - va)
    return None

text = [s for s in secs if s[0] == ".text"][0]
tname, tva, tvsz, tra, trsz = text
tbytes = d[tra:tra+trsz]

md = Cs(CS_ARCH_X86, CS_MODE_32)

# ---------- 1) 找 hook3 蹦床 ----------
print("\n===== [1] 搜索 hook3 蹦床 (FF 52 64 = call dword ptr [edx+0x64]) =====")
found = []
pos = 0
while True:
    i = tbytes.find(b"\xFF\x52\x64", pos)
    if i < 0:
        break
    found.append(i)
    pos = i + 1
print("在 .text 中命中 %d 处" % len(found))

for i in found:
    off = tra + i
    rva = off2rva(off)
    print(f"\n--- 候选 @ file={off:#x} RVA={rva:#x} (VA={imgbase+rva:#x}) ---")
    code = d[off:off+220]
    has_lea = False
    has_mov_deref = False
    has_lo = False
    has_hi = False
    for ins in md.disasm(code, imgbase + rva):
        print(f"  {ins.address:#010x}  {ins.bytes.hex():<16s} {ins.mnemonic} {ins.op_str}")
        if ins.mnemonic == "lea" and ins.op_str.replace(" ", "") == "eax,[eax+4]":
            has_lea = True
        if ins.mnemonic == "mov" and ins.op_str.replace(" ", "") == "eax,dwordptr[eax+4]":
            has_mov_deref = True
        if ins.mnemonic == "cmp" and "0x8d000" in ins.op_str:
            has_lo = True
        if ins.mnemonic == "cmp" and "0x8f000" in ins.op_str:
            has_hi = True
    print(f"  >>> lea eax,[eax+4] = {has_lea} | mov eax,[eax+4](崩溃写法) = {has_mov_deref}"
          f" | cmp 0x8D000 = {has_lo} | cmp 0x8F000 = {has_hi}")

# ---------- 2) 常量检查 ----------
print("\n===== [2] 常量检查 =====")
checks = {
    "cmp ..,0x3002 (句号判定)": b"\x02\x30\x00\x00",
    "0x2E 半角句点":            b"\x2e\x00\x00\x00",
    "hook1 第4调用者 0x8DDE3":  b"\xe3\xdd\x08\x00",
    "hook3 返回 0x8ED1F":       b"\x1f\xed\x08\x00",
    "hook3 安装点 0x8ED1A":     b"\x1a\xed\x08\x00",
    "SUB_LO 0x8D000":           b"\x00\xd0\x08\x00",
    "SUB_HI 0x8F000":           b"\x00\xf0\x08\x00",
}
for k, v in checks.items():
    idxs = []
    p = 0
    while True:
        j = d.find(v, p)
        if j < 0: break
        r = off2rva(j)
        idxs.append(f"{j:#x}(RVA {r:#x})" if r else f"{j:#x}(非映射)")
        p = j + 1
        if len(idxs) >= 6: break
    print(f"  {'OK ' if idxs else 'MISS'} {k:26s} -> {', '.join(idxs) if idxs else '未找到'}")

# ---------- 3) 版本串 ----------
print("\n===== [3] 版本/日志字符串 =====")
for kw in [b"EnclaveCJK v", b"[CJK]"]:
    p = 0
    n = 0
    while n < 8:
        j = d.find(kw, p)
        if j < 0: break
        end = d.find(b"\x00", j)
        try:
            s = d[j:end].decode("gbk", "replace")
        except Exception:
            s = repr(d[j:end])
        print(f"  {j:#x}: {s[:150]}")
        p = j + 1
        n += 1
