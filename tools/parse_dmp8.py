#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stack walk from ESP of exception thread in minidump."""
import sys, struct
from minidump.minidumpfile import MinidumpFile

dmp_path = sys.argv[1]
mf = MinidumpFile.parse(dmp_path)

mods = {}
for m in mf.modules.modules:
    try:
        name = m.name or ''
        base = m.baseaddress
        size = m.size
    except Exception:
        base, size, name = 0, 0, '?'
    mods[base] = (name, size)

def addr_mod(a):
    for base, (name, size) in sorted(mods.items()):
        if base <= a < base + size:
            return name, a - base
    return None, a

# memory segments
segs = []
try:
    for seg in mf.memory_segments.memory_segments:
        segs.append(seg)
except Exception:
    pass

def rd(va, n):
    for seg in segs:
        if seg.inrange(va):
            try:
                return seg.read(va, n, open(dmp_path, 'rb'))
            except Exception:
                pass
    return None

# context from file
rec0 = mf.exception.exception_records[0]
ctx_rva = rec0.ThreadContext.Rva
ctx_size = rec0.ThreadContext.DataSize
with open(dmp_path, 'rb') as f:
    f.seek(ctx_rva)
    b = f.read(ctx_size)

Eip = struct.unpack_from('<I', b, 0xB8)[0]
Esp = struct.unpack_from('<I', b, 0xC4)[0]
Ebp = struct.unpack_from('<I', b, 0xB4)[0]
Eax = struct.unpack_from('<I', b, 0xB0)[0]
Ecx = struct.unpack_from('<I', b, 0xAC)[0]
Edx = struct.unpack_from('<I', b, 0xA8)[0]
Esi = struct.unpack_from('<I', b, 0xA0)[0]
Edi = struct.unpack_from('<I', b, 0x9C)[0]
print("Eip=0x%08X Esp=0x%08X Ebp=0x%08X Eax=0x%08X Ecx=0x%08X Edx=0x%08X Esi=0x%08X Edi=0x%08X" % (Eip, Esp, Ebp, Eax, Ecx, Edx, Esi, Edi))

# ---- disasm at Eip ----
print("\n--- CODE @ Eip (ntdll+0x502F8) ---")
code = rd(Eip - 32, 64)
if code:
    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True
        for insn in md.disasm(code, Eip - 32):
            mark = " <== EIP" if insn.address == Eip else ""
            print("  0x%08X  %-10s %s%s" % (insn.address, insn.mnemonic, insn.op_str, mark))
    except ImportError:
        print("  capstone missing:", code.hex())
else:
    print("  no code readable")

# ---- stack walk ----
print("\n--- STACK WALK from Esp=0x%08X ---" % Esp)
esp = Esp
# collect dwords that look like code addresses (module rva >= 0x1000)
for i in range(256):
    d = rd(esp, 4)
    if not d:
        print("  [unreadable @ 0x%08X]" % esp)
        break
    val = struct.unpack('<I', d)[0]
    m, off = addr_mod(val)
    if m and off >= 0x1000:
        print("  [0x%08X] = 0x%08X  -> %s+0x%X" % (esp, val, m, off))
    esp += 4
