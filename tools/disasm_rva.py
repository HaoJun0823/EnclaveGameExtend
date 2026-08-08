# -*- coding: utf-8 -*-
"""反汇编 GameWorld.dll 指定 RVA 区间。用法: disasm_rva.py <startRVA> <length>"""
import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL = r'I:/SteamLibrary/steamapps/common/Enclave/Sbz1/GameWorld.dll'
IMAGE_BASE = 0x10000000

data = open(DLL, 'rb').read()
e = struct.unpack_from('<I', data, 0x3C)[0]
coff = e + 4
so = struct.unpack_from('<H', data, coff + 16)[0]
nsec = struct.unpack_from('<H', data, coff + 2)[0]
sec = coff + 20 + so

secs = []
for i in range(nsec):
    o = sec + i * 40
    nm = data[o:o + 8].split(b'\x00')[0].decode('latin1')
    va = struct.unpack_from('<I', data, o + 12)[0]
    vs = struct.unpack_from('<I', data, o + 8)[0]
    rp = struct.unpack_from('<I', data, o + 20)[0]
    rs = struct.unpack_from('<I', data, o + 16)[0]
    secs.append((nm, va, vs, rp, rs))


def rva2off(rva):
    for nm, va, vs, rp, rs in secs:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None


start = int(sys.argv[1], 16)
length = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x80
off = rva2off(start)
if off is None:
    print('RVA 不在任何节内')
    sys.exit(1)

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = False
for ins in md.disasm(data[off:off + length], IMAGE_BASE + start):
    rva = ins.address - IMAGE_BASE
    print('0x%05X  %-8s  %-28s  %s' % (rva, ins.bytes.hex(), ins.mnemonic, ins.op_str))
