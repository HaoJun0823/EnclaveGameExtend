# -*- coding: utf-8 -*-
"""反汇编 GameWorld.dll 指定 RVA 处的代码（PE32, ImageBase 0x10000000）"""
import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL = r"I:\SteamLibrary\steamapps\common\Enclave\Sbz1\GameWorld.dll"
IMAGE_BASE = 0x10000000

data = open(DLL, "rb").read()
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, e_lfanew + 4 + 2)[0]
size_opt = struct.unpack_from("<H", data, e_lfanew + 4 + 16)[0]
sect_off = e_lfanew + 4 + 20 + size_opt

sections = []
for i in range(nsec):
    off = sect_off + i * 40
    name = data[off:off + 8].rstrip(b"\x00").decode("latin1")
    vsize = struct.unpack_from("<I", data, off + 8)[0]
    vaddr = struct.unpack_from("<I", data, off + 12)[0]
    rsize = struct.unpack_from("<I", data, off + 16)[0]
    raddr = struct.unpack_from("<I", data, off + 20)[0]
    sections.append((name, vaddr, vsize, raddr, rsize))


def rva2off(rva):
    for name, va, vs, ra, rs in sections:
        if va <= rva < va + max(vs, rs):
            return ra + (rva - va)
    return None


md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

out = []
for rva, length in [(int(a, 16), int(b)) for a, b in
                    [x.split(":") for x in sys.argv[1:]]]:
    off = rva2off(rva)
    out.append("=== RVA 0x%X (VA 0x%X) file off 0x%X ===" % (rva, IMAGE_BASE + rva, off))
    for ins in md.disasm(data[off:off + length], IMAGE_BASE + rva):
        out.append("%08X  %-24s %s %s" % (ins.address,
                                          ins.bytes.hex(),
                                          ins.mnemonic, ins.op_str))
    out.append("")

open(r"G:\Projects\EnclaveGameExtend\tools\_disasm.txt", "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
