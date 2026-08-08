# -*- coding: utf-8 -*-
"""扫描 GameWorld.dll .text 段，找出所有 call rel32 指向指定 RVA 的调用点。"""
import struct, sys

DLL = r'I:/SteamLibrary/steamapps/common/Enclave/Sbz1/GameWorld.dll'
IMAGE_BASE = 0x10000000

data = open(DLL, 'rb').read()
e = struct.unpack_from('<I', data, 0x3C)[0]
coff = e + 4
so = struct.unpack_from('<H', data, coff + 16)[0]
nsec = struct.unpack_from('<H', data, coff + 2)[0]
sec = coff + 20 + so

sections = []
for i in range(nsec):
    o = sec + i * 40
    nm = data[o:o + 8].split(b'\x00')[0].decode('latin1')
    va = struct.unpack_from('<I', data, o + 12)[0]
    vs = struct.unpack_from('<I', data, o + 8)[0]
    rp = struct.unpack_from('<I', data, o + 20)[0]
    rs = struct.unpack_from('<I', data, o + 16)[0]
    sections.append((nm, va, vs, rp, rs))

text = [s for s in sections if s[0] == '.text'][0]
_, tva, tvs, trp, trs = text

targets = [int(x, 16) for x in sys.argv[1:]] or [0x8ECE0]

for target in targets:
    print('=== 调用 RVA 0x%X 的位置 ===' % target)
    found = 0
    body = data[trp:trp + trs]
    for i in range(len(body) - 5):
        if body[i] != 0xE8:
            continue
        rel = struct.unpack_from('<i', body, i + 1)[0]
        call_rva = tva + i
        dest = call_rva + 5 + rel
        if dest == target:
            print('   call 站点 RVA 0x%05X   (VA 0x%08X)' % (call_rva, IMAGE_BASE + call_rva))
            found += 1
    print('   共 %d 处\n' % found)
