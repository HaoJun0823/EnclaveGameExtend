# -*- coding: utf-8 -*-
"""在 GameWorld.dll / Enclave.exe 中查找对 MSystem Localize_* 的 IAT 间接调用点"""
import struct, io

GW = r'I:\SteamLibrary\steamapps\common\Enclave\Sbz1\GameWorld.dll'
EXE = r'I:\SteamLibrary\steamapps\common\Enclave\Enclave.exe'
OUT = r'G:\Projects\EnclaveGameExtend\tools\_loc_calls.txt'

# (模块, IAT RVA, 名称)
GW_IAT = [
    (0x13E4F4, 'Localize_FindKeyValue'),
    (0x13E51C, 'Localize_Str(CStr)->CStr'),
    (0x13E530, 'Localize_Str(WIDE src, wide* dst, int)'),
    (0x13E534, 'Localize_Str(NARROW src, wide* dst, int)'),
    (0x13E540, 'Localize_Str(CStr src, wide* dst, int)'),
]
EXE_IAT = [
    (0x07744C, 'Localize_Str(CStr src, wide* dst, int)'),
    (0x077458, 'Localize_Str(NARROW src, wide* dst, int)'),
    (0x07745C, 'Localize_Str(WIDE src, wide* dst, int)'),
]


def load(path):
    with open(path, 'rb') as f:
        d = f.read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e + 6)[0]
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    opt = e + 24
    ib = struct.unpack_from('<I', d, opt + 28)[0]
    so = opt + optsz
    secs = []
    for i in range(nsec):
        o = so + i * 40
        nm = d[o:o + 8].rstrip(b'\x00').decode('latin-1')
        vs, va, rs, ro = struct.unpack_from('<IIII', d, o + 8)
        secs.append((nm, va, vs, ro, rs))
    return d, ib, secs


def scan(path, iats, tag, lines):
    d, ib, secs = load(path)
    text = [s for s in secs if s[0] == '.text']
    lines.append('#' * 92)
    lines.append('## %s  imgbase=%08X' % (tag, ib))
    lines.append('#' * 92)
    for iat_rva, name in iats:
        va = ib + iat_rva
        pat_call = b'\xff\x15' + struct.pack('<I', va)   # call dword ptr [va]
        pat_jmp = b'\xff\x25' + struct.pack('<I', va)    # jmp  dword ptr [va]
        hits = []
        for nm, sva, vs, ro, rs in text:
            blob = d[ro:ro + rs]
            for pat, kind in ((pat_call, 'call'), (pat_jmp, 'jmp ')):
                p = 0
                while True:
                    p = blob.find(pat, p)
                    if p < 0:
                        break
                    hits.append((sva + p, kind))
                    p += 1
        lines.append('')
        lines.append('-- %-42s IAT=%06X  hits=%d' % (name, iat_rva, len(hits)))
        for rva, kind in sorted(hits):
            mark = ''
            if 0x8D000 <= rva <= 0x8F000:
                mark = '   <<== 字幕代码区!'
            elif 0x8C000 <= rva <= 0x90000:
                mark = '   <-- 字幕邻近'
            lines.append('     %s @ RVA %06X%s' % (kind, rva, mark))


def main():
    lines = []
    scan(GW, GW_IAT, 'GameWorld.dll', lines)
    scan(EXE, EXE_IAT, 'Enclave.exe', lines)
    txt = '\n'.join(lines)
    with io.open(OUT, 'w', encoding='utf-8') as f:
        f.write(txt + '\n')
    print('ok -> %s' % OUT)


if __name__ == '__main__':
    main()
