# -*- coding: utf-8 -*-
"""查找对 incremental-link thunk 的 E8 相对 call"""
import struct, io

GW = r'I:\SteamLibrary\steamapps\common\Enclave\Sbz1\GameWorld.dll'
EXE = r'I:\SteamLibrary\steamapps\common\Enclave\Enclave.exe'
OUT = r'G:\Projects\EnclaveGameExtend\tools\_thunk_callers.txt'

GW_T = [
    (0x1005C4, 'Localize_Str(CStr src, wide* dst, int)'),
    (0x1005D6, 'Localize_Str(NARROW src, wide* dst, int)'),
    (0x1005DC, 'Localize_Str(WIDE  src, wide* dst, int)'),
    (0x1005FA, 'Localize_Str(CStr)->CStr'),
    (0x100636, 'Localize_FindKeyValue'),
]
EXE_T = [
    (0x0495AE, 'Localize_Str(CStr src, wide* dst, int)'),
    (0x0495C0, 'Localize_Str(NARROW src, wide* dst, int)'),
    (0x0495C6, 'Localize_Str(WIDE  src, wide* dst, int)'),
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


def scan(path, thunks, tag, lines, zones):
    d, ib, secs = load(path)
    text = [s for s in secs if s[0] == '.text'][0]
    nm, sva, vs, ro, rs = text
    blob = d[ro:ro + rs]
    lines.append('#' * 92)
    lines.append('## %s   .text RVA=%06X size=%X' % (tag, sva, rs))
    lines.append('#' * 92)
    for tr, name in thunks:
        hits = []
        for p in range(0, len(blob) - 5):
            if blob[p] != 0xE8:
                continue
            rel = struct.unpack_from('<i', blob, p + 1)[0]
            if sva + p + 5 + rel == tr:
                hits.append(sva + p)
        lines.append('')
        lines.append('-- %-42s thunk=%06X  callers=%d' % (name, tr, len(hits)))
        for rva in hits:
            mark = ''
            for lo, hi, tagz in zones:
                if lo <= rva <= hi:
                    mark = '   <<== ' + tagz
            lines.append('     call @ RVA %06X%s' % (rva, mark))


def main():
    lines = []
    scan(GW, GW_T, 'GameWorld.dll', lines,
         [(0x8D000, 0x8F000, '字幕绘制区'), (0x8C000, 0x8D000, '宏判别器区'),
          (0x20000, 0x21000, '0x20FB2 hook区'), (0xF9000, 0xFA000, '绘制拷贝区')])
    scan(EXE, EXE_T, 'Enclave.exe', lines, [])
    txt = '\n'.join(lines)
    with io.open(OUT, 'w', encoding='utf-8') as f:
        f.write(txt + '\n')
    print('ok')


if __name__ == '__main__':
    main()
