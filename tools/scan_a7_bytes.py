# -*- coding: utf-8 -*-
"""
字节模式搜索所有与 0xA7 (§) 比较/装载的指令（线性反汇编会错位，字节搜索更可靠）。
覆盖 Enclave.exe + 三个 DLL。
"""
import io, struct

TARGETS = [
    r'I:\SteamLibrary\steamapps\common\Enclave\Enclave.exe',
    r'I:\SteamLibrary\steamapps\common\Enclave\Sbz1\GameWorld.dll',
    r'I:\SteamLibrary\steamapps\common\Enclave\MSystem.dll',
    r'I:\SteamLibrary\steamapps\common\Enclave\Sbz1\GameClasses.dll',
]
OUT = r'G:\Projects\EnclaveGameExtend\tools\_a7_bytes.txt'

# (模式, 说明, 宽/窄)
PATTERNS = [
    (b'\x3c\xa7',             'cmp al, 0A7h',            'NARROW'),
    (b'\x80\xf8\xa7',         'cmp al, 0A7h',            'NARROW'),
    (b'\x80\xf9\xa7',         'cmp cl, 0A7h',            'NARROW'),
    (b'\x80\xfa\xa7',         'cmp dl, 0A7h',            'NARROW'),
    (b'\x80\xfb\xa7',         'cmp bl, 0A7h',            'NARROW'),
    (b'\x80\x38\xa7',         'cmp byte [eax], 0A7h',    'NARROW'),
    (b'\x80\x39\xa7',         'cmp byte [ecx], 0A7h',    'NARROW'),
    (b'\x80\x3a\xa7',         'cmp byte [edx], 0A7h',    'NARROW'),
    (b'\x80\x3b\xa7',         'cmp byte [ebx], 0A7h',    'NARROW'),
    (b'\x80\x3e\xa7',         'cmp byte [esi], 0A7h',    'NARROW'),
    (b'\x80\x3f\xa7',         'cmp byte [edi], 0A7h',    'NARROW'),
    (b'\x66\x3d\xa7\x00',     'cmp ax, 0A7h',            'WIDE'),
    (b'\x66\x81\xf9\xa7\x00', 'cmp cx, 0A7h',            'WIDE'),
    (b'\x66\x81\xfa\xa7\x00', 'cmp dx, 0A7h',            'WIDE'),
    (b'\x66\x81\xfb\xa7\x00', 'cmp bx, 0A7h',            'WIDE'),
    (b'\x66\x81\x38\xa7\x00', 'cmp word [eax], 0A7h',    'WIDE'),
    (b'\x66\x81\x39\xa7\x00', 'cmp word [ecx], 0A7h',    'WIDE'),
    (b'\x66\x81\x3a\xa7\x00', 'cmp word [edx], 0A7h',    'WIDE'),
    (b'\x66\x81\x3c',         'cmp word [reg+reg*n], ?', 'WIDE?'),
    (b'\xb0\xa7',             'mov al, 0A7h',            'NARROW'),
    (b'\x6a\xa7',             'push 0A7h',               '?'),
    (b'\x66\xb8\xa7\x00',     'mov ax, 0A7h',            'WIDE'),
]

def sections(path):
    with open(path, 'rb') as f:
        data = f.read()
    e = struct.unpack_from('<I', data, 0x3C)[0]
    nsec = struct.unpack_from('<H', data, e + 6)[0]
    opt = struct.unpack_from('<H', data, e + 20)[0]
    imgbase = struct.unpack_from('<I', data, e + 24 + 28)[0]
    so = e + 24 + opt
    secs = []
    for i in range(nsec):
        o = so + i * 40
        nm = data[o:o+8].rstrip(b'\x00').decode('latin-1')
        vs = struct.unpack_from('<I', data, o + 8)[0]
        va = struct.unpack_from('<I', data, o + 12)[0]
        rs = struct.unpack_from('<I', data, o + 16)[0]
        ro = struct.unpack_from('<I', data, o + 20)[0]
        ch = struct.unpack_from('<I', data, o + 36)[0]
        secs.append((nm, va, vs, ro, rs, ch))
    return data, imgbase, secs

def main():
    lines = []
    for path in TARGETS:
        data, imgbase, secs = sections(path)
        lines.append('')
        lines.append('#' * 92)
        lines.append('## %s   imgbase=%08X' % (path, imgbase))
        lines.append('#' * 92)
        for nm, va, vs, ro, rs, ch in secs:
            if not (ch & 0x20000000):
                continue
            blob = data[ro:ro + rs]
            for pat, desc, kind in PATTERNS:
                start = 0
                while True:
                    i = blob.find(pat, start)
                    if i < 0:
                        break
                    start = i + 1
                    # cmp word [reg+reg*n] 需要确认立即数是 A7 00
                    if pat == b'\x66\x81\x3c':
                        if blob[i+4:i+6] != b'\xa7\x00':
                            continue
                    rva = va + i
                    ctx = blob[max(0, i-8):i+14].hex(' ')
                    lines.append('  [%-6s] %s RVA=%06X  %-26s | ctx %s'
                                 % (kind, nm, rva, desc, ctx))
    with io.open(OUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print('\n'.join(lines))

if __name__ == '__main__':
    main()
