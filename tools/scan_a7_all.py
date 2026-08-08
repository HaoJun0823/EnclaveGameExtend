# -*- coding: utf-8 -*-
"""全 .text 扫描所有对 0xA7 (§) 的比较，判断宏扫描器是【窄】还是【宽】"""
import sys, io, struct

TARGETS = [
    r'I:\SteamLibrary\steamapps\common\Enclave\Sbz1\GameWorld.dll',
    r'I:\SteamLibrary\steamapps\common\Enclave\MSystem.dll',
    r'I:\SteamLibrary\steamapps\common\Enclave\Sbz1\GameClasses.dll',
]
OUT = r'G:\Projects\EnclaveGameExtend\tools\_a7_scan.txt'

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

WIDE_REGS  = ('ax', 'cx', 'dx', 'bx', 'si', 'di', 'bp', 'sp')
BYTE_REGS  = ('al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh')

def classify(ins):
    op = ins.op_str.lower()
    if 'byte ptr' in op:
        return 'NARROW(byte ptr)'
    if 'word ptr' in op and 'dword' not in op:
        return 'WIDE(word ptr)'
    first = op.split(',')[0].strip()
    if first in BYTE_REGS:
        return 'NARROW(%s)' % first
    if first in WIDE_REGS:
        return 'WIDE(%s)' % first
    return 'OTHER(%s)' % first

def main():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    lines = []
    for path in TARGETS:
        try:
            data, imgbase, secs = sections(path)
        except Exception as ex:
            lines.append('!! %s : %s' % (path, ex))
            continue
        lines.append('')
        lines.append('#' * 90)
        lines.append('## %s  imgbase=%08X' % (path, imgbase))
        lines.append('#' * 90)
        for nm, va, vs, ro, rs, ch in secs:
            if not (ch & 0x20000000):     # 只扫可执行段
                continue
            code = data[ro:ro + min(rs, vs if vs else rs)]
            lines.append('-- section %s rva=%06X size=%06X' % (nm, va, len(code)))
            n = 0
            for ins in md.disasm(code, va):
                m = ins.mnemonic.lower()
                op = ins.op_str.lower()
                if m not in ('cmp', 'sub', 'test', 'mov', 'movzx', 'movsx', 'push'):
                    continue
                if '0xa7' not in op:
                    continue
                # 排除大立即数里恰好含 a7 的（如 0x101a7000）
                if '0x' in op:
                    ok = False
                    for tok in op.replace(',', ' ').replace('[', ' ').replace(']', ' ').split():
                        if tok.startswith('0x'):
                            try:
                                v = int(tok, 16)
                            except Exception:
                                continue
                            if v == 0xA7:
                                ok = True
                    if not ok:
                        continue
                lines.append('  %-6s %05X  %-20s %s %-28s  => %s'
                             % (m.upper(), ins.address, ins.bytes.hex(' '),
                                ins.mnemonic, ins.op_str, classify(ins)))
                n += 1
            lines.append('   (hits=%d)' % n)
    with io.open(OUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print('done, lines=%d' % len(lines))

if __name__ == '__main__':
    main()
