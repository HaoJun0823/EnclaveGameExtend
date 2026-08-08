# -*- coding: utf-8 -*-
"""通用反汇编：disasm_any.py <dll路径关键字> <起始RVA hex> <结束RVA hex>"""
import sys, io, struct

MAP = {
    'exe':   r'I:\SteamLibrary\steamapps\common\Enclave\Enclave.exe',
    'gw':    r'I:\SteamLibrary\steamapps\common\Enclave\Sbz1\GameWorld.dll',
    'ms':    r'I:\SteamLibrary\steamapps\common\Enclave\MSystem.dll',
    'gc':    r'I:\SteamLibrary\steamapps\common\Enclave\Sbz1\GameClasses.dll',
}
OUT = r'G:\Projects\EnclaveGameExtend\tools\_disasm_any.txt'

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
        secs.append((nm, va, vs, ro, rs))
    return data, imgbase, secs

def r2o(secs, rva):
    for nm, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None

def strat(data, imgbase, secs, va, maxn=48):
    """尝试把一个 VA 解释为字符串"""
    rva = va - imgbase
    off = r2o(secs, rva)
    if off is None or off <= 0 or off >= len(data):
        return None
    raw = data[off:off+maxn]
    a = raw.split(b'\x00')[0]
    if len(a) >= 2 and all(0x20 <= c < 0x7f for c in a):
        return 'A"%s"' % a.decode('latin-1')
    # utf-16
    if len(raw) >= 4 and raw[1] == 0 and raw[3] == 0:
        try:
            w = raw.decode('utf-16-le', 'ignore').split('\x00')[0]
            if len(w) >= 2 and all(0x20 <= ord(c) < 0x7f for c in w):
                return 'W"%s"' % w
        except Exception:
            pass
    return None

def main():
    key = sys.argv[1]
    lo = int(sys.argv[2], 16)
    hi = int(sys.argv[3], 16)
    path = MAP[key]
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    data, imgbase, secs = sections(path)
    off = r2o(secs, lo)
    code = data[off:off + (hi - lo)]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    lines = ['## %s  imgbase=%08X  RVA %05X-%05X' % (path, imgbase, lo, hi), '=' * 88]
    for ins in md.disasm(code, lo):
        note = ''
        op = ins.op_str
        # 给立即数/内存地址标注字符串
        for tok in op.replace(',', ' ').replace('[', ' ').replace(']', ' ').replace('+', ' ').split():
            if tok.startswith('0x') and len(tok) >= 8:
                try:
                    v = int(tok, 16)
                except Exception:
                    continue
                s = strat(data, imgbase, secs, v)
                if s:
                    note = '   ; ' + s
                    break
        lines.append('%05X  %-24s %-7s %-34s%s' % (ins.address, ins.bytes.hex(' '), ins.mnemonic, op, note))
    txt = '\n'.join(lines)
    with io.open(OUT, 'w', encoding='utf-8') as f:
        f.write(txt + '\n')
    print('lines=%d -> %s' % (len(lines), OUT))

if __name__ == '__main__':
    main()
