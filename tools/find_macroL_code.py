# -*- coding: utf-8 -*-
"""
在 GameWorld.dll 的宏展开区 [0x8D000,0x8F000] 里定位 §L 处理代码。
关注点：
  - 对 0xA7 (§) 的比较是【宽】(cmp ax/cx/dx, 0A7h) 还是【窄】(cmp al/cl/dl, 0A7h)
  - 紧随其后对 'L'(0x4C) / 'Z'(0x5A) / 'p'(0x70) 的分支
  - 展开时调用了哪些函数（键名查表 / 按键名取字符串）
"""
import sys, io, struct

DLL  = r'I:\SteamLibrary\steamapps\common\Enclave\Sbz1\GameWorld.dll'
OUT  = r'G:\Projects\EnclaveGameExtend\tools\_macroL_code.txt'

def pe_text(path):
    with open(path, 'rb') as f:
        data = f.read()
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    nsec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt  = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    imgbase = struct.unpack_from('<I', data, e_lfanew + 24 + 28)[0]
    sec_off = e_lfanew + 24 + opt
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o+8].rstrip(b'\x00').decode('latin-1')
        vsize = struct.unpack_from('<I', data, o + 8)[0]
        vaddr = struct.unpack_from('<I', data, o + 12)[0]
        rsize = struct.unpack_from('<I', data, o + 16)[0]
        roff  = struct.unpack_from('<I', data, o + 20)[0]
        secs.append((name, vaddr, vsize, roff, rsize))
    return data, imgbase, secs

def rva2off(secs, rva):
    for name, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None

def main():
    lo = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x8D000
    hi = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x8F000

    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    data, imgbase, secs = pe_text(DLL)
    off = rva2off(secs, lo)
    size = hi - lo
    code = data[off:off+size]

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False

    lines = []
    hits  = []
    for ins in md.disasm(code, lo):
        s = '%05X  %-22s %s %s' % (ins.address, ins.bytes.hex(' '), ins.mnemonic, ins.op_str)
        lines.append(s)
        op = ins.op_str.lower()
        m  = ins.mnemonic.lower()
        # 关注 §(0xA7) 与 L/Z/p 的比较
        if m in ('cmp', 'sub', 'movzx', 'test') and ('0xa7' in op or '0x4c' in op or '0x5a' in op or '0x70' in op):
            hits.append(('MACRO?', s))
        if m == 'call':
            hits.append(('CALL', s))

    with io.open(OUT, 'w', encoding='utf-8') as o:
        o.write('DLL=%s imgbase=%08X range=%05X-%05X\n' % (DLL, imgbase, lo, hi))
        o.write('=' * 90 + '\n')
        o.write('### 关注点 (%d)\n' % len(hits))
        for t, s in hits:
            o.write('%-7s %s\n' % (t, s))
        o.write('\n' + '=' * 90 + '\n')
        o.write('### 全量反汇编 (%d 条)\n' % len(lines))
        for s in lines:
            o.write(s + '\n')
    print('lines=%d hits=%d' % (len(lines), len(hits)))

if __name__ == '__main__':
    main()
