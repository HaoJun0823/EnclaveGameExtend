# -*- coding: utf-8 -*-
"""解析 PE 导出表 / 导入表，定位 MSystem 的 §L 展开函数是否被外部调用"""
import struct, io, sys

MS = r'I:\SteamLibrary\steamapps\common\Enclave\MSystem.dll'
GW = r'I:\SteamLibrary\steamapps\common\Enclave\Sbz1\GameWorld.dll'
GC = r'I:\SteamLibrary\steamapps\common\Enclave\Sbz1\GameClasses.dll'
EXE = r'I:\SteamLibrary\steamapps\common\Enclave\Enclave.exe'
OUT = r'G:\Projects\EnclaveGameExtend\tools\_pe_exp.txt'


def load(path):
    with open(path, 'rb') as f:
        d = f.read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e + 6)[0]
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    opt = e + 24
    imgbase = struct.unpack_from('<I', d, opt + 28)[0]
    ndir = struct.unpack_from('<I', d, opt + 92)[0]
    dirs = []
    for i in range(ndir):
        va, sz = struct.unpack_from('<II', d, opt + 96 + i * 8)
        dirs.append((va, sz))
    so = opt + optsz
    secs = []
    for i in range(nsec):
        o = so + i * 40
        nm = d[o:o + 8].rstrip(b'\x00').decode('latin-1')
        vs, va, rs, ro = struct.unpack_from('<IIII', d, o + 8)
        secs.append((nm, va, vs, ro, rs))
    return d, imgbase, dirs, secs


def r2o(secs, rva):
    for nm, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


def cstr(d, off):
    if off is None:
        return ''
    end = d.find(b'\x00', off)
    return d[off:end].decode('latin-1', 'ignore')


def exports(path):
    d, ib, dirs, secs = load(path)
    eva, esz = dirs[0]
    res = []
    if not eva:
        return res
    eo = r2o(secs, eva)
    nfunc, nname = struct.unpack_from('<II', d, eo + 20)
    afunc, aname, aord = struct.unpack_from('<III', d, eo + 28)
    fo = r2o(secs, afunc)
    no = r2o(secs, aname)
    oo = r2o(secs, aord)
    ordmap = {}
    for i in range(nname):
        nrva = struct.unpack_from('<I', d, no + i * 4)[0]
        idx = struct.unpack_from('<H', d, oo + i * 2)[0]
        ordmap[idx] = cstr(d, r2o(secs, nrva))
    for i in range(nfunc):
        frva = struct.unpack_from('<I', d, fo + i * 4)[0]
        if frva:
            res.append((frva, ordmap.get(i, '<noname>')))
    return res


def imports(path, want_dll):
    d, ib, dirs, secs = load(path)
    iva, isz = dirs[1]
    res = []
    if not iva:
        return res
    io_ = r2o(secs, iva)
    k = 0
    while True:
        o = io_ + k * 20
        oft, tds, fwd, nrva, fta = struct.unpack_from('<IIIII', d, o)
        if nrva == 0:
            break
        dll = cstr(d, r2o(secs, nrva))
        if want_dll.lower() in dll.lower():
            t = oft or fta
            to = r2o(secs, t)
            j = 0
            while True:
                v = struct.unpack_from('<I', d, to + j * 4)[0]
                if v == 0:
                    break
                if v & 0x80000000:
                    res.append((dll, 'ord#%d' % (v & 0xFFFF), fta + j * 4))
                else:
                    nm = cstr(d, r2o(secs, v) + 2)
                    res.append((dll, nm, fta + j * 4))
                j += 1
        k += 1
    return res


def main():
    lines = []
    exp = exports(MS)
    lines.append('== MSystem.dll exports: %d ==' % len(exp))
    targets = {0x10AA20: 'MacroExpand(?)', 0x10A900: 'Localize_GetKey',
               0x10A6A0: 'Localize_Lookup', 0x10A560: 'ParamCollect'}
    for rva, nm in exp:
        if rva in targets:
            lines.append('  ** RVA %06X = %-18s EXPORTED as %s' % (rva, targets[rva], nm))
    # 邻近导出（定位函数边界归属）
    near = sorted([e for e in exp if 0x10A000 <= e[0] <= 0x10B200])
    lines.append('-- exports in 0x10A000..0x10B200: %d' % len(near))
    for rva, nm in near[:40]:
        lines.append('   %06X  %s' % (rva, nm[:110]))
    for tag, p in (('GameWorld', GW), ('GameClasses', GC), ('Enclave.exe', EXE)):
        try:
            imp = imports(p, 'MSystem')
        except Exception as ex:
            lines.append('!! %s: %s' % (tag, ex))
            continue
        lines.append('')
        lines.append('== %s imports from MSystem: %d ==' % (tag, len(imp)))
        hits = [i for i in imp if 'ocali' in i[1] or 'acro' in i[1] or 'xpand' in i[1] or 'Text' in i[1]]
        for dll, nm, iat in hits[:40]:
            lines.append('   IAT=%06X  %s' % (iat, nm[:120]))
    txt = '\n'.join(lines)
    with io.open(OUT, 'w', encoding='utf-8') as f:
        f.write(txt + '\n')
    print('ok -> %s (%d lines)' % (OUT, len(lines)))


if __name__ == '__main__':
    main()
