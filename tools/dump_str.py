# -*- coding: utf-8 -*-
"""按 VA 从 GameWorld.dll dump 字符串/字节（imgbase=0x10000000）"""
import sys, io, struct

DLL = r'I:\SteamLibrary\steamapps\common\Enclave\Sbz1\GameWorld.dll'

def load():
    with open(DLL, 'rb') as f:
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

def show(data, imgbase, secs, va, n=64):
    rva = va - imgbase
    off = r2o(secs, rva)
    if off is None:
        return 'VA %08X -> RVA %06X : NOT MAPPED' % (va, rva)
    raw = data[off:off+n]
    a = raw.split(b'\x00')[0].decode('latin-1', 'replace')
    try:
        w = raw.decode('utf-16-le', 'ignore').split('\x00')[0]
    except Exception:
        w = ''
    return ('VA %08X (RVA %06X off %06X)\n  hex   : %s\n  ascii : %r\n  utf16 : %r'
            % (va, rva, off, raw[:32].hex(' '), a, w))

if __name__ == '__main__':
    data, imgbase, secs = load()
    out = []
    for s in sys.argv[1:]:
        va = int(s, 16)
        out.append(show(data, imgbase, secs, va))
    txt = '\n\n'.join(out)
    with io.open(r'G:\Projects\EnclaveGameExtend\tools\_strdump.txt', 'w', encoding='utf-8') as f:
        f.write(txt + '\n')
    print(txt)
