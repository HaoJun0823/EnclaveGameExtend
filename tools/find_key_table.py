# -*- coding: utf-8 -*-
"""在整个游戏目录里搜索 §L 键名的定义位置（同时试 ASCII 与 UTF-16LE 两种字节形式）"""
import os, io

ROOT = r'I:\SteamLibrary\steamapps\common\Enclave'
OUT  = r'G:\Projects\EnclaveGameExtend\tools\_keytable_report.txt'

KEYS = ['TUTORIAL_WEAPON', 'TUTORIAL_PRIMARY', 'TUTORIAL_JUMP', 'CHECKPOINT_MSG']

SKIP_DIRS = {'_ida_trash', 'directx', '.workbuddy', '.git'}
SKIP_EXT  = {'.bik', '.wav', '.ogg', '.jpg', '.png', '.gif', '.cab', '.zip', '.7z'}

def main():
    out = []
    scanned = 0
    for root, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in SKIP_EXT:
                continue
            p = os.path.join(root, f)
            try:
                if os.path.getsize(p) > 40 * 1024 * 1024:
                    continue
                with open(p, 'rb') as fh:
                    data = fh.read()
            except Exception:
                continue
            scanned += 1
            rel = os.path.relpath(p, ROOT)
            for k in KEYS:
                a = k.encode('ascii')
                w = k.encode('utf-16-le')
                na = data.count(a)
                nw = data.count(w)
                if na or nw:
                    # 取第一处上下文
                    ctx = ''
                    if nw:
                        i = data.find(w)
                        s = max(0, i - 60); e = min(len(data), i + len(w) + 60)
                        try:
                            ctx = data[s:e].decode('utf-16-le', 'replace').replace('\r', ' ').replace('\n', ' ')
                        except Exception:
                            ctx = repr(data[s:e])
                    else:
                        i = data.find(a)
                        s = max(0, i - 60); e = min(len(data), i + len(a) + 60)
                        ctx = data[s:e].decode('latin-1', 'replace').replace('\r', ' ').replace('\n', ' ')
                    out.append('%-60s | %s | ascii=%d wide=%d | %s' % (rel, k, na, nw, ctx))

    with io.open(OUT, 'w', encoding='utf-8') as o:
        o.write('scanned=%d files\n' % scanned)
        o.write('=' * 100 + '\n')
        for L in out:
            o.write(L + '\n')
    print('hits=%d scanned=%d' % (len(out), scanned))

if __name__ == '__main__':
    main()
