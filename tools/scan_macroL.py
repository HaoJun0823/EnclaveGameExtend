# -*- coding: utf-8 -*-
"""扫描 xrg 里的 §L 宏与教程句，输出到文件（避免控制台编码问题）"""
import os, glob, io

BASE = r'I:\SteamLibrary\steamapps\common\Enclave\Sbz1'
OUT  = r'G:\Projects\EnclaveGameExtend\tools\_macroL_report.txt'

SECT = '\u00a7'   # §

def scan():
    lines = []
    files = []
    for root, dirs, fs in os.walk(BASE):
        for f in fs:
            if f.lower().endswith('.xrg'):
                files.append(os.path.join(root, f))

    total = 0
    for fn in sorted(files):
        try:
            with open(fn, 'r', encoding='utf-16') as fh:
                txt = fh.read()
        except Exception:
            continue
        rel = os.path.relpath(fn, BASE)
        for i, line in enumerate(txt.splitlines(), 1):
            if (SECT + 'L') in line or '拔出' in line or '武器' in line:
                lines.append('%s:%d: %s' % (rel, i, line.strip()))
                total += 1

    with io.open(OUT, 'w', encoding='utf-8') as o:
        o.write('SCAN BASE=%s  files=%d  hits=%d\n' % (BASE, len(files), total))
        o.write('=' * 70 + '\n')
        for L in lines:
            o.write(L + '\n')
    return total

if __name__ == '__main__':
    n = scan()
    print('hits=%d' % n)
