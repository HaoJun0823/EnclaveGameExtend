# -*- coding: utf-8 -*-
"""
在 45820 条真实字幕缓冲上离线仿真 v16c 新截断算法，与 v17r 旧结果对比。
缓冲重建：日志中 未加括号(正文) + 加括号(尾部) 合起来就是缓冲内容。
"""
import re, collections

LOG = r"I:\SteamLibrary\steamapps\common\Enclave\Sbz1\Save\CJK_sub_log.txt"

def is_junk(w):
    return (w < 0x20) or (0x3400 <= w <= 0x4DBF) or (0xA000 <= w <= 0xABFF) \
        or (0xAC00 <= w <= 0xD7FF) or (0xD800 <= w <= 0xDFFF) \
        or (0xE000 <= w <= 0xF8FF) or w in (0xFFFE, 0xFFFF)

def is_body(w):
    return (0x3000 <= w <= 0x30FF) or (0x4E00 <= w <= 0x9FFF) \
        or (0xFF01 <= w <= 0xFFEF) or (0x2010 <= w <= 0x2027)

PUNCT_SET = {0x3002, 0x3001, 0xFF01, 0xFF1F, 0x2014, 0xFF0C}
LOOKAHEAD = 6

def junk_ahead(d, i):
    for k in range(i, min(i + LOOKAHEAD, len(d), 120)):
        w = d[k]
        if w == 0: return False
        if is_junk(w): return True
    return False

def v16c(d):
    """返回 lastValid"""
    last = -1
    n = min(len(d), 120)
    for i in range(n):
        w = d[i]
        if w == 0: break
        if w in PUNCT_SET:
            wn = d[i+1] if i+1 < n else 0
            if wn != 0 and ((wn & 0xFF) == 0 or (wn & 0xFF00) == 0) and junk_ahead(d, i+1):
                last = i; break
        if (w & 0xFF00) != 0 and (w & 0xFF) != 0 and is_body(w):
            wn = d[i+1] if i+1 < n else 0
            if wn != 0 and (wn & 0xFF) == 0 and (wn & 0xFF00) != 0 and wn != 0x3000 \
               and junk_ahead(d, i+1):
                last = i; break
        if is_junk(w): break
        if (w & 0xFF00) == 0:
            if 0x20 <= w <= 0x7E:
                j = i
                while j < n and (d[j] & 0xFF00) == 0 and 0x20 <= d[j] <= 0x7E:
                    j += 1
                wl = d[j] if j < n else 0
                if wl != 0 and not is_body(wl): break
                last = i
                continue
            break
        if not is_body(w): break
        last = i
    return last

# ---- 解析 ----
recs = []
expect = False
with open(LOG, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        if line.startswith("[SUB "):
            expect = True; continue
        if expect:
            toks = re.findall(r"\[([0-9A-F]{4})\]|([0-9A-F]{4})", line)
            body = [int(b, 16) for a, b in toks if b]
            tail = [int(a, 16) for a, b in toks if a]
            if body:
                recs.append((body, body + tail))
            expect = False

print("样本条数：", len(recs))

shorter = longer = same = 0
cut_junk = 0          # 旧正文含垃圾、新正文不含 → 修好
new_junk = 0          # 新正文仍含垃圾 → 漏网
over_cut = collections.Counter()
examples_fixed, examples_overcut, examples_leak = [], [], []

for old_body, buf in recs:
    lv = v16c(buf)
    new_body = buf[:lv+1]
    o_junk = any(is_junk(w) for w in old_body)
    n_junk = any(is_junk(w) for w in new_body)
    if len(new_body) < len(old_body): shorter += 1
    elif len(new_body) > len(old_body): longer += 1
    else: same += 1
    if o_junk and not n_junk:
        cut_junk += 1
        if len(examples_fixed) < 3:
            examples_fixed.append(("".join(chr(w) for w in old_body),
                                   "".join(chr(w) for w in new_body)))
    if n_junk:
        new_junk += 1
        if len(examples_leak) < 3:
            examples_leak.append("".join(chr(w) for w in new_body))
    # 误切检测：旧正文无垃圾，新正文却更短 → 可能误伤
    if not o_junk and len(new_body) < len(old_body):
        over_cut[len(old_body) - len(new_body)] += 1
        if len(examples_overcut) < 5:
            examples_overcut.append(("".join(chr(w) for w in old_body),
                                     "".join(chr(w) for w in new_body)))

print(f"\n新正文更短: {shorter}   更长: {longer}   相同: {same}")
print(f"垃圾被切干净(修好): {cut_junk}")
print(f"新正文仍含垃圾(漏网): {new_junk}")
print(f"疑似误切(旧无垃圾却被切短): {sum(over_cut.values())}  分布={dict(over_cut)}")

print("\n=== 修好样例 ===")
for o, n in examples_fixed:
    print(f"   旧: {o!r}")
    print(f"   新: {n!r}")
print("\n=== 漏网样例 ===")
for n in examples_leak:
    print(f"   {n!r}")
print("\n=== 疑似误切样例 ===")
for o, n in examples_overcut:
    print(f"   旧: {o!r}")
    print(f"   新: {n!r}")

# 专项：含「攀」U+6500 或 「一」U+4E00 的句子是否被腰斩
print("\n=== 低字节为 0x00 的合法汉字（攀 U+6500 / 一 U+4E00）保护验证 ===")
hit = 0
for old_body, buf in recs:
    if 0x6500 in buf[:40] or 0x4E00 in buf[:40]:
        lv = v16c(buf)
        idx = min([buf.index(c) for c in (0x6500, 0x4E00) if c in buf[:40]])
        if lv < idx:
            hit += 1
            if hit <= 3:
                print(f"   ✗ 被腰斩: {''.join(chr(w) for w in buf[:idx+4])!r} -> lastValid={lv}")
print(f"   含该类字的句子中被腰斩: {hit} 条")
