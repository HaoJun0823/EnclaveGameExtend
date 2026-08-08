# -*- coding: utf-8 -*-
"""
用"绝对垃圾码位"判据重做统计，回答一个问题：
   @@@@ 到底是 (甲) 句号 。的字形缺失，还是 (乙) 句号后未截断的垃圾尾？

绝对垃圾码位（字库 1931 字集绝无、且正常中文字幕绝不会出现）：
   < 0x20 控制字符 / 0x3400-0x4DBF CJK扩展A / 0xA000-0xABFF 彝文·占文
   / 0xAC00-0xD7FF 谚文音节 / 0xD800-0xDFFF 代理对 / 0xE000-0xF8FF 私用区
"""
import re, collections

LOG = r"I:\SteamLibrary\steamapps\common\Enclave\Sbz1\Save\CJK_sub_log.txt"

def is_junk(w):
    return (w < 0x20) or (0x3400 <= w <= 0x4DBF) or (0xA000 <= w <= 0xABFF) \
        or (0xAC00 <= w <= 0xD7FF) or (0xD800 <= w <= 0xDFFF) or (0xE000 <= w <= 0xF8FF)

PUNCT = {0x3002: "。", 0xFF0C: "，", 0x3001: "、", 0xFF01: "！", 0xFF1F: "？", 0x2014: "—"}

entries = []
expect = False
with open(LOG, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        if line.startswith("[SUB "):
            expect = True
            continue
        if expect:
            toks = re.findall(r"\[([0-9A-F]{4})\]|([0-9A-F]{4})", line)
            body = [int(b, 16) for a, b in toks if b]
            if body:
                entries.append(body)
            expect = False

print("SUB 条目：", len(entries))

# 以"正文中第一个绝对垃圾"为界，看它前面紧邻的是什么
stat = collections.Counter()          # 首个垃圾前一个字符
tot_by_punct = collections.Counter()  # 正文含某标点的总条数
junk_by_punct = collections.Counter() # 其中含垃圾的条数
uniq = {}

for body in entries:
    j = next((i for i, w in enumerate(body) if is_junk(w)), None)
    has_junk = j is not None
    # 该条正文里出现过哪些句尾标点
    seen = {PUNCT[w] for w in (body[:j] if has_junk else body) if w in PUNCT}
    for s in seen:
        tot_by_punct[s] += 1
        if has_junk:
            junk_by_punct[s] += 1
    if has_junk:
        prev = body[j-1] if j > 0 else 0
        stat[PUNCT.get(prev, "非句尾标点(U+%04X)" % prev)] += 1
        key = "".join(chr(w) for w in body[:j])
        if key not in uniq and len(uniq) < 8:
            uniq[key] = (j, [f"{w:04X}" for w in body[j:j+10]])

print(f"\n正文含【绝对垃圾】的条目：{sum(1 for b in entries if any(is_junk(w) for w in b))} / {len(entries)}")

print("\n=== A. 首个垃圾字【前一个字符】分布（Top10）===")
for k, v in stat.most_common(10):
    print(f"   {k:22s} {v:6d}")

print("\n=== B. 按句尾标点分组：该标点出现的条目中有多少含垃圾 ===")
print(f"   {'标点':6s} {'总条数':>8s} {'含垃圾':>8s} {'比例':>8s}")
for s in ["。", "，", "！", "？", "—", "、"]:
    t = tot_by_punct[s]
    g = junk_by_punct[s]
    if t:
        print(f"   {s:6s} {t:8d} {g:8d} {g*100.0/t:7.2f}%")

print("\n=== C. 垃圾前的正文样例 ===")
for txt, (j, gar) in list(uniq.items())[:8]:
    print(f"   正文({j}字)={txt!r}")
    print(f"        垃圾起始: {' '.join(gar)}")
