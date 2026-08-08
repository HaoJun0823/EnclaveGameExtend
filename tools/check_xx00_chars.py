# -*- coding: utf-8 -*-
"""
针对性验证：正文【中间】出现低字节为 0x00 的合法汉字（U+XX00，如 攀6500 一4E00
斗6597? 不…）时，v16c 算法是否会腰斩。
做法：从日志重建缓冲 → 先用"真文本边界"（第一个 0x0000 或绝对垃圾）定出真实正文
      → 若真实正文内部含 U+XX00 字符，检查 v16c 的 lastValid 是否覆盖到真实末尾。
另外附一组合成用例（含「攀上」）做白盒验证。
"""
import re

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
                last = i; continue
            break
        if not is_body(w): break
        last = i
    return last

def true_end(d):
    """真实正文末尾索引：第一个 0x0000 / 绝对垃圾 / 非正文字符 之前"""
    for i, w in enumerate(d[:120]):
        if w == 0 or is_junk(w): return i - 1
        if not is_body(w) and not (0x20 <= w <= 0x7E): return i - 1
    return min(len(d), 120) - 1

# ---------- 合成白盒用例 ----------
print("=== 合成用例（白盒）===")
def S(s): return [ord(c) for c in s]
cases = [
    ("正常含攀上",      S("　　我要攀上那座塔。") + [0]*4),
    ("正常含一",        S("　　这是一个人。")     + [0]*4),
    ("攀在句中+后接垃圾", S("　　我要攀上那座塔。") + [0xAA00, 0xD0D1, 0x2700, 0]),
    ("句号后垃圾",      S("　　关押啊。")         + [0xAA00, 0x3800, 0x719B, 0xD0D1, 0]),
    ("逗号后垃圾",      S("　　同胞的声音，")     + [0xE800, 0x1234, 0]),
    ("干净无垃圾",      S("　　你此刻听到的，")   + [0, 0]),
]
for name, buf in cases:
    lv = v16c(buf)
    print(f"   {name:18s} lastValid={lv:2d}  正文={''.join(chr(w) for w in buf[:lv+1])!r}")

# ---------- 真实样本 ----------
recs = []
expect = False
with open(LOG, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        if line.startswith("[SUB "):
            expect = True; continue
        if expect:
            toks = re.findall(r"\[([0-9A-F]{4})\]|([0-9A-F]{4})", line)
            words = [int(a or b, 16) for a, b in toks]
            if words: recs.append(words)
            expect = False

print(f"\n=== 真实样本 {len(recs)} 条：正文内部含 U+XX00 合法汉字的腰斩检查 ===")
bad = 0
inner = 0
shown = 0
seen = set()
for buf in recs:
    te = true_end(buf)
    if te < 1: continue
    real = buf[:te+1]
    # 正文内部（非末位）出现低字节 0x00 的合法汉字
    idxs = [i for i, w in enumerate(real[:-1]) if (w & 0xFF) == 0 and is_body(w) and w != 0x3000]
    if not idxs: continue
    inner += 1
    lv = v16c(buf)
    if lv < te:
        bad += 1
        key = "".join(chr(w) for w in real)
        if key not in seen and shown < 5:
            seen.add(key); shown += 1
            print(f"   ✗ 腰斩 真实正文={key!r}")
            print(f"       v16c 只保留 -> {''.join(chr(w) for w in buf[:lv+1])!r}")
print(f"   正文内部含 U+XX00 汉字的条目: {inner}    其中被腰斩: {bad}")
