#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EnclaveCJK v16i 日志分析器
===========================
读取游戏根目录下的三份日志，给出 v16i 部署后的诊断结论：

  CJK_hook_log.txt   安装期日志（重点：4 条 IAT hook 是否成功）
  CJK_post_log.txt   §L 后置全角化日志（重点：教程按键名是否真的展开）
  CJK_tfstr_log.txt  字幕诊断日志（重点：H4 不再被 SND: 刷屏、H5 有数据）

用法：
  python analyze_v16i_logs.py [日志目录]
  默认目录 = 脚本同级的 Enclave 游戏根（I:/SteamLibrary/steamapps/common/Enclave）
"""
import os
import re
import sys

DEFAULT_DIR = r"I:\SteamLibrary\steamapps\common\Enclave"

SECTION = "=" * 64


def read_text(path):
    """编码鲁棒读取：BOM 优先；无 BOM 时按 gb18030(日志中文) -> utf-8 -> latin-1"""
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        raw = f.read()
    if not raw:
        return ""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw.decode("utf-8-sig", errors="replace")
    for enc in ("gb18030", "utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def parse_words(hexdump):
    """从 '004E 6309 0053 ...' 提取 WORD 列表（十六进制）"""
    out = []
    for tok in hexdump.replace(",", " ").split():
        tok = tok.strip()
        if re.fullmatch(r"[0-9A-Fa-f]{2,4}", tok):
            try:
                out.append(int(tok, 16))
            except ValueError:
                pass
    return out


def analyze_hook(log):
    print("\n" + SECTION)
    print("① CJK_hook_log.txt  ——  IAT hook 安装")
    print(SECTION)
    if log is None:
        print("  [缺失] 文件不存在。游戏本次是否启动过？")
        return {"iat_ok": 0, "iat_fail": [], "msys_missing": False, "missing": True}
    lines = log.splitlines()
    iat_ok = []
    iat_fail = []
    msys_missing = False
    legacy = []
    for ln in lines:
        if "IAT" in ln and "hook 成功" in ln:
            m = re.search(r"IAT (\S+) hook 成功", ln)
            if m:
                iat_ok.append(m.group(1))
        elif "IAT" in ln and "校验失败" in ln:
            m = re.search(r"IAT (\S+) 校验失败", ln)
            iat_fail.append(m.group(1) if m else "?")
        elif "MSystem.dll 未加载" in ln:
            msys_missing = True
        elif "TFStr" in ln and "hook" in ln:
            legacy.append(ln.strip())
        elif "0x20FB2" in ln or "0x10054F00" in ln or "0x1008ED" in ln or "0x1008ED1A" in ln:
            if "hook" in ln or "跳过" in ln:
                legacy.append(ln.strip())

    print(f"  IAT hook 成功：{len(iat_ok)} / 4   槽位={iat_ok}")
    if iat_fail:
        print(f"  ⚠ IAT 校验失败（未改写，零风险跳过）：{iat_fail}")
    if msys_missing:
        print("  ⚠ MSystem.dll 未加载 → IAT hook 整体跳过，§L 全角化不生效！")
    if legacy:
        print("  原有 hook：")
        for l in legacy[:6]:
            print("    " + l)

    print("\n  【判定】", end="")
    if msys_missing:
        print("§L 全角化整条未装 → 教程仍会 @@@")
    elif len(iat_ok) == 4:
        print("4 槽全部命中，§L 覆盖完整 ✓")
    elif len(iat_ok) >= 1:
        print(f"部分命中（{len(iat_ok)}/4），其余槽位校验失败需查 IAT_RVA")
    else:
        print("无任何 IAT 命中 → 槽位地址或修饰名可能需复核")
    return {"iat_ok": len(iat_ok), "iat_fail": iat_fail, "msys_missing": msys_missing}


def analyze_post(log):
    print("\n" + SECTION)
    print("② CJK_post_log.txt  ——  §L 展开产物（核心判据）")
    print(SECTION)
    if log is None or log.strip() == "":
        print("  [空] 没有任何 POST 记录。")
        print("  → IAT 后置处理从未触发。可能：")
        print("    (a) IAT hook 未装上（看 ①）；")
        print("    (b) 教程文本根本不经过 Localize_Str（走了别的入口）；")
        print("    (c) 游戏本次没跑到教程提示。")
        return {"post": 0, "skip": 0, "secl": False, "callers": set()}
    post = 0
    skip = 0
    secl = False          # 检出 §L 仍未展开
    nl_hit = 0
    nl_words = []
    callers = set()
    samples = []
    for ln in log.splitlines():
        if ln.startswith("[POST-SKIP"):
            skip += 1
            m = re.search(r"caller=([0-9A-Fa-f]+)", ln)
            if m:
                callers.add(m.group(1))
        elif ln.startswith("[POST"):
            post += 1
            m = re.search(r"caller=([0-9A-Fa-f]+)", ln)
            if m:
                callers.add(m.group(1))
    # 第二遍：逐对解析 [POST n] 行 + 紧跟的 hexdump 行
    lines = log.splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith("[POST ") and not ln.startswith("[POST-SKIP"):
            hexline = lines[i + 1] if i + 1 < len(lines) else ""
            words = parse_words(hexline)
            # 检测 §L 未展开：连续 0x00A7 0x004C（'§' 'L'）
            for j in range(len(words) - 1):
                if words[j] == 0x00A7 and words[j + 1] == 0x004C:
                    secl = True
            # v16j：检测换行/行分隔码位（换行破坏取证）
            wl = [w for w in words if w in (0x000A, 0x000D, 0x2028, 0x0085, 0x000B)]
            if wl:
                nl_hit += 1
                if len(nl_words) < 8:
                    nl_words.append((ln.strip(), words[:48]))
            if len(samples) < 5:
                samples.append((ln.strip(), words[:24]))

    print(f"  [POST] 命中：{post} 条，其中含换行码位 {nl_hit} 条")
    print(f"  [POST-SKIP] 纯 ASCII 放行：{skip} 条（安全闸按预期工作）")
    print(f"  涉及调用者 RVA：{sorted(callers)}")
    if nl_words:
        print("  ★ 含换行/行分隔码位的缓冲（换行破坏取证）：")
        for head, w in nl_words:
            txt = " ".join(f"{x:04X}" for x in w)
            print(f"    {head}")
            print(f"      {txt}")
    if samples:
        print("  样本（前若干条，含 WORD 快照）：")
        for head, w in samples:
            txt = " ".join(f"{x:04X}" for x in w)
            print(f"    {head}")
            print(f"      {txt}")
    print("\n  【判定】", end="")
    if secl:
        print("⚠ 检出 0x00A7 0x004C（§L）原样残留 → §L 在 Localize_Str【之外】展开，"
              "IAT 后置拿不到键名 → 需改 hook Localize_FindKeyValue 兜底分支（记忆 P2）")
    elif post > 0:
        print("§L 已在 Localize_Str 内部展开为键名，后置全角化已接管 ✓ "
              "（快照应见 0xFFxx 全角键名而非 @）")
    else:
        print("无 [POST] 数据，见上『空』分支")
    return {"post": post, "skip": skip, "secl": secl, "callers": callers}


def analyze_tfstr(log):
    print("\n" + SECTION)
    print("③ CJK_tfstr_log.txt  ——  字幕截断点（闪烁/句尾 @）")
    print(SECTION)
    if log is None or log.strip() == "":
        print("  [空] 本次无字幕诊断数据。")
        return
    h4 = 0
    h4_snd = 0
    h5 = 0
    h5_ok = 0
    for ln in log.splitlines():
        if "[H4]" in ln:
            h4 += 1
            if "SND" in ln or "53 4E 44" in ln:
                h4_snd += 1
        elif "[H5]" in ln:
            h5 += 1
            # 期望头字节 A7 5A 32 32（§Z22）
            if "A7 5A" in ln or "A7 5A 32 32" in ln:
                h5_ok += 1
    print(f"  [H4] 共 {h4} 条，其中 SND: 噪声 {h4_snd} 条")
    print(f"  [H5] 共 {h5} 条，头字节 §Z22 正常 {h5_ok} 条")
    print("\n  【判定】", end="")
    if h4 == 0 and h5 == 0:
        print("无数据（可能诊断配额未触发或日志被清空）")
    elif h4_snd == 0 and h4 > 0:
        print("H4 已无 SND: 噪声 → 登记表不再被刷爆，闪烁/句尾 @ 应已消失 ✓")
    elif h4_snd > 0:
        print(f"⚠ H4 仍含 {h4_snd} 条 SND: → 噪声过滤未生效，需复查 strong 判据")
    else:
        print("见 H4/H5 数据")


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DIR
    print(SECTION)
    print(f"EnclaveCJK v16i 日志分析  ——  目录: {d}")
    print(SECTION)
    hook = read_text(os.path.join(d, "CJK_hook_log.txt"))
    post = read_text(os.path.join(d, "CJK_post_log.txt"))
    tfstr = read_text(os.path.join(d, "CJK_tfstr_log.txt"))

    r1 = analyze_hook(hook)
    r2 = analyze_post(post)
    analyze_tfstr(tfstr)

    print("\n" + SECTION)
    print("汇总")
    print(SECTION)
    if r1.get("missing"):
        verdict = "日志尚未生成：游戏本次未启动 / 未跑到教程。先启动游戏跑教程关再回传日志"
    elif r1.get("msys_missing"):
        verdict = "BLOCKER: MSystem.dll 未加载，IAT hook 未装 → 教程 §L 必失败"
    elif r1.get("iat_ok", 0) == 4 and r2.get("post", 0) > 0 and not r2.get("secl"):
        verdict = "理想：4 槽全中 + POST 有键名展开 → 教程按键名应正常显示"
    elif r1.get("iat_ok", 0) == 4 and r2.get("post", 0) == 0:
        verdict = "IAT 已装但无 POST → 教程提示可能不走 Localize_Str（需查调用入口）"
    elif r1.get("iat_ok", 0) == 4 and r2.get("secl"):
        verdict = "§L 在 Localize_Str 之外展开 → 需 hook FindKeyValue 兜底分支"
    elif r1.get("iat_ok", 0) < 4:
        verdict = "IAT 槽位覆盖不全 → 查校验失败项，复核 IAT_RVA"
    else:
        verdict = "需结合上述分项人工判断"
    print("  " + verdict)
    print(SECTION)


if __name__ == "__main__":
    main()
