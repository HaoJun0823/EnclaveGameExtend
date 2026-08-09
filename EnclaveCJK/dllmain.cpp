// ============================================================================
//  EnclaveCJK  v16i   (2026-08-08)  —— 两个根因一次性定案
// ============================================================================
//  【实测反馈】v16h 部署后：① 字幕句尾 @ 仍闪烁（"…用我的——" 末尾）
//                          ② 教程仍 "按 @@@@ 来跳跃"；CJK_post_log.txt 一条未生成
//
//  ★ 根因 A（闪烁 + 句尾 @）：v16g 的抗刷判据【写错了】
//     v16g 用「WORD 落在 CJK 区 U+4E00–U+9FFF 且 ≥2 个」判字幕，但
//     ASCII 字节 ∈ 0x20–0x7E，两两拼成 WORD = 0x2020–0x7E7E，与 CJK 区大面积重叠！
//     实证：v16h 日志 72 条 [H4] 全是 "SND:xxx" 音效名 ——
//           "SND:Sats_ground" → 4E53('SN') 6153('aS') 7374('ts') 全部落在 CJK 区，
//           判据形同虚设 ⇒ 音效名被当字幕接管并 len_put 登记 ⇒ 登记表照样被刷爆。
//     修法：改用与 hook1（第 847-851 行）一致的 strong 判据，两道 ASCII 无法伪造的关：
//       ① 纯 ASCII 字节流（全 <0x80 且无 0x00）直接放行
//       ② strong = 低字节不可打印的汉字 / 全角区 U+FF01–U+FFEF
//          （ASCII 对低字节必可打印、高字节最大 0x7E ⇒ 永不满足）
//
//  ★ 根因 B（教程 @@@@）：hook 点覆盖面不够
//     §L 由 MSystem 的 Localize_Str 内部展开成【玩家绑定按键名】= 半角 ASCII，
//     而汉化字库（1931 字集）无半角 ASCII 字形 ⇒ 逐字回落 '@'。
//     v16h 只在调用点 0x20FB2 之后补全角化，但 GameWorld 有 9 处 call Localize_Str(CStr)，
//     且后处理还带着字幕区间判据 ⇒ 教程走别的点，一次没命中。
//     修法：改用 IAT hook（GameWorld 3 个变体 + GameClasses 1 个），
//           一次覆盖全部调用点；安装前用 GetProcAddress 逐项校验，不符不装。
// ============================================================================
//  v16f 已确认【全链路保宽 UTF-16LE】路线成立（攀/一/需 等低字节 0x00 汉字整句
//  正常显示）。残留缺陷：① 字幕闪烁（时有时无）② 句尾仍偶发 @。
//  根因：登记表 g_len 被高频纯 ASCII 噪声（SND: 音效名等，在字幕区间 0x8E362
//  内）刷爆 —— 每帧 len_put 轮转清空 12 槽，字幕登记被挤出 → hook5 查不到 → 回落
//  裸 strlen → 半截 + 句尾 @（即"闪烁"）。
//  v16g 修法（不动已验证的保宽构造路径）：
//    ① len_put 未命中且对象不在表中时不再占用/轮转槽位；
//    ② cjk_concat_finish / tfstr_cjk_wide 对纯 ASCII 资源名直接放行，不登记、不写日志；
//    ③ LEN_SLOTS 12 → 32。
//  效果：32 槽专供真实字幕，噪声零占用 → hook5 稳定命中 → 闪烁与句尾 @ 消失。
// ============================================================================
//  背景：v18~v20.2 一路激进改渲染路径，全部失败并造成倒退。本版【停止试探】，
//        回到 v15b 已验证可用的三 hook 架构，只做定点修正。
//
//  已安装 hook（3 个）：
//    [0] 0x20FB2  Localize_Str 调用点 —— 字幕文本入口（实证 sub=28746 条经过）
//                 判据：[esp+0x48A4] RVA ∈ [0x8D000,0x8F000]
//                 处理：置宽 flags|0x8000 → 剥 §Z → 残留终止符截断 → ASCII 全角化
//    [1] 0x54F00  TFStr<252> 构造（hook1）：★v16f 起【只观察不改写】——
//                 识别 UTF-16 中文正文后把宽文本【暂存】到 g_stash（按对象指针索引），
//                 然后无条件放行原构造。对引擎状态零副作用。
//                 调用者【区间】过滤 [0x8D000,0x8F000]（v16d 由白名单改来）
//    [2] 0x8ED9A  拼接收尾（hook4，v16f 新增）：拼接 sub_1008ECE0 在此写终止符、
//                 再 copy-ctor 出目标 TFStr。我们在此【直接重建目标对象】：
//                 前缀(§Z22，从临时缓冲原样取) + 暂存的完整宽正文 + 00 00 终止，
//                 从而【完全绕开】0x10054DA0 → 0x100EF96A 的裸 strlen。
//                 （hook3 0x8ED1A 已在 v16f 移除：长度不再经过引擎计算）
//
//  ── 本版修正的三个缺陷 ────────────────────────────────────────────────
//   (1) hook3 入口崩溃（0xC0000005）
//       根因：TFStr<252> 字符数据【内联】在对象 +4，旧码写成 mov eax,[eax+4]
//             把内联字符当指针解引用。
//       修正：改 lea eax,[eax+4]；并加【调用者区间过滤】(sub_1008ECE0 有 7 个
//             调用者，仅字幕区 [0x8D000,0x8F000] 才改长度，资源名等原样放行)。
//       v16b 追加：NULL 守卫必须在 lea 之【前】，否则 NULL→4 会绕过判空再次崩溃。
//
//   (2) "攀上" 类整句截断（v16d 修正）
//       根因（决定性）：hook1 调用者白名单用的是【call 指令地址】(0x8DD09/0x8DD31/
//             0x8E362/0x8DDE3)，但 trampoline 比对的是【call 之后的返回地址】
//             (= call 站点 + 5，如 0x8DD0E) → 永远对不上 → 全部 fallback 走窄构造
//             → 攀(U+6500 低字节 0x00)被 vsnprintf %s / strlen 截断 → 整句腰斩，
//             且窄构造把 UTF-16 当窄字节造出垃圾缓冲 → 句尾偶发 @。
//       修正（v16d）：hook1 改用【调用者区间过滤】[0x8D000,0x8F000]（与 hook3 一致），
//             不再逐个比对地址；并加 UTF-16 内容判定（字节[1]==0 或 ∈[0x4E,0xA0)）
//             只对字幕区 UTF-16 文本宽构造，避免误伤窄文本。junk_ahead 门控保留。
//       注：句尾 @ 与 攀截断同根（hook1 未命中导致窄构造垃圾缓冲），hook1 命中后一并消失。
//
//   (3) 句尾 @@@@ / 闪烁
//       ★ 曾误判为"句号 。字形缺失"。45820 条实测日志（CJK_sub_log.txt）统计推翻：
//           。22703 条 / 含垃圾尾 1620 = 7.14%
//           ，17708 条 / 含垃圾尾 1738 = 9.81%   ← 逗号反而更高
//           ！  320 条 / 含垃圾尾    0 = 0.00%
//       真因：句尾之后【未截断的堆垃圾】被当成正文渲染。垃圾码位（谚文 D0D1/BC00、
//             私用区 E7C8/E800、占文 AA00、CJK扩展A 3800/466A、非字符 FFFE）
//             在 1931 字集字库中无字形 → 回落显示 '@'。
//       修正：① 引入 is_junk_char() 绝对垃圾码位表 + junk_ahead() 前瞻窗口，
//                只有探到绝对垃圾才判定为残留终止符 → 同时根治(2)的误截断；
//             ② 截断时保留句尾标点本身（lastValid = i）而不是连标点一起丢；
//             ③ 撤销「句号 → 半角点」替换（基于错误假设，且会破坏中文排版）。
//
//  ── v16e 的结论（已被实测证伪，保留作为教训）──────────────────────────
//   v16e 假设「渲染器吃窄字节 + 字库已补齐 ⇒ 喂 GBK 即可」，于是在 hook1 里
//   WideCharToMultiByte(CP936) 就地转 GBK。实测结果：
//       ★ 被转成 GBK 的整句【完全不显示】；没被 hook1 命中的短句照旧（句尾 @）。
//   ⇒ 判据：【渲染器消费的是 UTF-16LE，不是 GBK】。反证链：
//       v16c 时代 hook1 不生效，正文是原构造 vsnprintf 原样拷贝的【UTF-16LE 字节】
//       （所以才会在 攀 U+6500 的 0x00 处腰斩），而截断前的「以及他们」显示【完全正确】。
//       若渲染器按 GBK 解释，UTF-16LE 字节只会显示成另一串乱字，不可能正好是原文。
//   ⇒ 渲染器取字模型 = 逐字节读，<0x80 当 ASCII，≥0x80 则再取一字节拼成
//       【小端 WORD = Unicode 码位】。GBK 的 以(D2 D4) 在此被读成 U+D4D2（谚文区）
//       → 字库无此码位 → 整句不出字。与实测现象完全吻合。
//
//  ── v16f 的路线（当前）────────────────────────────────────────────────
//   既然渲染器要 UTF-16LE，就必须让宽数据活到最后；而宽数据的唯一杀手是
//   拼接收尾 0x1008EDA6 → 0x10054DA0 → 0x100EF96A 的【裸 strlen】
//   （只收一个指针，长度自己数）。既然改不了它，就【别走它】：
//
//     hook1(0x54F00)  只识别 + 暂存宽正文，不改写任何引擎对象（零副作用）。
//     hook4(0x8ED9A)  在拼接函数写终止符那一刻接管：此时
//                       esi = 目标 TFStr、ebx = 前缀字节数、[esp+0x14] = 临时缓冲、
//                       [ebp+0xc] = 正文对象（用它去 g_stash 里取回完整宽文本）。
//                     直接把「前缀 + 宽正文 + 00 00」写进目标对象并设 vtable，
//                     然后跳过 0x8EDA6 的 copy-ctor 调用 → strlen 根本不会执行。
//     hook3(0x8ED1A)  移除。长度不再由引擎计算，修它已无意义（少一处汇编风险）。
//
//   为什么这次能同时解决句尾 @：目标缓冲的终止符由我们写【2 字节 00 00】，
//   落在偶数边界上，渲染器按 WORD 取字时天然停住，尾部不会再读到残留。
//
//  ★ 不要重走的死路（累计 10 次失败）：
//     vtable 替换 / 渲染路径 hook（0x10020F60、vtable+0xB8、拼接调用、GetKey）
//     —— 全部导致乱码或崩溃。
//     ★ 以及「把正文转成 GBK 喂给渲染器」（v16e）—— 整句不出字。
// ============================================================================
#define CJK_VERSION "v23q8"

#include "pch.h"

#define HOOK_RVA    0x20FB2u    // call Localize_Str 调用点
#define THUNK_RVA   0x1005C4u   // Localize_Str IAT thunk
#define RET_VA      0x20FB7u    // 原 call 返回点（add esp,10h）
#define SUB_LO      0x8D000u    // 字幕 Render 区
#define SUB_HI      0x8F000u

#include <windows.h>
#include <intrin.h>             // ★ v16i：_ReturnAddress()（IAT hook 记录调用者 RVA）

static HMODULE  g_hGameWorld = NULL;
static DWORD    g_gwBase     = 0;
static BYTE     g_origBytes[8];
static DWORD    g_retVA      = 0;
static DWORD    g_thunkVA    = 0;
// （v16h 的 g_postVA 已废弃：改用 IAT hook，见 install_hook 中的 iat_hook_one）
static BOOL     g_hooked     = FALSE;
static volatile LONG g_hits      = 0;
static volatile LONG g_subHits   = 0;
static volatile LONG g_uiHits    = 0;
static volatile LONG g_postHits  = 0;   // ★ v16h：后处理命中数
static volatile LONG g_keyFixed  = 0;   // ★ v16h：全角化的字符数（§L 展开产物）

static void log_msg(const char* fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    wvsprintfA(buf, fmt, ap);
    va_end(ap);
    HANDLE h = CreateFileA("CJK_hook_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);
    DWORD written;
    WriteFile(h, buf, lstrlenA(buf), &written, NULL);
    CloseHandle(h);
}

// ★ 正文白名单：判断一个 WORD 是否"合法字幕正文字符"
//   （用于终止符定位——正文 = 连续白名单字符，垃圾/残留/相邻对象字段 = 非白名单）
//   返回 1 = 正文，0 = 非正文（垃圾/残留终止符/字段）
static int is_body_char(WORD w)
{
    if (w == 0) return 0;                                   // 终止符
    if (w == 0x00A7) return 1;                              // § 键名标记（正文组成部分，"按 §LXXX 拉动"）
    if ((w & 0xFF00) == 0)
        return (w >= 0x20 && w <= 0x7E) ? 1 : 0;            // ASCII（正文半角，待全角化）
    if (w == 0xFF00 || w == 0xFFFE || w == 0xFFFF) return 0; // 非字符
    if (w >= 0x3000 && w <= 0x30FF) return 1;               // CJK 标点（。，！？）
    if (w >= 0x4E00 && w <= 0x9FFF) return 1;               // CJK 汉字
    if (w >= 0xFF01 && w <= 0xFFEF) return 1;               // 全角 ASCII
    if (w >= 0x2010 && w <= 0x2027) return 1;               // — – （em dash 等）
    return 0;
}

// ★ v16c：绝对垃圾码位判定（判据来自 45820 条实测字幕日志统计，CJK_sub_log.txt）
//   这些码段字库（1931 字集）必然无字形，且正常中文字幕绝不可能出现。
//   实测垃圾尾样本：AA00(占文) D0D1/BC00(谚文) E7C8/E800(私用区) FFFE(非字符)
//                   3800/466A(CJK扩展A) 0002/0003/0017(控制字符)
static int is_junk_char(WORD w)
{
    if (w < 0x20)                    return 1;   // 控制字符
    if (w >= 0x3400 && w <= 0x4DBF)  return 1;   // CJK 扩展 A
    if (w >= 0xA000 && w <= 0xABFF)  return 1;   // 彝文 / 占文
    if (w >= 0xAC00 && w <= 0xD7FF)  return 1;   // 谚文音节
    if (w >= 0xD800 && w <= 0xDFFF)  return 1;   // 代理对（独立出现即非法）
    if (w >= 0xE000 && w <= 0xF8FF)  return 1;   // 私用区
    if (w == 0xFFFE || w == 0xFFFF)  return 1;   // 非字符
    return 0;
}

// 从 i 开始向后看 LOOKAHEAD 个 WORD，是否出现绝对垃圾（遇 0 终止符即停）。
//   用途：区分【残留终止符 + 堆垃圾】和【低字节为 0x00 的合法汉字】。
//   反例保护：「攀(U+6500)上」——攀 低字节=0x00，旧规则会误判为终止符而截断整句；
//             但 攀 之后是正常文本、6 词内无绝对垃圾 → 本函数返回 0 → 不截断。
//   正例命中：「。」+ AA00 3800 719B D0D1 ... → 首词即绝对垃圾 → 返回 1 → 截断。
//   实测：全部 6 类垃圾尾样本均在 6 词内被识别；正常正文无误命中。
#define JUNK_LOOKAHEAD 6
static int junk_ahead(const WORD* data, int i)
{
    for (int k = i; k < i + JUNK_LOOKAHEAD && k < 120; k++)
    {
        WORD w = data[k];
        if (w == 0) return 0;                   // 正常终止 → 前面是真文本
        if (is_junk_char(w)) return 1;
    }
    return 0;
}

static void process_subtitle_text(DWORD dataHead)
{
    if (!dataHead || dataHead < 0x10000 || dataHead > 0x7FFEFFFF) return;
    WORD flags = *(WORD*)dataHead;
    if (!(flags & 0x8000))
    {
        *(WORD*)dataHead = flags | 0x8000;
    }
    WORD* data = (WORD*)(dataHead + 2);
    // ★ 剥 § 前缀（v13 宽容逻辑）：WORD0 低字节 == 0xA7 → 有 § 前缀（A7 00 标准 / A7 5A 错位）
    //   §L 键名（0x00A7, 0x004C）→ 保留（查表用）；其余（§Z 字号等）→ 剥 2 WORD 为空格
    WORD w0 = data[0];
    if ((w0 & 0xFF) == 0x00A7)
    {
        if (w0 == 0x00A7 && data[1] == 0x004C)
        {
            // §L 键名 → 保留（不剥）
        }
        else
        {
            data[0] = 0x0020;
            data[1] = 0x0020;
        }
    }

    // 表观长度（修复前，仅日志用）——限制在缓冲范围
    int rawLen = 0;
    while (rawLen < 120 && data[rawLen] != 0) rawLen++;

    // ★ 终止符修复 v2（2026-08-08 07:45）——尾部 @@@@/闪烁 根治
    //   旧版（v17r）只认 0x00AA 形态（高字节=0 且低字节>0x7E），实测漏网形态：
    //     0x0036('6') 0x0033('3') 0x002D('-') 0x0D00 0x0700 0xFF00 0x1E00 ...（约 50% 坏帧）
    //   → 引擎 GetLength(wcslen) 读到相邻对象字段 → 显示 "正文+@@@@@+重复句"
    //   新版：合一循环（全角化 + 正文白名单定位终止符）
    //     - 正文 = 连续白名单字符（汉字/全角标点/ASCII/§键名）
    //     - 遇"非白名单"即正文结束 → 补宽终止符 0000 0000 + 清残留
    //     - ASCII 加链前瞻：跳过整条 ASCII 看链后，非正文则整链是垃圾
    //   ★ v4 越界防护（2026-08-08 08:12）：读写严格限制在 TFStr<252> 缓冲内（120 WORD 上限），
    //     防止 lastValid 误判到垃圾区时写坏相邻堆对象（崩溃根因，dmp: ESP=0xAAAAAAAA）
    int lastValid = -1;
    for (int i = 0; i < 120; i++)
    {
        WORD w = data[i];
        if (w == 0) break;                              // 完整终止符
        if (w == 0x00A7)                                // § 键名 → 跳过保留（查表用）
        {
            // ★ v11 修复（2026-08-08 08:45）：纯键名字幕（如 §LCHECKPOINT_MSG）后是
            //   1 字节终止符残留（如 6F00）→ 旧版跳过循环把残留也当键名跳过 → 一路跳进垃圾区
            //   → lastValid 落在垃圾区深处 → 清 0 写坏堆 → ntdll 崩溃（31364 dmp 实证）
            //   v11：键名后紧贴"含 0 字节 WORD"（残留终止符，排除空格）→ 键名即正文结束
            i++;
            while (i < 120 && data[i] != 0 && data[i] != 0x20) i++;   // 跳过键名 ASCII
            lastValid = i - 1;                          // 键名最后一个字符
            if (i < 120)
            {
                WORD wn = data[i];
                if (wn != 0 && wn != 0x0020 && wn != 0x3000
                    && ((wn & 0xFF) == 0 || (wn & 0xFF00) == 0))
                    break;                              // 键名后残留终止符 → 截断（防垃圾区越界）
            }
            continue;                                   // 键名后空格/正文 → 继续处理
        }
        // ★ v10 残留终止符规则（2026-08-08 08:40）——覆盖所有结尾形态：
        //   规则1（标点后）：句尾标点（。！？——，）后紧贴"含 0 字节 WORD"（[00][XX] 或 [XX][00]
        //     = 引擎 1 字节终止符 + 残留）→ 正文到此结束。
        //     实测：3002(。)+6F00、2014(—)+7100、FF0C(，)+4F00 —— 用户反馈"还有——、逗号结尾"
        //     多句字幕安全：标点后是正常汉字（低字节≠0 且高字节≠0）不触发
        //   规则2（汉字后，覆盖无标点结尾）：正文汉字后紧贴 [00][XX]（低字节=0 高字节≠0，非 3000 空格）
        //     → 残留终止符截断。实测：4EEC(们)+6F00、6309(机)+3000(空格,已排除)
        //     误伤风险低：正文"汉字+低字节0汉字"（如"一刀"）罕见
        // ★ v16c 门控：单看"下一个 WORD 含 0 字节"会误伤低字节为 0x00 的合法汉字
        //   （攀 U+6500、一 U+4E00 等）→ 这正是「攀上」整句被截断的根因。
        //   改为【必须同时在前瞻窗口内探到绝对垃圾】才判定为残留终止符。
        if (w == 0x3002 || w == 0x3001 || w == 0xFF01 || w == 0xFF1F
            || w == 0x2014 || w == 0xFF0C)
        {
            WORD wn = (i + 1 < 120) ? data[i + 1] : 0;
            if (wn != 0 && ((wn & 0xFF) == 0 || (wn & 0xFF00) == 0)
                && junk_ahead(data, i + 1))
            {
                lastValid = i;                          // ★ 保留句尾标点本身，只丢垃圾
                break;
            }
        }
        if ((w & 0xFF00) != 0 && (w & 0xFF) != 0 && is_body_char(w))
        {
            WORD wn = (i + 1 < 120) ? data[i + 1] : 0;
            if (wn != 0 && (wn & 0xFF) == 0 && (wn & 0xFF00) != 0 && wn != 0x3000
                && junk_ahead(data, i + 1))
            {
                lastValid = i;                          // ★ 保留当前汉字
                break;
            }
        }
        // ★ 兜底：当前 WORD 本身就是绝对垃圾 → 正文到此为止
        if (is_junk_char(w)) break;
        if ((w & 0xFF00) == 0)                          // 高字节 = 0
        {
            if (w >= 0x20 && w <= 0x7E)                 // ASCII
            {
                // ★ ASCII 链前瞻（v3）：跳过整条连续 ASCII，看链后第一个非 ASCII
                int j = i;
                while (j < 120 && (data[j] & 0xFF00) == 0
                       && data[j] >= 0x20 && data[j] <= 0x7E)
                    j++;
                WORD wlook = (j < 120) ? data[j] : 0;
                if (wlook != 0 && !is_body_char(wlook)) break;
                if (w == 0x7C) { /* v18h：引擎换行符 0x7C 保持原样（渲染器识别为换行；0xFF5C 全角竖线不换行 → 教程 | 换行不生效根因）*/ }
                else data[i] = (w == 0x20) ? 0x3000 : (w + 0xFEE0);  // 全角化
                lastValid = i;
                continue;
            }
            break;                                      // 高字节=0 非 ASCII → 残留终止符
        }
        if (!is_body_char(w)) break;                    // 高字节≠0 但非正文白名单 → 垃圾字段
        lastValid = i;                                  // 正文（汉字/全角标点）
    }
    // 补宽终止符 + 清残留（防 wcslen 越界读相邻对象）——严格限制缓冲内
    if (lastValid > 116) lastValid = 116;               // 上限保险（清 0 范围 117..121 仍在 120 内）
    for (int j = lastValid + 1; j < lastValid + 6 && j < 120; j++)
        data[j] = 0;

    // ★ 句号 @@@@ 根治（v16, 2026-08-08）：。（U+3002）经引擎 GBK 窄字节渲染 → A1 A3，
    //   第二字节 A3 在字库无对应字形 → 显示 @@@@ / 闪烁（用户实测：逗号结尾无 @@@@、句号结尾有）。
    //   渲染执行流不可 hook，故在此（字幕宽文本阶段，且 0x20FB2 已实证对字幕生效）把 。
    //   替换为半角 .（U+002E）。
    //
    // ★★ v16c 已撤销该替换 —— 假设被 45820 条实测日志推翻（2026-08-08）：
    //       。出现 22703 条，含垃圾尾 1620 条 =  7.14%
    //       ，出现 17708 条，含垃圾尾 1738 条 =  9.81%   ← 比句号更高
    //       ！出现   320 条，含垃圾尾    0 条 =  0.00%
    //    逗号比句号更容易带垃圾尾 → @@@@ 与句号字形无关。
    //    真因：句尾之后【未截断的堆垃圾】被当成正文渲染，其码位（谚文/私用区/
    //          CJK扩展A/FFFE）字库无字形 → 回落显示 '@'。
    //    正确治法 = 上面的垃圾前瞻截断规则（+ hook1 写入正确的宽终止符），
    //    而不是替换标点；替换只会让中文句号变成难看的半角点，且治不了 @@@@。

    // ★ 取证日志：前 25 条 + 坏帧（rawLen>25）+ 每 100 条 + 正文残留 @ 形态
    {
        static volatile LONG s_logCnt = 0;
        LONG n = InterlockedIncrement(&s_logCnt);
        int len = lastValid + 1;
        // 检测修复后正文范围内是否残留 @（0x0040 半角 / 0xFF20 全角）——漏网实证
        int has_sus = 0;
        for (int k = 0; k < len && k < 96; k++)
        {
            WORD wk = data[k];
            if (wk == 0x0040 || wk == 0xFF20) { has_sus = 1; break; }
        }
        if (n <= 25 || rawLen > 25 || (n % 100) == 1 || has_sus)
        {
            char buf[1024];
            char* p = buf;
            p += wsprintfA(p, "[SUB %ld] dh=%08X flags=%04X fixlen=%d rawlen=%d\n", n, dataHead, (unsigned)flags, len, rawLen);
            for (int i = 0; i < 96 && i < len + 24; i++)
            {
                if (i < len)
                    p += wsprintfA(p, "%04X ", (unsigned)data[i]);
                else
                    p += wsprintfA(p, "[%04X] ", (unsigned)data[i]);
            }
            p += wsprintfA(p, "\n");
            p += wsprintfA(p, "tail: ");
            for (int i = len; i < len + 8 && i < 120; i++)
                p += wsprintfA(p, "%04X ", (unsigned)data[i]);
            p += wsprintfA(p, "\n");
            HANDLE h = CreateFileA("CJK_sub_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                                   NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE)
            {
                SetFilePointer(h, 0, NULL, FILE_END);
                DWORD written;
                WriteFile(h, buf, (DWORD)(p - buf), &written, NULL);
                CloseHandle(h);
            }
        }
    }
    InterlockedIncrement(&g_subHits);
}

// ★ v13：判断地址是否在当前线程栈内（StackLimit~StackBase）
//   崩溃证据4：Enclave.exe.35920.dmp = dsound.dll+5B256，崩溃线程 ESP=0xAAAAAAAA（栈损坏）
//   → v12 放宽特征验证后，ECX 偶尔是"栈地址"（父栈残留碰巧中文/§开头）→ hook 写 data[0..120] 写坏栈
//   → 栈损坏漂移到音频路径崩溃。v13：栈内地址一律跳过（不写 → 不坏栈）
static int is_stack_addr(DWORD addr)
{
    NT_TIB* tib = (NT_TIB*)NtCurrentTeb();
    DWORD base = (DWORD)tib->StackBase;
    DWORD limit = (DWORD)tib->StackLimit;
    return (addr >= limit && addr < base);
}

// ★ v8 SEH 保护壳 + 双候选 data_head + 字幕特征验证（2026-08-08 08:24）
//   崩溃史：25136/31876 = ntdll 堆操作（hook 写坏堆）→ v7 特征验证后消失 ✓
//   @ 残留（v7 用户反馈"极少数文本末尾只有一个@"）：hook 修复正确（fixlen 内无 @，9752 条 dump 实证）
//   → @ 帧 = 引擎 GetLength 读的 data_head（[STACK+0x48A0]）≠ ECX（hook 修的）→ 偶发不一致
//   → v8：双候选——候选1=ECX（v1-v3/v7 实测有效）；候选2=[参数1-4]（=引擎读的 data_head）
//     各自特征验证通过才处理（不写非字幕 → 不坏堆 → 不崩）
static int looks_like_subtitle(DWORD dataHead)
{
    if (dataHead < 0x10000 || dataHead > 0x7FFEFFFF) return 0;
    if (is_stack_addr(dataHead)) return 0;  // ★ v13：栈地址跳过（防写坏栈 → dsound 崩溃）
    WORD flags = *(volatile WORD*)dataHead;
    if (flags & 0x8000) return 0;           // 已置宽（非待处理/已处理）→ 跳过
    WORD* d = (WORD*)(dataHead + 2);
    // ★ v12 放宽（2026-08-08 08:50）：字幕不总是 § 开头——"按 §LTUTORIAL_SECONDARY 拉动拉杆"
    //   以"按"(0x6309) 开头，§ 键名在正文中间。旧条件 (d[0]&0xFF)==0xA7 会漏掉 → 引擎原样渲染 § → @@
    //   新条件：§ 开头 / §L 键名（扫描前 24 WORD）/ 中文正文开头 / 空格开头 → 处理
    if ((d[0] & 0xFF) == 0xA7) return 1;    // § 开头（拼接缓冲 §Z/§L）
    for (int k = 0; k < 24 && d[k] != 0; k++)
        if (d[k] == 0x00A7 && d[k + 1] == 0x004C) return 1;   // 正文含 §L 键名
    if (d[0] >= 0x4E00 && d[0] <= 0x9FFF) return 1;           // 中文正文开头（"按..."）
    if (d[0] == 0x0020 || d[0] == 0x3000) return 1;           // 空格开头
    return 0;
}

static void __declspec(noinline) safe_process_subtitle_text(DWORD ecxVal, DWORD pParam)
{
    __try
    {
        // 候选1：ECX（v1-v3/v7 实测有效 = 字幕 data_head）
        if (looks_like_subtitle(ecxVal))
            process_subtitle_text(ecxVal);
        // 候选2：[参数1-4] = [STACK+0x48A0] = 引擎 GetLength 读的 data_head（@ 帧引擎侧对象）
        if (pParam >= 0x10004 && pParam <= 0x7FFEFFFF)
        {
            DWORD dh2 = *(volatile DWORD*)(pParam - 4);
            if (dh2 != ecxVal && looks_like_subtitle(dh2))
                process_subtitle_text(dh2);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // 吞掉所有异常，不影响游戏
    }
}

static void __declspec(naked) cjk_trampoline_impl(void)
{
    __asm
    {
        pushad
        mov eax, [esp + 0x48A4]
        sub eax, g_gwBase
        cmp eax, SUB_LO
        jb  not_sub
        cmp eax, SUB_HI
        ja  not_sub
        ; ★ v8：候选1 = [esp+0x24]（ECX 值，v1-v3 实测字幕 data_head）
        ;       候选2 = [esp+0x2C]（参数1 = STACK+0x48A4）→ safe_process 内 [参数1-4] = 引擎读的 data_head
        ;   cdecl 双参数：先 push pParam，再 push ecxVal
        mov edx, [esp + 0x24]
        mov eax, [esp + 0x2C]
        push eax
        push edx
        call safe_process_subtitle_text
        add esp, 8
        jmp done_proc
not_sub:
        mov eax, g_uiHits
        inc eax
        mov g_uiHits, eax
done_proc:
        mov eax, g_hits
        inc eax
        mov g_hits, eax
        popad
        ; ★ v16i：恢复直接返回 0x20FB7。
        ;   v16h 曾在这里改跳后处理 trampoline，但那样只覆盖 0x20FB2 这一个调用点，
        ;   而 GameWorld 有 9 处 call Localize_Str(CStr)，教程提示并不走本点
        ;   （实测 CJK_post_log.txt 一条未生成）。改用 IAT hook 一次覆盖全部调用点。
        push g_retVA
        jmp dword ptr [g_thunkVA]
    }
}

// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
// ★ v16h：§L 宏展开产物全角化（2026-08-08）——教程文本 "按@@@@来拔出武器" 根治
//
// 【根因（静态反汇编定案）】
//   .xrg 原文：  按 §LTUTORIAL_WEAPON 取出武器。
//   hook 时机：  0x20FB2 是 `call Localize_Str` **之前**，此刻缓冲里还是字面量 §LTUTORIAL_WEAPON。
//   pre-pass（process_subtitle_text 第 236-237 行）**故意跳过键名 ASCII 不全角化** —— 这是对的，
//     因为 MSystem 的 Localize_SubstituteKeys(0x10AA20) 要 `cmp cx,0xA7` / `cmp ecx,0x4C` 匹配
//     再拿窄 ASCII 键名 "TUTORIAL_WEAPON" 去 stringtable 查表；全角化了就查不到。
//   随后 Localize_Str 把 §LTUTORIAL_WEAPON 展开成【玩家实际绑定的按键显示名】写进 out 缓冲，
//     而按键名来自 Enclave.exe 内嵌 CONFIG 的 bind 参数 —— **半角 ASCII**（如 SPACE / CTRL / E）。
//   汉化字库（1931 字集）**没有半角 ASCII 字形** —— 这正是 pre-pass 要做全角化的原因。
//   → 展开出来的按键名每个字符都无字形 → 逐字回落 '@' → "按@@@@来拔出武器@@@"
//
// 【结论】可修复。不是引擎 bug，是我们的全角化跑在了展开之前。
// 【修法】在 Localize_Str **返回后**对 out 缓冲补做一次全角化。
//
// 【失败安全】本函数只做【原地等长改写】，不移动、不扩长、不写终止符：
//   - § 控制序列（§Z22 字号等）原样跳过，绝不改动 → 不会破坏渲染器的 § 解析
//   - 看不懂的字节形态一律不动 → 最坏退化成"和今天一样"，不会更差
// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
#define POST_MAX_WORDS 1000     // out 缓冲 cap = 0x3FF 字符，留余量
#define POST_SITES     16       // v16j：按 caller 分组的诊断配额（防止被主菜单每帧文本刷爆）
#define POST_PER_SITE  12

// v16j：按 caller RVA 分组的 [POST] 记录配额。
//   返回 1 = 本组允许记录；force=1（含换行码位）强制记录、不占配额。
//   v16i 用全局 400 条配额，被主菜单「新建游戏」每帧调用刷满，
//   导致游戏内字幕/教程的 [POST] 一条都记不到 —— 换行 @@ 无据可查。
static int post_quota(DWORD callerRva, int force)
{
    static DWORD s_site[POST_SITES];
    static LONG  s_cnt[POST_SITES];
    static LONG  s_sites = 0;
    LONG i, n;
    if (force) return 1;
    for (i = 0; i < s_sites; i++)
        if (s_site[i] == callerRva) break;
    if (i >= s_sites)
    {
        n = InterlockedIncrement(&s_sites) - 1;          // 原子分配新槽
        if (n >= POST_SITES) { InterlockedDecrement(&s_sites); return 0; }
        s_site[n] = callerRva; s_cnt[n] = 0;
        i = n;
    }
    n = InterlockedIncrement(&s_cnt[i]);
    return n <= POST_PER_SITE;
}

static void __declspec(noinline) safe_fullwidth_expanded(DWORD outPtr, DWORD callerRva, int cap)
{
    __try
    {
        if (outPtr < 0x10000 || outPtr > 0x7FFEFFFF) return;
        WORD* out = (WORD*)outPtr;
        // 取证快照（改写前），只记前若干条
        static volatile LONG s_postLog = 0;
        LONG n = InterlockedIncrement(&s_postLog);

        // ★ v16i 安全闸：IAT hook 覆盖了【全游戏】的 Localize_Str 调用，
        //   其中难免有「输出被当作查表 key / 资源名 / 路径」的内部用途。
        //   对那些做全角化会直接把功能改坏。
        //   判据：只有【本身含 CJK 汉字或全角字符】的输出才是"要显示给玩家的汉化文本"，
        //   才允许补全角化；纯 ASCII 输出一律不动（宁可它显示成 @，也不能毁掉内部 key）。
        //   教程文本展开后 = 「按(全角) SPACE(半角) 来跳跃(全角)」→ 含 CJK ✓ 命中。
        int hasAscii = 0, hasCjk = 0, hasNl = 0, nw = 0;
        // v16j：以 cap 为硬上限，绝不越过 out 缓冲的实际容量（防越界读/写坏缓冲）
        int limit = (cap > 0 && cap < POST_MAX_WORDS) ? cap : POST_MAX_WORDS;
        for (int k = 0; k < limit && out[k] != 0; k++)
        {
            WORD c = out[k];
            if (c == 0x000A || c == 0x000D || c == 0x2028 || c == 0x0085 || c == 0x000B)
                hasNl = 1;                                  // 换行/行分隔候选 → 强制取证
            if (c >= 0x21 && c <= 0x7E) hasAscii = 1;
            else if ((c >= 0x4E00 && c <= 0x9FFF) ||    // CJK 统一汉字
                     (c >= 0x3000 && c <= 0x303F) ||    // CJK 标点
                     (c >= 0xFF00 && c <= 0xFFEF))      // 全角字符
                hasCjk = 1;
            nw = k + 1;
        }
        if (!hasCjk)
        {
            // 纯 ASCII / 无中文 → 不是玩家可见汉化文本，放行不动。
            // v16j：含换行码位的纯 ASCII 文本也强制记录（换行取证）；
            //       其余按 caller 分组配额记前若干条（判断是否误伤）。
            if (hasAscii && (hasNl || post_quota(callerRva, 0)))
            {
                char sb[256];
                wsprintfA(sb, "[POST-SKIP %ld] caller=%05X out=%08X len=%d nl=%d (no CJK)\n",
                          n, callerRva, outPtr, nw, hasNl);
                HANDLE hs = CreateFileA("CJK_post_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                                        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hs != INVALID_HANDLE_VALUE)
                {
                    SetFilePointer(hs, 0, NULL, FILE_END);
                    DWORD wn; WriteFile(hs, sb, (DWORD)lstrlenA(sb), &wn, NULL);
                    CloseHandle(hs);
                }
            }
            return;
        }

        int i = 0, fixed = 0;
        while (i < limit)
        {
            WORD w = out[i];
            if (w == 0) break;
            if (w == 0x00A7)                    // § 控制码 → 原样跳过（§Z22 / §C… 字号颜色）
            {
                i++;
                if (i >= limit || out[i] == 0) { out[i - 1] = 0x3000; break; }
                WORD code = out[i];
                // v16m：码字母必须是字母/数字才当控制码；§ 后跟非字母（如「正在加载§.」
                //   的省略号控制）→ § 转全角空格（0x00A7 无字形会渲染 @），后续字符正常处理
                if ((code >= 'A' && code <= 'Z') || (code >= 'a' && code <= 'z') || (code >= '0' && code <= '9'))
                {
                    i++;                                                        // 码字母（Z/C/…）
                    while (i < limit && out[i] >= 0x30 && out[i] <= 0x39) i++;  // 数字参数
                    continue;
                }
                out[i - 1] = 0x3000;
                continue;
            }
            if (w == 0x2E)              { out[i] = 0x3002;             fixed++; }  // v16n：半角点→全角句号（0xFF0E 字库无字形→@，0x3002 确定有）
            else if (w == 0x7C)         { /* v18g：引擎换行符 0x7C 保持原样（渲染器识别为换行）——v16o 的 →0x0A 是错误转换（渲染器不识别 0x0A → @，简报 @@ 根因！x64dbg 实证：源 0x0F7CFA26 = 7C00 7C00 正常，渲染缓冲被转成 0A00 0A00）*/ }
            else if (w >= 0x21 && w <= 0x7E) { out[i] = (WORD)(w + 0xFEE0); fixed++; }  // 半角 → 全角
            else if (w == 0x20)         { out[i] = 0x3000;             fixed++; }  // 半角空格 → 全角
            i++;
        }
        if (fixed) InterlockedExchangeAdd((volatile LONG*)&g_keyFixed, fixed);

        // ★ v16i 取证升级：记录【外层调用者 RVA】。
        //   0x20FB2 是 GameWorld 9 个 Localize_Str(CStr) 调用点之一，其上游还有
        //   021942 / 021E9B / 03319F / 0334CF / 05E3AF / 05E6DF / 0E3D37 / 0E3E37。
        //   若教程提示不走本点，这份日志会是空的 —— 那就直接锁定"要改 hook 点"。
        if ((hasAscii || hasCjk) && (hasNl || post_quota(callerRva, 0)))
        {
            // v16n：内容去重 —— 主菜单「新建游戏」每帧同内容会刷爆 caller 配额，
            //       同指纹（caller + 前 8 WORD）只记一次，让真实字幕/教程有配额
            static DWORD s_fp[48];
            static LONG  s_fpn = 0;
            DWORD fp = callerRva;
            for (int k = 0; k < 8 && k < i; k++) fp = fp * 31 + out[k];
            int dup = 0;
            for (int k = 0; k < s_fpn; k++) if (s_fp[k] == fp) { dup = 1; break; }
            if (dup) return;
            if (s_fpn < 48) s_fp[s_fpn++] = fp;
            char buf[1452];
            char* p = buf;
            p += wsprintfA(p, "[POST %ld] caller=%05X out=%08X len=%d fixed=%d nl=%d cap=%d\n",
                           n, callerRva, outPtr, i, fixed, hasNl, cap);
            for (int k = 0; k < 200 && k < i; k++)
                p += wsprintfA(p, "%04X ", (unsigned)out[k]);
            p += wsprintfA(p, "\n");
            HANDLE h = CreateFileA("CJK_post_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                                   NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE)
            {
                SetFilePointer(h, 0, NULL, FILE_END);
                DWORD written;
                WriteFile(h, buf, (DWORD)(p - buf), &written, NULL);
                CloseHandle(h);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
// ★ v16i：IAT hook —— 一次覆盖【所有】Localize_Str 调用点
//
// 【为什么放弃 v16h 的调用点 trampoline】
//   v16h 在调用点 0x20FB2 之后挂了后处理，实测 CJK_post_log.txt **一条都没生成**。
//   两个原因叠加：
//     (a) 后处理还带着字幕区间判据 [0x8D000,0x8F000]，而教程 HUD 提示的外层
//         返回地址根本不在字幕绘制区 → 被自己的判据挡掉；
//     (b) 更根本：GameWorld 有 **9 处** call Localize_Str(CStr)
//         （020FB2 / 021942 / 021E9B / 03319F / 0334CF / 05E3AF / 05E6DF /
//           0E3D37 / 0E3E37），教程提示大概率不走 0x20FB2 这一处。
//
// 【IAT 的好处】这些调用点全都 `call <thunk>`，而 thunk = `jmp [IAT]`
//   ⇒ 改写 IAT 一项 = 覆盖该变体的全部调用点；
//   ⇒ 无需 patch 代码字节、无需 naked 汇编、无寄存器纪律风险，纯 C + SEH。
//
// 【零风险校验】安装前用 GetProcAddress(MSystem.dll, 修饰名) 取真实导出地址，
//   与 IAT 槽当前值**逐项比对**，不相等一律不装 —— 宁可不修，绝不写错地址。
//
// 【签名】三个变体的 out 缓冲都是第 2 个参数，均为 __cdecl（修饰名 YA 开头）：
//     ?Localize_Str@@YAXVCStr@@PAGH@Z   void(CStr 按值8字节, WORD* out, int cap)
//     ?Localize_Str@@YAXPBDPAGH@Z       void(const char*  src, WORD* out, int cap)
//     ?Localize_Str@@YAXPBGPAGH@Z       void(const WORD*  src, WORD* out, int cap)
// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★

// IAT 槽位（pe_exports.py 解析导入表实测）
#define IAT_GW_CSTR_RVA    0x13E540u   // GameWorld  ?Localize_Str@@YAXVCStr@@PAGH@Z
#define IAT_GW_NARROW_RVA  0x13E534u   // GameWorld  ?Localize_Str@@YAXPBDPAGH@Z
#define IAT_GW_WIDE_RVA    0x13E530u   // GameWorld  ?Localize_Str@@YAXPBGPAGH@Z
#define IAT_GC_NARROW_RVA  0x1A72E4u   // GameClasses ?Localize_Str@@YAXPBDPAGH@Z
// v16k：Enclave.exe（主程序）也导入全部 3 个变体（教程 HUD 直接调 Localize_Str，
//       走 EXE 自己的 IAT → 之前从未 hook → 键名永不全角化 → "按@@@@@…"）。
// ★ v16l 修正：EXE 的 MSystem 导入描述符是【巨型列表】（~150 函数），FirstThunk=0x773B0 只是
//   起始，第一个函数是 ?Attrib_Push@CRC_Core。v16k 误用 0x773B0/B4/B8（= Attrib_Push/VB_Precache/
//   VB_GetVBIDInfo 的槽）→ 校验失败。精确遍历 INT 表得 Localize_Str 槽：
//   idx=39 → 0x7744C(CStr) / idx=42 → 0x77458(narrow) / idx=43 → 0x7745C(wide)
#define IAT_EXE_CSTR_RVA   0x7744Cu   // Enclave.exe ?Localize_Str@@YAXVCStr@@PAGH@Z
#define IAT_EXE_NARROW_RVA 0x77458u   // Enclave.exe ?Localize_Str@@YAXPBDPAGH@Z
#define IAT_EXE_WIDE_RVA   0x7745Cu   // Enclave.exe ?Localize_Str@@YAXPBGPAGH@Z
// v16m：渲染最终出口 GDI TextOutW —— 教程文本（不经 Localize_Str 槽，直接渲染路径）
//       的唯一观察点。GW 0x13E020 / EXE 0x7705C（导入表精确解析）
#define IAT_GW_TEXTOUTW_RVA  0x13E020u  // GameWorld  GDI32.TextOutW
#define IAT_EXE_TEXTOUTW_RVA 0x7705Cu   // Enclave.exe GDI32.TextOutW

typedef struct { DWORD lo, hi; } CStrVal;      // CStr 按值 = 8 字节

typedef void (__cdecl *pfn_LocCStr)(CStrVal, WORD*, int);
typedef void (__cdecl *pfn_LocNarrow)(const char*, WORD*, int);
typedef void (__cdecl *pfn_LocWide)(const WORD*, WORD*, int);

static pfn_LocCStr   g_origLocCStr   = NULL;
static pfn_LocNarrow g_origLocNarrow = NULL;
static pfn_LocWide   g_origLocWide   = NULL;
static pfn_LocNarrow g_origLocGcNarrow = NULL;   // GameClasses.dll 那一份

static int g_iatCount = 0;                       // 成功改写的 IAT 项数

// ★ v23q6 前向声明：§L 预展开（定义在下方——SubstituteKeys 入口 hook 区）
//   Localize_Str(wide) 入口预展开输入 src：§L → 键名全角写回 src 缓冲（只缩短、SEH、
//   hasCjk 保护）→ 引擎展开时无 §L → 无逐字形写入 → 渲染竞态消失（教程提示路径）
static void __declspec(noinline) cjk_subst_expand_input(DWORD textPtr);

static void __declspec(noinline) __cdecl my_LocCStr(CStrVal src, WORD* out, int cap)
{
    if (!g_origLocCStr) return;
    g_origLocCStr(src, out, cap);                            // 先让引擎完成 §L 展开
    InterlockedIncrement((volatile LONG*)&g_postHits);
    safe_fullwidth_expanded((DWORD)out,
                            (DWORD)_ReturnAddress() - g_gwBase, cap);
}

static void __declspec(noinline) __cdecl my_LocNarrow(const char* src, WORD* out, int cap)
{
    if (!g_origLocNarrow) return;
    g_origLocNarrow(src, out, cap);
    InterlockedIncrement((volatile LONG*)&g_postHits);
    safe_fullwidth_expanded((DWORD)out,
                            (DWORD)_ReturnAddress() - g_gwBase, cap);
}

static void __declspec(noinline) __cdecl my_LocWide(const WORD* src, WORD* out, int cap)
{
    if (!g_origLocWide) return;
    // ★ v23q6：调用引擎前【预展开输入 src】——§L → 键名全角写回（原子）→
    //   引擎展开时无 §L → 无逐字形写入 → 渲染并行读竞态消失（教程提示路径）
    //   只处理含 §L + 中文的文本（hasCjk 保护），无 §L 零开销。
    cjk_subst_expand_input((DWORD)src);
    g_origLocWide(src, out, cap);
    InterlockedIncrement((volatile LONG*)&g_postHits);
    safe_fullwidth_expanded((DWORD)out,
                            (DWORD)_ReturnAddress() - g_gwBase, cap);
}

static DWORD g_gcBase = 0;                       // GameClasses.dll 基址

static void __declspec(noinline) __cdecl my_LocGcNarrow(const char* src, WORD* out, int cap)
{
    if (!g_origLocGcNarrow) return;
    g_origLocGcNarrow(src, out, cap);
    InterlockedIncrement((volatile LONG*)&g_postHits);
    // 最高位置 1 标记「来自 GameClasses」，与 GameWorld 的 RVA 一眼可分
    safe_fullwidth_expanded((DWORD)out,
                            0x80000000u | ((DWORD)_ReturnAddress() - g_gcBase), cap);
}

// ★ v16k：Enclave.exe（主程序）的 3 个变体转发函数 —— callerRVA 以 g_exeBase 计算
static DWORD g_exeBase = 0;                      // Enclave.exe 基址（GetModuleHandle(NULL)）
static pfn_LocCStr   g_origExeLocCStr   = NULL;
static pfn_LocNarrow g_origExeLocNarrow = NULL;
static pfn_LocWide   g_origExeLocWide   = NULL;

static void __declspec(noinline) __cdecl my_LocExeCStr(CStrVal src, WORD* out, int cap)
{
    if (!g_origExeLocCStr) return;
    g_origExeLocCStr(src, out, cap);
    InterlockedIncrement((volatile LONG*)&g_postHits);
    safe_fullwidth_expanded((DWORD)out,
                            (DWORD)_ReturnAddress() - g_exeBase, cap);
}

static void __declspec(noinline) __cdecl my_LocExeNarrow(const char* src, WORD* out, int cap)
{
    if (!g_origExeLocNarrow) return;
    g_origExeLocNarrow(src, out, cap);
    InterlockedIncrement((volatile LONG*)&g_postHits);
    safe_fullwidth_expanded((DWORD)out,
                            (DWORD)_ReturnAddress() - g_exeBase, cap);
}

static void __declspec(noinline) __cdecl my_LocExeWide(const WORD* src, WORD* out, int cap)
{
    if (!g_origExeLocWide) return;
    // ★ v23q6：EXE 的 Localize_Str(wide)——教程 HUD 直接调 EXE IAT 走这里！
    //   预展开输入 src（§L → 键名全角写回）→ 引擎无 §L 可展 → 竞态消失
    cjk_subst_expand_input((DWORD)src);
    g_origExeLocWide(src, out, cap);
    InterlockedIncrement((volatile LONG*)&g_postHits);
    safe_fullwidth_expanded((DWORD)out,
                            (DWORD)_ReturnAddress() - g_exeBase, cap);
}

// ★ v16m：渲染最终出口 GDI TextOutW —— 教程文本（不经 Localize_Str 槽，直接渲染）
//       的唯一观察点。记录含中文的绘制文本（strong 判据，前 200 条）→ CJK_draw_log.txt
typedef int (__stdcall *pfn_TextOutW)(void* hdc, int x, int y, const WORD* lp, int c);
static pfn_TextOutW g_origTextOutW = NULL;

static void draw_log(const WORD* w, int c)
{
    static volatile LONG s_draw = 0;
    LONG n = InterlockedIncrement(&s_draw);
    int strong = 0, i;
    char buf[1600];
    char* p;
    HANDLE h;
    DWORD wn;
    if (n > 200) return;
    if (!w || c <= 0 || c > 512) return;
    __try
    {
        for (i = 0; i < c && i < 256; i++)
        {
            BYTE lo = (BYTE)w[i];
            if (lo < 0x20 || lo > 0x7E) strong++;
        }
        if (strong < 2) return;                       // 纯 ASCII 绘制 → 跳过（噪声）
        p = buf;
        p += wsprintfA(p, "[DRAW %ld] c=%d strong=%d\n", n, c, strong);
        for (i = 0; i < c && i < 256; i++)
            p += wsprintfA(p, "%04X ", (unsigned)w[i]);
        p += wsprintfA(p, "\n");
        h = CreateFileA("CJK_draw_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE)
        {
            SetFilePointer(h, 0, NULL, FILE_END);
            WriteFile(h, buf, (DWORD)(p - buf), &wn, NULL);
            CloseHandle(h);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
}

static int __stdcall my_TextOutW(void* hdc, int x, int y, const WORD* lp, int c)
{
    if (g_origTextOutW)
    {
        draw_log(lp, c);
        return g_origTextOutW(hdc, x, y, lp, c);
    }
    return 0;
}

// ★ v16p：hook MSystem Localize_Str(wide) 函数本体 —— 【终极统一】
//   所有 Localize_Str 变体（CStr/narrow/返回值）最终都调 wide（0x1010AD10）做 §L 展开，
//   wide 返回后 out（a2）= 最终文本（v16o [POST]「正在加载」实证）。
//   hook 本体 = 无论调用者走 IAT/直接 call/GetProcAddress，全角化都生效
//   —— 教程（走返回值变体绕过所有 IAT 槽）也被覆盖。
// ★ v16q 修正：真实导出 RVA = 0x10AD10（.text 从 RVA 0x1000 起，函数在 0x10AD10）！
//   v16p 误用 0xAD10 → patch 到 0x1000AD10（错误地址）→ hook 从未生效 → 实测「毫无变化」。
//   v16q 再修正：函数头 = sub esp,0x800（6 字节指令），trampoline 必须复制完整 6 字节。
#define MS_LOCALIZE_WIDE_RVA 0x10AD10u
#define WIDE_HDR_BYTES 6
static BYTE  g_origLocWideBody[WIDE_HDR_BYTES];
static void* g_wideTramp = NULL;
static DWORD g_msBase = 0;
static BOOL  g_hookedWideBody = FALSE;
static DWORD g_wideOrigRet = 0;   // ★ v16r：hook_impl 保存的原调用者返回地址
static volatile LONG g_widePostBusy = 0;   // ★ v23p：post 重入锁（嵌套/多线程调用保护）

static void __cdecl cjk_loc_wide_post_c(const WORD* a1, WORD* out, int cap)
{
    // ★ v16r：caller 用 hook_impl 保存的 g_wideOrigRet（_ReturnAddress() 是 post 内地址，无意义）
    safe_fullwidth_expanded((DWORD)out,
                            g_wideOrigRet - g_msBase, cap);
}

// 原函数 ret 后被改到的 post（独立 naked 函数，避免编译器 C1001）
// ★ v16r：post 是被原函数 ret 跳入的，进入时栈顶是参数 a1 而非返回地址，
//   结尾必须 jmp 回保存的原调用者（参数留给 __cdecl 调用者清理）——
//   之前用 ret 会弹出 a1 当返回地址 → 跳到垃圾地址 → 崩溃（v16q 实测）。
static void __declspec(naked) cjk_loc_wide_post(void)
{
    __asm
    {
        pushad
        mov  eax, [esp + 0x20]                   ; a1
        mov  ecx, [esp + 0x24]                   ; out
        mov  edx, [esp + 0x28]                   ; cap
        push edx
        push ecx
        push eax
        call cjk_loc_wide_post_c
        add  esp, 12
        popad
        ; ★ v23p：先清重入锁再跳回（保证嵌套调用外层 post 也能正确取到自己的返回地址）
        mov  eax, g_widePostBusy
        mov  g_widePostBusy, 0
        jmp  dword ptr [g_wideOrigRet]           ; 回原调用者（栈上参数保留，调用者清栈）
    }
}
static DWORD cjk_loc_wide_post_addr = (DWORD)cjk_loc_wide_post;

static void __declspec(naked) cjk_loc_wide_hook_impl(void)
{
    __asm
    {
        ; 进入：栈 [ret, a1, out, cap]
        ; ★ v23p：重入保护 —— 若已有 post 在途（嵌套/多线程调用 Localize_Str(wide)），
        ;   不装 post、原样走原函数（返回地址不变），避免 g_wideOrigRet 被覆盖 → 外层
        ;   post jmp 错地址崩溃。内层文本不处理后返回，代价极小（主菜单高频调用）。
        cmp  dword ptr [g_widePostBusy], 0
        jne  wh_reentrant
        mov  dword ptr [g_widePostBusy], 1
        push ebp
        mov  ebp, esp
        push eax
        mov  ecx, cjk_loc_wide_post_addr         ; post 地址
        mov  eax, [ebp + 4]                      ; 原返回地址
        mov  g_wideOrigRet, eax                  ; ★ v16r：保存 → post 用 jmp 回来
        mov  [ebp + 4], ecx                      ; 替换 → 原函数 ret 后先到 post
        pop  eax
        pop  ebp
        jmp  dword ptr [g_wideTramp]             ; 跳板：原 5 字节 + jmp 原函数+5
    wh_reentrant:
        jmp  dword ptr [g_wideTramp]             ; 重入：原样走原函数（不装 post）
    }
}

static int install_wide_body_hook(void)
{
    BYTE* entry;
    DWORD oldProt;
    int i;
    // 期望函数头：sub esp,0x800（81 EC 00 08 00 00）
    static const BYTE expect[WIDE_HDR_BYTES] = {0x81, 0xEC, 0x00, 0x08, 0x00, 0x00};
    if (g_hookedWideBody) return 1;
    g_msBase = (DWORD)GetModuleHandleA("MSystem.dll");
    if (!g_msBase) return 0;
    entry = (BYTE*)(g_msBase + MS_LOCALIZE_WIDE_RVA);
    memcpy(g_origLocWideBody, entry, WIDE_HDR_BYTES);
    for (i = 0; i < WIDE_HDR_BYTES; i++)
        if (g_origLocWideBody[i] != expect[i])
        {
            log_msg("[CJK] wide 落点核验失败：%02X %02X %02X %02X %02X %02X，跳过\n",
                    g_origLocWideBody[0], g_origLocWideBody[1], g_origLocWideBody[2],
                    g_origLocWideBody[3], g_origLocWideBody[4], g_origLocWideBody[5]);
            return 0;
        }
    g_wideTramp = VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_wideTramp) return 0;
    memcpy(g_wideTramp, g_origLocWideBody, WIDE_HDR_BYTES);
    ((BYTE*)g_wideTramp)[WIDE_HDR_BYTES] = 0xE9;
    *(DWORD*)((BYTE*)g_wideTramp + WIDE_HDR_BYTES + 1) =
        ((DWORD)entry + WIDE_HDR_BYTES) - ((DWORD)g_wideTramp + WIDE_HDR_BYTES + 5);
    if (!VirtualProtect(entry, WIDE_HDR_BYTES, PAGE_EXECUTE_READWRITE, &oldProt)) return 0;
    entry[0] = 0xE9;
    *(DWORD*)(entry + 1) = (DWORD)cjk_loc_wide_hook_impl - ((DWORD)entry + 5);
    entry[5] = 0x90;   // 第 6 字节（原 sub esp 的第 6 字节）→ nop
    VirtualProtect(entry, WIDE_HDR_BYTES, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), entry, WIDE_HDR_BYTES);
    g_hookedWideBody = TRUE;
    log_msg("[CJK] v16q Localize_Str(wide) 本体 hook：%08X -> %08X（终极统一，6B trampoline）\n",
            (DWORD)entry, (DWORD)cjk_loc_wide_hook_impl);
    return 1;
}

// ═══════════════════════════════════════════════════════════════════════
// ★ v16q：hook Localize_FindKeyValue（MSystem 导出 RVA 0x10A6A0，VA 0x1010A6A0）
//   —— §L 键名查表点！教程 HUD「按§LTUTORIAL_PRIMARY取出武器」由渲染器调它查
//   STRINGTABLES\DYNAMIC，展开产物 = 半角 ASCII 键名（注册值 = "'键名'"）→
//   字库无半角/全角字母字形 → 渲染 @。
//   在函数本体 post 里：日志（caller/key/数据）+ 键名→汉字映射（字库确定有汉字字形）。
//   ★ 与 wide 本体 hook 的关系：FindKeyValue 在 Localize_Str 内部也被调用（§L 展开），
//     但教程渲染路径绕过 Localize_Str 直接调 FindKeyValue —— 这里是教程键名的唯一通路。
// ═══════════════════════════════════════════════════════════════════════
#define MS_FINDKEY_RVA 0x10A6A0u
#define FINDKEY_HDR_BYTES 7
static BYTE  g_origFindKeyBody[FINDKEY_HDR_BYTES];
static void* g_findKeyTramp = NULL;
static BOOL  g_hookedFindKey = FALSE;
static DWORD g_keyCaller = 0;              // hook_impl 保存的原调用者返回地址
static volatile LONG g_keyPostBusy = 0;    // ★ v23p：FindKeyValue post 重入锁（嵌套/多线程保护）

// 大小写不敏感 ASCII 比较（免 string.h 依赖）。maxn 上限防 a2 非 0 结尾越界读。
static int key_eq_n(const char* a, const char* b, int maxn)
{
    int n = 0;
    while (n < maxn && *a && *b)
    {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
        a++; b++; n++;
    }
    return (n == maxn || (*a == 0 && *b == 0)) ? 1 : 0;
}
static int key_eq(const char* a, const char* b)
{
    return key_eq_n(a, b, 39);
}

// 键名 → 汉字映射表（UTF-16 码位数组，规避源文件编码问题）
// 全部用字库确定有的汉字（cfg 字符集实证）
static const WORD W_MOUSE_LEFT[]  = {0x9F20,0x6807,0x5DE6,0x952E,0};   // 鼠标左键
static const WORD W_MOUSE_RIGHT[] = {0x9F20,0x6807,0x53F3,0x952E,0};   // 鼠标右键
static const WORD W_SPACE[]       = {0x7A7A,0x683C,0x952E,0};          // 空格键
static const WORD W_SHIFT[]       = {0x4E0A,0x6863,0x952E,0};          // 上档键
static const WORD W_CTRL[]        = {0x63A7,0x5236,0x952E,0};          // 控制键
static const WORD W_ALT[]         = {0x66FF,0x6362,0x952E,0};          // 替换键
static const WORD W_TAB[]         = {0x8DF3,0x683C,0x952E,0};          // 跳格键
static const WORD W_ENTER[]       = {0x56DE,0x8F66,0x952E,0};          // 回车键
static const WORD W_ESC[]         = {0x9000,0x51FA,0x952E,0};          // 退出键
static const WORD W_BACKSPACE[]   = {0x9000,0x683C,0x952E,0};          // 退格键
static const WORD W_DELETE[]      = {0x5220,0x9664,0x952E,0};          // 删除键
static const WORD W_INSERT[]      = {0x63D2,0x5165,0x952E,0};          // 插入键
static const WORD W_HOME[]        = {0x8D77,0x59CB,0x952E,0};          // 起始键
static const WORD W_END[]         = {0x7ED3,0x675F,0x952E,0};          // 结束键
static const WORD W_PGUP[]        = {0x4E0A,0x7FFB,0x9875,0};          // 上翻页
static const WORD W_PGDN[]        = {0x4E0B,0x7FFB,0x9875,0};          // 下翻页
static const WORD W_UP[]          = {0x4E0A,0x7BAD,0x5934,0};          // 上箭头
static const WORD W_DOWN[]        = {0x4E0B,0x7BAD,0x5934,0};          // 下箭头
static const WORD W_LEFT[]        = {0x5DE6,0x7BAD,0x5934,0};          // 左箭头
static const WORD W_RIGHT[]       = {0x53F3,0x7BAD,0x5934,0};          // 右箭头
static const WORD W_MMOVE[]       = {0x9F20,0x6807,0x79FB,0x52A8,0};   // 鼠标移动
// 单字母键 → 动作名（教程默认绑定；字库无字母字形，映射汉字保证可读）
static const WORD W_KEY_W[]       = {0x524D,0x8FDB,0x952E,0};          // 前进键
static const WORD W_KEY_A[]       = {0x5DE6,0x79FB,0x952E,0};          // 左移键
static const WORD W_KEY_S[]       = {0x540E,0x9000,0x952E,0};          // 后退键
static const WORD W_KEY_D[]       = {0x53F3,0x79FB,0x952E,0};          // 右移键
static const WORD W_KEY_Q[]       = {0x5207,0x6362,0x6B66,0x5668,0x952E,0};  // 切换武器键
static const WORD W_KEY_E[]       = {0x5207,0x6362,0x7269,0x54C1,0x952E,0};  // 切换物品键
static const WORD W_KEY_C[]       = {0x8E72,0x4E0B,0x952E,0};          // 蹲下键
static const WORD W_KEY_F[]       = {0x559D,0x836F,0x6C34,0x952E,0};   // 喝药水键
static const WORD W_KEY_J[]       = {0x83DC,0x5355,0x952E,0};          // 菜单键
static const WORD W_KEY_G[]       = {0x5207,0x6362,0x89C6,0x89D2,0x952E,0};  // 切换视角键

typedef struct { const char* name; const WORD* repl; } KeyMapEntry;
static const KeyMapEntry KEY_MAP[] = {
    {"MOUSE1", W_MOUSE_LEFT}, {"MOUSEBTN1", W_MOUSE_LEFT}, {"MOUSEBUTTON1", W_MOUSE_LEFT}, {"MOUSE_LEFT", W_MOUSE_LEFT}, {"LMOUSE", W_MOUSE_LEFT},
    {"MOUSE2", W_MOUSE_RIGHT}, {"MOUSEBTN2", W_MOUSE_RIGHT}, {"MOUSEBUTTON2", W_MOUSE_RIGHT}, {"MOUSE_RIGHT", W_MOUSE_RIGHT}, {"RMOUSE", W_MOUSE_RIGHT},
    {"SPACE", W_SPACE}, {"SPACEBAR", W_SPACE},
    {"SHIFT", W_SHIFT}, {"LSHIFT", W_SHIFT}, {"RSHIFT", W_SHIFT},
    {"CTRL", W_CTRL}, {"CONTROL", W_CTRL}, {"LCONTROL", W_CTRL}, {"RCONTROL", W_CTRL},
    {"ALT", W_ALT}, {"LMENU", W_ALT}, {"RMENU", W_ALT},
    {"TAB", W_TAB},
    {"ENTER", W_ENTER}, {"RETURN", W_ENTER}, {"KP_ENTER", W_ENTER},
    {"ESC", W_ESC}, {"ESCAPE", W_ESC},
    {"BACKSPACE", W_BACKSPACE}, {"BACK", W_BACKSPACE},
    {"DELETE", W_DELETE}, {"DEL", W_DELETE},
    {"INSERT", W_INSERT}, {"INS", W_INSERT},
    {"HOME", W_HOME}, {"END", W_END},
    {"PAGEUP", W_PGUP}, {"PGUP", W_PGUP}, {"PAGEDOWN", W_PGDN}, {"PGDN", W_PGDN},
    {"UP", W_UP}, {"UPARROW", W_UP}, {"DOWN", W_DOWN}, {"DOWNARROW", W_DOWN},
    {"LEFT", W_LEFT}, {"LEFTARROW", W_LEFT}, {"RIGHT", W_RIGHT}, {"RIGHTARROW", W_RIGHT},
    {"MOUSEMOVE", W_MMOVE},
    {"W", W_KEY_W}, {"A", W_KEY_A}, {"S", W_KEY_S}, {"D", W_KEY_D},
    {"Q", W_KEY_Q}, {"E", W_KEY_E}, {"C", W_KEY_C}, {"F", W_KEY_F},
    {"J", W_KEY_J}, {"G", W_KEY_G},
};

// 查映射：tok 为 ASCII 字母数字串（≤38），命中返回替换串（WORD*），否则 NULL
static const WORD* key_map_lookup(const char* tok)
{
    int i;
    for (i = 0; i < (int)(sizeof(KEY_MAP) / sizeof(KEY_MAP[0])); i++)
    {
        if (key_eq(KEY_MAP[i].name, tok))
            return KEY_MAP[i].repl;
    }
    return NULL;
}

// 在 UTF-16 文本 t 中替换键名：识别 [引号]字母数字串[引号]，命中映射则替换为汉字并剥离引号。
// 变长处理：memmove 后续文本（含终止符）。边界：maxw WORD。
// ★ v23p 崩溃修复（51872 dump 实证：dsound 音频线程 free/malloc 时 AV → 堆损坏延迟爆发）：
//   v16x 只修了 strip 分支，**memmove 变长分支仍会越界写**：
//     ① `while (t[total]) total++` 无上限扫描（缓冲区终止符缺失时扫出边界）
//     ② `rlen > delta`（如 Q→切换武器键 5 WORD、1 字母变 5 汉字）时 memmove 右移
//       超出缓冲实际容量 → 静默写坏堆/栈 → 数分钟后任意线程 free 时崩。
//   ⇒ v23p：扫描限长 + **只允许等长/缩短替换（rlen <= delta）**，变长一律跳过（原样保留 token）。
static void key_replace(WORD* t, int maxw)
{
    int i = 0;
    while (i < maxw && t[i])
    {
        WORD c = t[i];
        if ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A))
        {
            int strip_lead = (i > 0 && t[i - 1] == 0x27) ? 1 : 0;
            int j = i, tl = 0;
            char tok[40];
            while (j < maxw && t[j] &&
                   ((t[j] >= 0x30 && t[j] <= 0x39) || (t[j] >= 0x41 && t[j] <= 0x5A) ||
                    (t[j] >= 0x61 && t[j] <= 0x7A)) && tl < 38)
            {
                tok[tl++] = (char)t[j];
                j++;
            }
            tok[tl] = 0;
            int strip_trail = (j < maxw && t[j] == 0x27) ? 1 : 0;
            const WORD* repl = key_map_lookup(tok);
            if (repl)
            {
                int rlen = 0, newstart, oldend, total, delta, k;
                while (repl[rlen]) rlen++;
                newstart = i - strip_lead;
                oldend = j + strip_trail;
                total = 0;
                while (total < maxw && t[total]) total++;    // ★ v23p：限长扫描（原无上限）
                delta = oldend - newstart;
                // ★ v23p：只允许等长/缩短替换（memmove 左移，目标区在原文本内，绝不越界）。
                //   变长（rlen > delta）会右移越过缓冲容量 → 越界写 → 跳过（原样保留）。
                if (rlen < delta && oldend <= total)
                {
                    memmove(t + newstart + rlen, t + oldend,
                            (total + 1 - oldend) * sizeof(WORD));
                }
                if (rlen <= delta && oldend <= total)
                {
                    for (k = 0; k < rlen; k++) t[newstart + k] = repl[k];
                    i = newstart + rlen;
                    continue;
                }
                i = j;                                      // 变长：放弃替换
                continue;
            }
            // ★ v16x 修正（v16w 崩溃）：未命中映射但被引号包裹（= 键名，如 'MOUSEBUTTON1'）→
            //   前/后引号 → 全角空格 0x3000，token 字母数字 → 全角（+0xFEE0）。
            //   全部【等长原地替换，零 memmove、零移动】——v16w 用 memmove 覆盖了 token 再全角化
            //   错误位置，破坏文本结构 → ntdll 内存函数崩溃（dmp 实证 ExceptionAddr=ntdll）。
            //   新字库（GB2312 全字符集）A3 区有全角字母数字字形（v16u 的 ′ 实证）。
            if (strip_lead || strip_trail)
            {
                int q;
                if (strip_lead && i > 0)
                    t[i - 1] = 0x3000;                      // 前引号 → 全角空格（等长）
                if (strip_trail && j < maxw)
                    t[j] = 0x3000;                          // 后引号 → 全角空格（等长）
                for (q = 0; q < tl && i + q < maxw; q++)
                {
                    WORD c = t[i + q];
                    if (c >= 0x21 && c <= 0x7E)
                        t[i + q] = (WORD)(c + 0xFEE0);      // 半角字母数字 → 全角（等长）
                }
                i = j + strip_trail;
                continue;
            }
            i = j;
        }
        else
        {
            i++;
        }
    }
}

// post：原函数 ret 后被跳入。栈 [a1, a2]（__cdecl，调用者未清栈）。
static void __cdecl cjk_findkey_post_c(DWORD a1, DWORD a2)
{
    static char s_keySeen[64][40];
    static int  s_keySeenN = 0;
    static volatile LONG s_n = 0;
    char sb[900], *p;
    WORD* data;
    const char* k;
    LONG n;
    int i, kl, seenCnt;
    if (!a1) return;
    __try
    {
        data = *(WORD**)(a1 + 4);
        if (!data || data == (WORD*)-2) return;
        k = (const char*)a2;
        kl = 0;
        __try { while (k[kl] && kl < 40) kl++; }
        __except (EXCEPTION_EXECUTE_HANDLER) { kl = 0; }
        // ★ v16x：**先替换**（永远执行，不因日志配额跳过）——
        //   v16w 把 key_replace 放在配额判断之后，同 key 第 4 次查表起不再替换 →
        //   STD_LOADING 每帧查表刷满后，教程键名原样渲染（@@@ 根源之一）。
        //   键名→汉字映射。数据 = [标志 WORD(bit15 宽)][UTF-16 正文] → 正文从 data+1 起。
        key_replace(data + 1, 512);
        // ★ v16w：per-key 配额——每个 key 最多记 3 次（替换前/后配对）。
        //   v16v 全局 300 条被加载界面 STD_LOADING（每帧查表）刷爆 → 教程（游戏内）的
        //   FindKeyValue 调用被配额掩盖 → 「教程不走 FindKeyValue」结论不可靠。
        //   按 key 计数，同 key 第 4 次起只替换不记录 → STD_LOADING 占 3 条，TUTORIAL_* 必可记录。
        seenCnt = 0;
        for (i = 0; i < s_keySeenN && i < 64; i++)
            if (key_eq(s_keySeen[i], k))
            {
                seenCnt++;
                if (seenCnt >= 3) return;
            }
        if (s_keySeenN < 64)
        {
            int cp = kl < 39 ? kl : 39;
            for (i = 0; i < cp; i++) s_keySeen[s_keySeenN][i] = k[i];
            s_keySeen[s_keySeenN][cp] = 0;
            s_keySeenN++;
        }
        n = InterlockedIncrement(&s_n);
        if (n > 400) return;
        // 替换前 dump
        p = sb;
        p += wsprintfA(p, "[KEY %ld] caller=%08X key=", n, g_keyCaller - g_msBase);
        for (i = 0; i < kl; i++)
            p += wsprintfA(p, "%c", (k[i] >= 0x20 && k[i] < 0x7F) ? k[i] : '.');
        p += wsprintfA(p, " out=%08X | ", a1);
        for (i = 0; i < 20; i++)
            p += wsprintfA(p, "%04X ", (unsigned)data[i]);
        p += wsprintfA(p, "\n");
        {
            HANDLE h = CreateFileA("CJK_key_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                                   NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE)
            {
                SetFilePointer(h, 0, NULL, FILE_END);
                DWORD wn; WriteFile(h, sb, (DWORD)(p - sb), &wn, NULL);
                CloseHandle(h);
            }
        }
        // 替换后 dump
        p = sb;
        p += wsprintfA(p, "[KEY->%ld]       | ", n);
        for (i = 0; i < 20; i++)
            p += wsprintfA(p, "%04X ", (unsigned)data[i]);
        p += wsprintfA(p, "\n");
        {
            HANDLE h = CreateFileA("CJK_key_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                                   NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE)
            {
                SetFilePointer(h, 0, NULL, FILE_END);
                DWORD wn; WriteFile(h, sb, (DWORD)(p - sb), &wn, NULL);
                CloseHandle(h);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
}

static void __declspec(naked) cjk_findkey_post(void)
{
    __asm
    {
        pushad
        mov  eax, [esp + 0x20]                   ; a1
        mov  ecx, [esp + 0x24]                   ; a2
        push ecx
        push eax
        call cjk_findkey_post_c
        add  esp, 8
        popad
        ; ★ v23p：先清重入锁再跳回
        mov  eax, g_keyPostBusy
        mov  g_keyPostBusy, 0
        jmp  dword ptr [g_keyCaller]             ; ★ v16r：jmp 回原调用者（参数留给调用者清）
    }
}
static DWORD cjk_findkey_post_addr = (DWORD)cjk_findkey_post;

static void __declspec(naked) cjk_findkey_hook_impl(void)
{
    __asm
    {
        ; 进入：栈 [ret_to_caller, a1, a2]
        ; ★ v23p：重入保护（嵌套/多线程调用 FindKeyValue → g_keyCaller 被覆盖 →
        ;   post jmp 错地址崩溃）。忙则原样走原函数。
        cmp  dword ptr [g_keyPostBusy], 0
        jne  fk_reentrant
        mov  dword ptr [g_keyPostBusy], 1
        push ebp
        mov  ebp, esp
        push eax
        mov  ecx, cjk_findkey_post_addr          ; post 地址
        mov  eax, [ebp + 4]                      ; 原返回地址（= 原函数调用者）
        mov  g_keyCaller, eax                    ; 保存 → post 里算 caller RVA
        mov  [ebp + 4], ecx                      ; 替换 → 原函数 ret 后先到 post
        pop  eax
        pop  ebp
        jmp  dword ptr [g_findKeyTramp]          ; 跳板：原 5 字节 + jmp 原函数+5
    fk_reentrant:
        jmp  dword ptr [g_findKeyTramp]          ; 重入：原样走原函数（不装 post）
    }
}

static int install_findkey_hook(void)
{
    BYTE* entry;
    DWORD oldProt;
    HMODULE hMs;
    int i;
    // 期望函数头：push -1（6A FF）+ push SEHhandler（68 DA 80 11 10）＝7 字节完整两条指令
    static const BYTE expect[FINDKEY_HDR_BYTES] = {0x6A, 0xFF, 0x68, 0xDA, 0x80, 0x11, 0x10};
    if (g_hookedFindKey) return 1;
    hMs = GetModuleHandleA("MSystem.dll");
    if (!hMs) return 0;
    g_msBase = (DWORD)hMs;
    entry = (BYTE*)(g_msBase + MS_FINDKEY_RVA);
    memcpy(g_origFindKeyBody, entry, FINDKEY_HDR_BYTES);
    for (i = 0; i < FINDKEY_HDR_BYTES; i++)
        if (g_origFindKeyBody[i] != expect[i])
        {
            log_msg("[CJK] FindKeyValue 落点核验失败：%02X %02X %02X %02X %02X %02X %02X，跳过\n",
                    g_origFindKeyBody[0], g_origFindKeyBody[1], g_origFindKeyBody[2],
                    g_origFindKeyBody[3], g_origFindKeyBody[4], g_origFindKeyBody[5],
                    g_origFindKeyBody[6]);
            return 0;
        }
    g_findKeyTramp = VirtualAlloc(NULL, 20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_findKeyTramp) return 0;
    memcpy(g_findKeyTramp, g_origFindKeyBody, FINDKEY_HDR_BYTES);
    ((BYTE*)g_findKeyTramp)[FINDKEY_HDR_BYTES] = 0xE9;
    *(DWORD*)((BYTE*)g_findKeyTramp + FINDKEY_HDR_BYTES + 1) =
        ((DWORD)entry + FINDKEY_HDR_BYTES) - ((DWORD)g_findKeyTramp + FINDKEY_HDR_BYTES + 5);
    if (!VirtualProtect(entry, FINDKEY_HDR_BYTES, PAGE_EXECUTE_READWRITE, &oldProt)) return 0;
    entry[0] = 0xE9;
    *(DWORD*)(entry + 1) = (DWORD)cjk_findkey_hook_impl - ((DWORD)entry + 5);
    entry[5] = 0x90;   // 原第 6 字节（push imm32 的第 3 字节）→ nop
    entry[6] = 0x90;   // 原第 7 字节 → nop
    VirtualProtect(entry, FINDKEY_HDR_BYTES, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), entry, FINDKEY_HDR_BYTES);
    g_hookedFindKey = TRUE;
    log_msg("[CJK] v16q FindKeyValue 本体 hook：%08X -> %08X（教程 §L 键名查表点，7B trampoline）\n",
            (DWORD)entry, (DWORD)cjk_findkey_hook_impl);
    return 1;
}

// ═══════════════════════════════════════════════════════════════════════
// ★ v16y：hook CKeyContainer::GetKeyName（MCCdyn RVA 0x34570）——教程键名显示名唯一源头！
//   __thiscall CStr GetKeyName(CKeyContainer* this, int index)
//   （CStr 按值返回 = hidden ret ptr）函数头 = 51 8B 41 0C 85 C0（6 字节），尾 ret 8。
//   eax = ret_ptr（CStr* 8 字节 [vtable][data_ptr]）→ post 里全角化/汉字映射键名。
//   ★ 为什么是它：教程 HUD 的 §L 键名（'MOUSEBUTTON1'）来自 STRINGTABLES\DYNAMIC 注册值，
//     注册时 EXE 用 vtable+376（= CKeyContainer 查键名显示名）获取 → hook 它的返回 = 源头替换！
// ═══════════════════════════════════════════════════════════════════════
#define MCC_KEYNAME_RVA 0x34570u
#define KEYNAME_HDR_BYTES 6
static BYTE  g_origKeyNameBody[KEYNAME_HDR_BYTES];
static void* g_keyNameTramp = NULL;
static BOOL  g_hookedKeyName = FALSE;
static DWORD g_keyNameOrigRet = 0;
static DWORD g_mccBase = 0;

// ★ v17a：post 改【只读诊断】——v16z 崩溃根因：GetKeyName 返回的 CStr 走浅拷贝，
//   data_ptr 直接指向 MXR 内部共享缓冲（caller=0x46F67BE=MXR RVA 0x367BE），
//   v16y/v16z 对 data[1..255] 全角化【写入】→ 越界破坏 MXR 内部数据 →
//   MXR 0x6af6（CStr 哈希 mov [edx],ax）用被破坏指针 → 崩（两次 dmp 同点实锤）。
//   ⇒ 本 post 零写入：只记录返回 CStr 的真实数据（确认它到底是不是教程键名源）。
static void __cdecl cjk_keyname_post_c(DWORD retPtr)
{
    static volatile LONG s_n = 0;
    char sb[700], *p;
    WORD* data;
    LONG n;
    int i;
    if (!retPtr) return;
    __try
    {
        data = *(WORD**)(retPtr + 4);
        if (!data || data == (WORD*)-2) return;
        // 只读：前 16 WORD 快照（上限收紧，防越界读）
        n = InterlockedIncrement(&s_n);
        if (n <= 200)
        {
            p = sb;
            p += wsprintfA(p, "[KEYNAME %ld] caller=%08X ret=%08X | ", n,
                           g_keyNameOrigRet - g_mccBase, retPtr);
            for (i = 0; i < 16; i++)
                p += wsprintfA(p, "%04X ", (unsigned)data[i]);
            p += wsprintfA(p, "\n");
            {
                HANDLE h = CreateFileA("CJK_keyname_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                                       NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (h != INVALID_HANDLE_VALUE)
                {
                    SetFilePointer(h, 0, NULL, FILE_END);
                    DWORD wn; WriteFile(h, sb, (DWORD)(p - sb), &wn, NULL);
                    CloseHandle(h);
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
}

// 原函数 ret 8 后跳入的 post。进入时 eax = ret_ptr（原函数 mov eax,esi 后 ret 8）。
// 栈：原函数 ret 8 已弹返回地址并清 ret_ptr+index → 栈顶 = 调用者栈 → jmp 回原调用者（v16r 教训）
static void __declspec(naked) cjk_keyname_post(void)
{
    __asm
    {
        pushad
        mov  eax, [esp + 0x1C]           ; 原 eax = ret_ptr（CStr*）
        push eax
        call cjk_keyname_post_c
        add  esp, 4
        popad
        jmp  dword ptr [g_keyNameOrigRet] ; ★ v16r：不 ret，jmp 回保存的原调用者
    }
}
static DWORD cjk_keyname_post_addr = (DWORD)cjk_keyname_post;

static void __declspec(naked) cjk_keyname_hook_impl(void)
{
    __asm
    {
        ; 进入：栈 [ret_to_caller, ret_ptr, index]，this = ecx（__thiscall！）
        ; ★ v16z：绝不能用 ecx 传 post 地址——会覆盖 this，原函数 [ecx+0xC] 崩溃
        ;   （v16y 崩溃：dmp ExceptionAddr=0x3458d = GetKeyName 内 cmp edi,[eax+4]）
        push ebp
        mov  ebp, esp
        push eax
        mov  eax, [ebp + 4]              ; 原返回地址
        mov  g_keyNameOrigRet, eax       ; 保存 → post 里 jmp 回
        mov  eax, cjk_keyname_post_addr  ; post 地址
        mov  [ebp + 4], eax              ; 替换 → 原函数 ret 8 后先到 post
        pop  eax
        pop  ebp
        jmp  dword ptr [g_keyNameTramp]  ; 跳板：原 6 字节 + jmp 原函数+6（this 仍在 ecx）
    }
}

static int install_keyname_hook(void)
{
    BYTE* entry;
    DWORD oldProt;
    HMODULE hMc;
    int i;
    static const BYTE expect[KEYNAME_HDR_BYTES] = {0x51, 0x8B, 0x41, 0x0C, 0x85, 0xC0};
    if (g_hookedKeyName) return 1;
    hMc = GetModuleHandleA("MCCdyn.dll");
    if (!hMc) return 0;
    g_mccBase = (DWORD)hMc;
    entry = (BYTE*)hMc + MCC_KEYNAME_RVA;
    memcpy(g_origKeyNameBody, entry, KEYNAME_HDR_BYTES);
    for (i = 0; i < KEYNAME_HDR_BYTES; i++)
        if (g_origKeyNameBody[i] != expect[i])
        {
            log_msg("[CJK] GetKeyName 落点核验失败：%02X %02X %02X %02X %02X %02X，跳过\n",
                    g_origKeyNameBody[0], g_origKeyNameBody[1], g_origKeyNameBody[2],
                    g_origKeyNameBody[3], g_origKeyNameBody[4], g_origKeyNameBody[5]);
            return 0;
        }
    g_keyNameTramp = VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_keyNameTramp) return 0;
    memcpy(g_keyNameTramp, g_origKeyNameBody, KEYNAME_HDR_BYTES);
    ((BYTE*)g_keyNameTramp)[KEYNAME_HDR_BYTES] = 0xE9;
    *(DWORD*)((BYTE*)g_keyNameTramp + KEYNAME_HDR_BYTES + 1) =
        ((DWORD)entry + KEYNAME_HDR_BYTES) - ((DWORD)g_keyNameTramp + KEYNAME_HDR_BYTES + 5);
    if (!VirtualProtect(entry, KEYNAME_HDR_BYTES, PAGE_EXECUTE_READWRITE, &oldProt)) return 0;
    entry[0] = 0xE9;
    *(DWORD*)(entry + 1) = (DWORD)cjk_keyname_hook_impl - ((DWORD)entry + 5);
    entry[5] = 0x90;   // 原第 6 字节（test eax,eax 第 2 字节）→ nop
    VirtualProtect(entry, KEYNAME_HDR_BYTES, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), entry, KEYNAME_HDR_BYTES);
    g_hookedKeyName = TRUE;
    log_msg("[CJK] v16y CKeyContainer::GetKeyName 本体 hook：%08X -> %08X（教程键名源头）\n",
            (DWORD)entry, (DWORD)cjk_keyname_hook_impl);
    return 1;
}

// ═══════════════════════════════════════════════════════════════════════
// ★ v17b：hook CRegistry_Dynamic::SetThisKey(PBD,VCStr)（MSystem RVA 0xA9670）
//   —— EXE 教程键名注册点！0x407553 等 7 处 call [eax+0x124] = vtable+292 = 本函数
//   （IDA 实证：vtable 0x1012E74C 第 73 槽 = 0x100A9670，0x124/4 = 73）。
//   __thiscall SetThisKey(CRegistry_Dynamic* this, const char* key, CStr value)
//   栈 [ret, key, value(8B)]。value = 注册值（如 'MOUSEBUTTON1' 带引号，写入 DYNAMIC stringtable）。
//   前置只读：记录 key + value data 快照 → CJK_setkey_log.txt（一锤定音注册值格式）
//   函数头 = 64 A1 00 00 00 00（mov eax, fs:0，6 字节完整指令）
//   ⚠️ 前置模式（v16t 同款）：hook_impl 不碰返回地址、pushad/popad 保护寄存器、
//      this 留在 ecx（popad 恢复）→ 零崩溃风险。
// ═══════════════════════════════════════════════════════════════════════
#define MS_SETKEY_RVA 0xA9670u
#define SETKEY_HDR_BYTES 6
static BYTE  g_origSetKeyBody[SETKEY_HDR_BYTES];
static void* g_setKeyTramp = NULL;
static BOOL  g_hookedSetKey = FALSE;

// 前置只读记录：key + value CStr 数据快照 + 进入时原始栈（v17c 定案栈布局）
// r0=ret, r1=key, r2=valueLo, r3=valueHi（hook_impl 从 pushad 后 [esp+0x24..0x30] 取）
static void __cdecl cjk_setkey_pre_c(DWORD valueLo, const char* key,
                                     DWORD r0, DWORD r1, DWORD r2, DWORD r3)
{
    static volatile LONG s_n = 0;
    static CRITICAL_SECTION s_cs;
    static BOOL s_csInit = FALSE;
    char sb[900], *p;
    WORD* data;
    LONG n;
    int i;
    if (!key) return;
    if (!s_csInit)
    {
        InitializeCriticalSection(&s_cs);
        s_csInit = TRUE;
    }
    __try
    {
        data = *(WORD**)(valueLo + 4);
        if (!data || data == (WORD*)-2) return;
        n = InterlockedIncrement(&s_n);
        if (n <= 300)
        {
            p = sb;
            p += wsprintfA(p, "[SETKEY %ld] key=", n);
            {
                const char* k = key;
                int kl = 0;
                __try { while (k[kl] && kl < 48) kl++; }
                __except (EXCEPTION_EXECUTE_HANDLER) { kl = 0; }
                for (i = 0; i < kl; i++)
                    p += wsprintfA(p, "%c", (k[i] >= 0x20 && k[i] < 0x7F) ? k[i] : '.');
            }
            p += wsprintfA(p, " raw=[%08X %08X %08X %08X] out=%08X | ", r0, r1, r2, r3, valueLo);
            for (i = 0; i < 24; i++)
                p += wsprintfA(p, "%04X ", (unsigned)data[i]);
            p += wsprintfA(p, "\n");
            EnterCriticalSection(&s_cs);
            {
                HANDLE h = CreateFileA("CJK_setkey_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                                       NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (h != INVALID_HANDLE_VALUE)
                {
                    SetFilePointer(h, 0, NULL, FILE_END);
                    DWORD wn; WriteFile(h, sb, (DWORD)(p - sb), &wn, NULL);
                    CloseHandle(h);
                }
            }
            LeaveCriticalSection(&s_cs);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
}

// 前置：取 key（[esp+0x28]）+ value.lo（[esp+0x2C]）+ 原始栈 4 dword → pre_c → jmp trampoline
static void __declspec(naked) cjk_setkey_hook_impl(void)
{
    __asm
    {
        ; 进入：栈 [ret, key, value.lo, value.hi, ...]，this = ecx（__thiscall！）
        push ebp
        mov  ebp, esp
        pushad
        ; push ebp(4) + pushad(32) = 36 = 0x24
        ; [esp+0x24] = ret, [esp+0x28] = key, [esp+0x2C] = value.lo, [esp+0x30] = value.hi
        ; 先取到寄存器（避免 push 改变 esp 偏移）：
        mov  eax, [esp + 0x24]           ; r0 = ret
        mov  ecx, [esp + 0x28]           ; r1 = key
        mov  edx, [esp + 0x2C]           ; r2 = value.lo
        mov  esi, [esp + 0x30]           ; r3 = value.hi
        ; __cdecl 从右往左压：r3, r2, r1, r0, key, valueLo
        push esi                         ; r3
        push edx                         ; r2
        push ecx                         ; r1
        push eax                         ; r0
        push ecx                         ; key（= r1）
        push edx                         ; valueLo（= r2）
        call cjk_setkey_pre_c
        add  esp, 24                     ; 6 个参数清栈
        popad
        pop  ebp
        jmp  dword ptr [g_setKeyTramp]   ; 执行原函数（popad 已恢复 ecx = this）
    }
}

static int install_setkey_hook(void)
{
    BYTE* entry;
    DWORD oldProt;
    HMODULE hMs;
    int i;
    static const BYTE expect[SETKEY_HDR_BYTES] = {0x64, 0xA1, 0x00, 0x00, 0x00, 0x00};
    if (g_hookedSetKey) return 1;
    hMs = GetModuleHandleA("MSystem.dll");
    if (!hMs) return 0;
    entry = (BYTE*)hMs + MS_SETKEY_RVA;
    memcpy(g_origSetKeyBody, entry, SETKEY_HDR_BYTES);
    for (i = 0; i < SETKEY_HDR_BYTES; i++)
        if (g_origSetKeyBody[i] != expect[i])
        {
            log_msg("[CJK] SetThisKey 落点核验失败：%02X %02X %02X %02X %02X %02X，跳过\n",
                    g_origSetKeyBody[0], g_origSetKeyBody[1], g_origSetKeyBody[2],
                    g_origSetKeyBody[3], g_origSetKeyBody[4], g_origSetKeyBody[5]);
            return 0;
        }
    g_setKeyTramp = VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_setKeyTramp) return 0;
    memcpy(g_setKeyTramp, g_origSetKeyBody, SETKEY_HDR_BYTES);
    ((BYTE*)g_setKeyTramp)[SETKEY_HDR_BYTES] = 0xE9;
    *(DWORD*)((BYTE*)g_setKeyTramp + SETKEY_HDR_BYTES + 1) =
        ((DWORD)entry + SETKEY_HDR_BYTES) - ((DWORD)g_setKeyTramp + SETKEY_HDR_BYTES + 5);
    if (!VirtualProtect(entry, SETKEY_HDR_BYTES, PAGE_EXECUTE_READWRITE, &oldProt)) return 0;
    entry[0] = 0xE9;
    *(DWORD*)(entry + 1) = (DWORD)cjk_setkey_hook_impl - ((DWORD)entry + 5);
    entry[5] = 0x90;
    VirtualProtect(entry, SETKEY_HDR_BYTES, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), entry, SETKEY_HDR_BYTES);
    g_hookedSetKey = TRUE;
    log_msg("[CJK] v17b SetThisKey 本体 hook：%08X -> %08X（EXE 教程键名注册点，前置只读）\n",
            (DWORD)entry, (DWORD)cjk_setkey_hook_impl);
    return 1;
}

// ═══════════════════════════════════════════════════════════════════════
// ★ v17d：hook CRegistry::GetValue(PBD)（MSystem RVA 0x607B0）——教程渲染【读 DYNAMIC 值】点！
//   ?GetValue@CRegistry@@UBE?AVCStr@@PBD@Z：__thiscall，CStr 按值返回（hidden ret ptr）
//   栈 [ret, ret_ptr, key]，this=ecx。函数头 51 8B 54 24 08（5 字节完整），尾 retn 8。
//   eax = ret_ptr（CStr* = [vtable @0][data_ptr @4]）→ post 里改写/记录。
//   ★ 为什么是它：教程渲染用运行时 §L 名（.xrg 的 "TUTORIAL_JUMP"）查 DYNAMIC stringtable →
//     CRegistry::GetValue(PBD)（Dynamic 继承基类实现）→ 返回注册值 '键名'（半角 ASCII → @）。
//     post 模式（v16r 教训：post 结尾 jmp 回原调用者）：key 含 TUTORIAL_ → data 改写
//     （key_replace：'键名' → 中文）+ 日志 CJK_getval_log.txt。
// ═══════════════════════════════════════════════════════════════════════
#define MS_GETVAL_RVA 0x607B0u
#define GETVAL_HDR_BYTES 5
static BYTE  g_origGetValBody[GETVAL_HDR_BYTES];
static void* g_getValTramp = NULL;
static BOOL  g_hookedGetVal = FALSE;
static DWORD g_getValOrigRet = 0;
static DWORD g_getValKey = 0;          // hook_impl 保存的 key 参数（post 用）

static void __cdecl cjk_getval_post_c(DWORD retPtr)
{
    static volatile LONG s_n = 0;
    char sb[700], *p;
    WORD* data;
    const char* key;
    LONG n;
    int i, kl, isTut;
    if (!retPtr || !g_getValKey) return;
    __try
    {
        key = (const char*)g_getValKey;
        kl = 0;
        __try { while (key[kl] && kl < 48) kl++; }
        __except (EXCEPTION_EXECUTE_HANDLER) { kl = 0; }
        // 只处理 TUTORIAL_ 前缀（教程键名；其他配置值原样放行）
        isTut = (kl >= 9 && key[0] == 'T' && key[1] == 'U' && key[2] == 'T' &&
                 key[3] == 'O' && key[4] == 'R' && key[5] == 'I' &&
                 key[6] == 'A' && key[7] == 'L' && key[8] == '_');
        if (!isTut) return;
        data = *(WORD**)(retPtr + 4);
        if (!data || data == (WORD*)-2) return;
        // ★ 改写：'键名' → 中文（key_replace 只处理引号+ASCII 键名，等长/缩短替换，零越界）
        key_replace(data + 1, 512);
        // 日志（前 100 条）
        n = InterlockedIncrement(&s_n);
        if (n <= 100)
        {
            p = sb;
            p += wsprintfA(p, "[GETVAL %ld] key=", n);
            for (i = 0; i < kl; i++)
                p += wsprintfA(p, "%c", (key[i] >= 0x20 && key[i] < 0x7F) ? key[i] : '.');
            p += wsprintfA(p, " ret=%08X | ", retPtr);
            for (i = 0; i < 20; i++)
                p += wsprintfA(p, "%04X ", (unsigned)data[i]);
            p += wsprintfA(p, "\n");
            {
                HANDLE h = CreateFileA("CJK_getval_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                                       NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (h != INVALID_HANDLE_VALUE)
                {
                    SetFilePointer(h, 0, NULL, FILE_END);
                    DWORD wn; WriteFile(h, sb, (DWORD)(p - sb), &wn, NULL);
                    CloseHandle(h);
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
}

// post：原函数 retn 8 后跳入。进入时 eax = ret_ptr（原函数 mov eax, esi）。
// 栈：retn 8 已弹返回地址并清 ret_ptr+key → 栈顶 = 调用者栈 → jmp 回原调用者（v16r 教训）
static void __declspec(naked) cjk_getval_post(void)
{
    __asm
    {
        pushad
        mov  eax, [esp + 0x1C]           ; 原 eax = ret_ptr（CStr*）
        push eax
        call cjk_getval_post_c
        add  esp, 4
        popad
        jmp  dword ptr [g_getValOrigRet] ; ★ v16r：不 ret，jmp 回保存的原调用者
    }
}
static DWORD cjk_getval_post_addr = (DWORD)cjk_getval_post;

// hook_impl：保存 orig ret + key（[ebp+0xC]）→ 改返回地址 → jmp trampoline（this 留 ecx）
static void __declspec(naked) cjk_getval_hook_impl(void)
{
    __asm
    {
        ; 进入：栈 [ret, ret_ptr, key]，this = ecx（__thiscall！严禁碰 ecx）
        push ebp
        mov  ebp, esp
        push eax
        mov  eax, [ebp + 4]              ; 原返回地址
        mov  g_getValOrigRet, eax        ; 保存 → post 里 jmp 回
        mov  eax, [ebp + 0xC]            ; key（[ebp+8]=ret_ptr, [ebp+0xC]=key）
        mov  g_getValKey, eax            ; 保存 → post 里检查 TUTORIAL_
        mov  eax, cjk_getval_post_addr   ; post 地址
        mov  [ebp + 4], eax              ; 替换 → 原函数 retn 8 后先到 post
        pop  eax
        pop  ebp
        jmp  dword ptr [g_getValTramp]   ; 跳板：原 5 字节 + jmp 原函数+5（this 仍在 ecx）
    }
}

static int install_getval_hook(void)
{
    BYTE* entry;
    DWORD oldProt;
    HMODULE hMs;
    int i;
    static const BYTE expect[GETVAL_HDR_BYTES] = {0x51, 0x8B, 0x54, 0x24, 0x08};
    if (g_hookedGetVal) return 1;
    hMs = GetModuleHandleA("MSystem.dll");
    if (!hMs) return 0;
    entry = (BYTE*)hMs + MS_GETVAL_RVA;
    memcpy(g_origGetValBody, entry, GETVAL_HDR_BYTES);
    for (i = 0; i < GETVAL_HDR_BYTES; i++)
        if (g_origGetValBody[i] != expect[i])
        {
            log_msg("[CJK] GetValue 落点核验失败：%02X %02X %02X %02X %02X，跳过\n",
                    g_origGetValBody[0], g_origGetValBody[1], g_origGetValBody[2],
                    g_origGetValBody[3], g_origGetValBody[4]);
            return 0;
        }
    g_getValTramp = VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_getValTramp) return 0;
    memcpy(g_getValTramp, g_origGetValBody, GETVAL_HDR_BYTES);
    ((BYTE*)g_getValTramp)[GETVAL_HDR_BYTES] = 0xE9;
    *(DWORD*)((BYTE*)g_getValTramp + GETVAL_HDR_BYTES + 1) =
        ((DWORD)entry + GETVAL_HDR_BYTES) - ((DWORD)g_getValTramp + GETVAL_HDR_BYTES + 5);
    if (!VirtualProtect(entry, GETVAL_HDR_BYTES, PAGE_EXECUTE_READWRITE, &oldProt)) return 0;
    entry[0] = 0xE9;
    *(DWORD*)(entry + 1) = (DWORD)cjk_getval_hook_impl - ((DWORD)entry + 5);
    VirtualProtect(entry, GETVAL_HDR_BYTES, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), entry, GETVAL_HDR_BYTES);
    g_hookedGetVal = TRUE;
    log_msg("[CJK] v17d GetValue(PBD) 本体 hook：%08X -> %08X（教程读 DYNAMIC 值点，post 改写）\n",
            (DWORD)entry, (DWORD)cjk_getval_hook_impl);
    return 1;
}

// ═══════════════════════════════════════════════════════════════════════
// ★ v19（x64dbg 动态取证定案）：hook GetValue 未命中分支 CStr 构造 0x1000960A
//   ——修复「你拾起了一支火把」→「你拾起了」（低字节 0x00 汉字截断）！
//
//   ◆ 截断链路（x64dbg 断点实证 + IDA 反汇编三重印证）：
//     教程 TEXT（LM01.xrg *TEXT 值）→ GetValue 查表【未命中】→ 0x1000960A（窄版 CStr 构造）
//       0x1000846A 格式化（按窄 %s 读源）+ 0x10009680 窄 strlen（按字节扫 0x00）
//       → 「一」= U+4E00（LE 00 4E）低字节 0x00 被当字符串结束 → 截断！
//     对白（registry 命中）→ 0x100A9B00 → 0x1000976A（拷贝构造，IsWide 判定）
//       → 首字符「救」0x6551（[1]=0x65）&0x40 → 宽路径 → 完整
//     教程首字符全角空格 0x3000（[1]=0x30）&0x40=0 → 窄路径 → 截断
//
//   ◆ 关键对比（x64dbg 反汇编）：
//     0x1000960A（窄版）：0x1000846A 窄格式化 + 窄 strlen + [vtable+0x68]（0x1000D88A 窄 Assign）
//     0x100096BA（宽版）：0x100E8456 宽格式化 + WORD 扫 0x0000 + [vtable+0x88]（宽 Assign）
//     两者参数布局完全相同（__cdecl：[esp+4]=输出CStr*, [esp+8]=源指针）！
//
//   ◆ v19 修复：hook 0x1000960A 入口（6B：64 A1 00 00 00 00 = mov eax,fs:[0]）
//     → 检测源是否 UTF-16 宽文本（偶数偏移字节==0x00 且下一字节非 0）
//     → 宽文本：jmp 到宽版 0x100096BA（参数原样，宽版自己 SEH+ret）
//     → 其他：jmp trampoline（原 6B + jmp 0x10009610）走原逻辑
// ═══════════════════════════════════════════════════════════════════════
#define MS_GETVAL_CALL_RVA 0x60615u     // GetValue 未命中分支 call 0x1000960A 调用点（唯一！）
#define MS_GETVAL_CALL_RET_RVA 0x6061Au // call 返回地址（add esp,0x08 前）
#define MS_GETVAL_NARROW_RVA 0x960Au    // 窄版 CStr 构造（原函数，未修改）
#define MS_GETVAL_WIDE_RVA   0x96BAu    // 宽版 CStr 构造（WORD 扫，不截断）
#define GETVALCALL_HDR_BYTES 5
static BYTE  g_origGetValCall[GETVALCALL_HDR_BYTES];
static DWORD g_getvalRetVA = 0;          // 运行时 call 返回地址（base+0x6061A）
static DWORD g_getvalNarrowVA = 0;       // 运行时窄版地址（base+0x960A）
static DWORD g_getvalWideVA = 0;         // 运行时宽版地址（base+0x96BA）
static BOOL  g_hookedGetValCall = FALSE;

// v20 handler：hook GetValue 未命中分支的 call 0x1000960A 调用点（0x10060615）
// 进入（jmp 替换 call，无返回地址压栈）：[esp]=arg1(输出CStr*), [esp+4]=arg2(源指针)
// 检测源是 UTF-16 宽文本 → 模拟 call 跳到【宽版 0x100096BA】（完整，不截断）
// 其他 → 模拟 call 跳到【原版 0x1000960A】（行为不变）
static void __declspec(naked) cjk_getval_call_impl(void)
{
    __asm
    {
        ; arg2 = 源指针 = [esp+4]
        mov  eax, [esp + 4]
        test eax, eax
        jz   gvc_orig            ; 空源 → 原版
        ; 扫描前 16 WORD（32 字节）：偶数偏移字节 == 0 && 下一字节非 0 → UTF-16 宽文本
        xor  ecx, ecx
    gvc_scan:
        cmp  ecx, 16
        jae  gvc_orig            ; 无特征 → 窄 → 原版
        movzx edx, byte ptr [eax + ecx*2]
        test edx, edx
        jnz  gvc_next            ; 偶数偏移非 0 → 下一个
        movzx edx, byte ptr [eax + ecx*2 + 1]
        test edx, edx
        jnz  gvc_wide            ; ★ 偶数0 + 后非0 → 宽文本（如「一」00 4E、全角空格 00 30）
    gvc_next:
        inc  ecx
        jmp  gvc_scan
    gvc_wide:
        ; ★ 宽文本 → 模拟 call 宽版 0x100096BA（push 返回地址 + jmp）
        push dword ptr [g_getvalRetVA]
        jmp  dword ptr [g_getvalWideVA]
    gvc_orig:
        ; 窄/空 → 模拟 call 原版 0x1000960A（push 返回地址 + jmp）
        push dword ptr [g_getvalRetVA]
        jmp  dword ptr [g_getvalNarrowVA]
    }
}

static int install_getval_call_hook(void)
{
    BYTE* entry;
    DWORD oldProt;
    HMODULE hMs;
    int i;
    static const BYTE expect[GETVALCALL_HDR_BYTES] = {0xE8, 0xF0, 0x8F, 0xFA, 0xFF};
    if (g_hookedGetValCall) return 1;
    hMs = GetModuleHandleA("MSystem.dll");
    if (!hMs) return 0;
    entry = (BYTE*)hMs + MS_GETVAL_CALL_RVA;
    memcpy(g_origGetValCall, entry, GETVALCALL_HDR_BYTES);
    for (i = 0; i < GETVALCALL_HDR_BYTES; i++)
        if (g_origGetValCall[i] != expect[i])
        {
            log_msg("[CJK] v20 调用点核验失败：%02X %02X %02X %02X %02X，跳过\n",
                    g_origGetValCall[0], g_origGetValCall[1], g_origGetValCall[2],
                    g_origGetValCall[3], g_origGetValCall[4]);
            return 0;
        }
    g_getvalRetVA    = (DWORD)hMs + MS_GETVAL_CALL_RET_RVA;
    g_getvalNarrowVA = (DWORD)hMs + MS_GETVAL_NARROW_RVA;
    g_getvalWideVA   = (DWORD)hMs + MS_GETVAL_WIDE_RVA;
    if (!VirtualProtect(entry, GETVALCALL_HDR_BYTES, PAGE_EXECUTE_READWRITE, &oldProt)) return 0;
    entry[0] = 0xE9;
    *(DWORD*)(entry + 1) = (DWORD)cjk_getval_call_impl - ((DWORD)entry + 5);
    VirtualProtect(entry, GETVALCALL_HDR_BYTES, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), entry, GETVALCALL_HDR_BYTES);
    g_hookedGetValCall = TRUE;
    log_msg("[CJK] v20 GetValue未命中调用点 hook：%08X -> %08X（宽->%08X 窄->%08X ret=%08X）\n",
            (DWORD)entry, (DWORD)cjk_getval_call_impl, g_getvalWideVA, g_getvalNarrowVA, g_getvalRetVA);
    return 1;
}

// ═══════════════════════════════════════════════════════════════════════
// ★ v22（x64dbg 断点定案修正）：hook GameWorld sub_10007900 (UI 布局解析器)
//   "TEXT" 关键字分支调用点（GameWorld RVA 0x7948 = call sub_100F9CCA）
//   ——修复「你拾起了一支火把」截断！
//
//   ◆ v21 教训（hook 错位置）：v21 hook 的是 sub_1008E1C0（对话脚本解析器）
//     内 call sub_100F9CCA（RVA 0x8E20C）——但教程 TEXT（LM01.xrg *TEXT 值）
//     实际走 sub_10007900（UI 布局解析器）"TEXT" 关键字分支！
//     x64dbg 实证：0x13BF7948（RVA 0x7948）断点命中（用户确认「exe 未完全启动」），
//     上下文 = mov edx,0x13D60478("TEXT"); call 0x13CE1C1A(关键字比较);
//     jz 下一分支 → lea eax,[ebp+0x14](TEXT 值); lea edi,[esi+0x138];
//     push eax; mov ecx,edi; call 0x13CE9CCA(sub_100F9CCA)！
//   ◆ 栈平衡修正：ts_wide 分支必须模拟原调用语义（push a2 → call → ret 0x04 清 a2）：
//     call sub_100FFD90 后 add esp,4 清 a2 + ret 返回——v21 的 push ret+jmp 会导致
//     返回后栈差 4 字节（a2 未清）→ 调用者栈错位。
//   ◆ 判定机制（同前）：教程 TEXT 首字符全角空格 0x3000（LE 00 30）→
//     [文本+1]&0x40 = 0 → 判窄 → 深拷贝窄 strlen 截断「一」(00 4E)。
//     v22 handler 检测 UTF-16 宽特征（偶数偏移 0x00 + 下字节非 0）→
//     强制宽路径 sub_100FFD90（引用共享不截断）。
// ═══════════════════════════════════════════════════════════════════════
#define GW_TEXT_STORE_CALL_RVA 0x7948u   // sub_10007900 (UI解析器) "TEXT" 关键字分支 call sub_100F9CCA
#define GW_TEXT_STORE_RET_RVA  0x794Du   // call 返回地址
#define GW_TEXT_STORE_F9CCA_RVA 0xF9CCAu  // sub_100F9CCA 原函数（窄路径 fallback）
#define GW_TEXT_STORE_FFD90_RVA 0xFFD90u  // sub_100FFD90 宽路径（引用共享）
static BYTE  g_origTextStore[5];
static DWORD g_textStoreRetVA = 0;        // 运行时返回地址（base+0x8E211）
static DWORD g_textStoreF9CCA = 0;        // 运行时原函数（base+0xF9CCA）
static DWORD g_textStoreFFD90 = 0;        // 运行时宽路径（base+0xFFD90）
static BOOL  g_hookedTextStore = FALSE;

// v21 handler：hook 调用点（jmp 替换 call，无返回地址）
// 进入：ecx=this（教程对象+8）, [esp]=a2（TEXT CStr*）——call 前 push 的源参数
// 注意：调用点 0x0D66E1FE 处 lea ecx,[ebx+8] 已设 ecx；0x0D66E1FD push eax 压了 a2。
// handler 用 pushad 保存后 [esp+0x20]=a2, [esp+0x18]=原ecx。
// 宽路径模拟（sub_100FFD90(this+4, a2+4)，引用共享不截断）：
//   进入时 [esp]=a2 → push ret 后 [esp]=ret,[esp+4]=a2 → mov [esp+4],a2+4
//   → lea ecx,[this+4] → jmp sub_100FFD90（ret 0x04 弹 a2+4 → 返回 ret）→ 栈平衡
// ★ v23q8 诊断：v21 TEXT 存储点收到的源文本（前 200 次）——
//   教程 TEXT（.xrg *TEXT 值，含 §L 宏）存储必经点。
//   记录文本形态：§L 原文（A7 00 4C 00）/ 已展开键名（半角 0x27 或全角 0xFF07）→
//   判定教程路径 + 全角化来源 + 预展开正确落点。
static void __declspec(noinline) cjk_textstore_diag(const WORD* w)
{
    static volatile LONG s_cnt = 0;
    LONG c = InterlockedIncrement(&s_cnt);
    if (c > 200) return;
    int n = 0;
    while (n < 40 && w[n]) n++;
    char sb[400]; char* q = sb;
    q += wsprintfA(q, "[TSTORE %ld] ptr=%08X n=%d | ", c, w, n);
    for (int i = 0; i < n; i++) q += wsprintfA(q, "%04X ", (unsigned)w[i]);
    q += wsprintfA(q, "\n");
    HANDLE h = CreateFileA("CJK_tstore_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        SetFilePointer(h, 0, NULL, FILE_END);
        DWORD wn; WriteFile(h, sb, (DWORD)(q - sb), &wn, NULL);
        CloseHandle(h);
    }
}

static void __declspec(naked) cjk_text_store_impl(void)
{
    __asm
    {
        ; 进入：[esp]=a2(TEXT CStr*), ecx=this —— 无返回地址（jmp 替换 call）
        pushad
        ; pushad 布局: [0x00]EDI [0x04]ESI [0x08]EBP [0x0C]ESP [0x10]EBX [0x14]EDX [0x18]ECX [0x1C]EAX
        ; 调用点 push 的 a2 在 [esp+0x20]
        mov  esi, [esp + 0x20]          ; esi = a2（TEXT CStr*）
        test esi, esi
        jz   ts_orig                    ; 空源 → 原逻辑
        mov  edi, [esi + 4]             ; edi = a2->文本指针
        test edi, edi
        jz   ts_orig                    ; 空文本 → 原逻辑
        ; ★ v23q8 诊断：记录 TEXT 存储源文本（前 200 次）
        push edi
        call cjk_textstore_diag
        add  esp, 4
        ; 扫描前 16 WORD：偶数偏移字节==0 且下字节非 0 → UTF-16 宽文本特征
        xor  ebx, ebx
    ts_scan:
        cmp  ebx, 16
        jae  ts_orig                    ; 无宽特征 → 原逻辑（窄路径）
        movzx eax, byte ptr [edi + ebx*2]
        test eax, eax
        jnz  ts_next
        movzx eax, byte ptr [edi + ebx*2 + 1]
        test eax, eax
        jnz  ts_wide                    ; ★ 偶数0+后非0 → UTF-16 宽文本（如「一」00 4E）
    ts_next:
        inc  ebx
        jmp  ts_scan
    ts_wide:
        ; ★ 强制宽路径：sub_100FFD90(this+4, a2+4)（引用共享，不截断）
        ; 进入 handler 时 [esp]=a2（调用点 push 的），ecx=this
        popad
        ; 恢复后 [esp]=a2, ecx=this
        mov  eax, [esp]                 ; eax = a2
        add  eax, 4                     ; eax = a2+4
        push eax                        ; [esp]=a2+4（sub_100FFD90 参数）, [esp+4]=a2
        lea  ecx, [ecx + 4]             ; ecx = this+4
        call dword ptr [g_textStoreFFD90]   ; call sub_100FFD90（ret 0x04 清 a2+4 返回）
        add  esp, 4                     ; ★ 清 a2（原调用点 push 的）→ 栈平衡
        ret                             ; 返回调用者（等效 sub_100F9CCA 的 ret 0x04 清 a2）
    ts_orig:
        popad
        ; 恢复后 [esp]=a2, ecx=this
        push dword ptr [g_textStoreRetVA]   ; [esp]=ret, [esp+4]=a2
        jmp  dword ptr [g_textStoreF9CCA]
        ; sub_100F9CCA ret 0x04 弹 a2 → 返回 0x0D66E211 → 原逻辑 ✓
    }
}

static int install_text_store_hook(void)
{
    BYTE* entry;
    DWORD oldProt;
    HMODULE hGw;
    static const BYTE expect[5] = {0xE8, 0x7D, 0x23, 0x0F, 0x00};
    if (g_hookedTextStore) return 1;
    hGw = GetModuleHandleA("GameWorld.dll");
    if (!hGw) return 0;
    g_gwBase = (DWORD)hGw;
    entry = (BYTE*)hGw + GW_TEXT_STORE_CALL_RVA;
    memcpy(g_origTextStore, entry, 5);
    if (memcmp(g_origTextStore, expect, 5) != 0)
    {
        log_msg("[CJK] v21 TEXT 存储调用点核验失败：%02X %02X %02X %02X %02X，跳过\n",
                g_origTextStore[0], g_origTextStore[1], g_origTextStore[2],
                g_origTextStore[3], g_origTextStore[4]);
        return 0;
    }
    g_textStoreRetVA  = g_gwBase + GW_TEXT_STORE_RET_RVA;
    g_textStoreF9CCA  = g_gwBase + GW_TEXT_STORE_F9CCA_RVA;
    g_textStoreFFD90  = g_gwBase + GW_TEXT_STORE_FFD90_RVA;
    if (!VirtualProtect(entry, 5, PAGE_EXECUTE_READWRITE, &oldProt)) return 0;
    entry[0] = 0xE9;
    *(DWORD*)(entry + 1) = (DWORD)cjk_text_store_impl - ((DWORD)entry + 5);
    VirtualProtect(entry, 5, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), entry, 5);
    g_hookedTextStore = TRUE;
    log_msg("[CJK] v21 TEXT 存储调用点 hook：%08X -> %08X（宽->%08X 原->%08X ret=%08X）\n",
            (DWORD)entry, (DWORD)cjk_text_store_impl, g_textStoreFFD90, g_textStoreF9CCA, g_textStoreRetVA);
    return 1;
}

// ═══════════════════════════════════════════════════════════════════════
// ★ v23（纯只读探针）：hook sub_100F9CCA / sub_100EFCBA 函数本体，
//   批量 log「含 CJK 的文本」每次经过时的 caller + 文本 hex → CJK_probe_log.txt
//
//   ◆ 目的：定位「你拾起了一支火把」→「你拾起了」的真实截断路径。
//     v22 hook 调用点 0x7948 无效 → 教程 TEXT 可能不走该调用点；
//     改 hook **函数本体** = 拦截所有调用者（无论从哪个调用点进来），
//     且【行为零修改】：扫描完直接 trampoline 执行原逻辑，绝不死循环。
//
//   ◆ sub_100F9CCA（RVA 0xF9CCA）头部 5B = `8B 54 24 04 56`
//     （mov edx,[esp+4]; push esi）——完整指令，可安全覆盖 5B。
//     进入：[esp]=返回地址(caller), [esp+4]=a2(CStr*), ecx=this
//     源文本指针 = [a2+4]（v21 handler 实证布局：{vtable, text*}）
//   ◆ sub_100EFCBA（RVA 0xEFCBA）头部前 5B = `53 56 57 8B 7C` 会截断
//     mov edi,[esp+0Ch] → 必须覆盖 7B（`53 56 57 8B 7C 24 0C`），
//     trampoline 复制 7B + jmp entry+7。
//     进入：[esp]=返回地址(caller), [esp+4]=arg_0(源CStr*), ecx=this
//     源文本指针 = [arg_0+4]
//
//   ◆ 重入保护：g_inProbe 标志（volatile LONG），探针执行期间再入 → 直接
//     trampoline 原逻辑，杜绝递归死循环。
// ═══════════════════════════════════════════════════════════════════════
#define GW_F9CCA_BODY_RVA  0xF9CCAu    // sub_100F9CCA 本体（TEXT 存储咽喉）
#define GW_EFCBA_BODY_RVA  0xEFCBAu    // sub_100EFCBA 本体（窄路径深拷贝=截断点）
static BYTE   g_origF9CCA[5];
static BYTE*  g_f9ccaTramp = NULL;
static BYTE   g_origEFCBA[7];
static BYTE*  g_efcbaTramp = NULL;
static volatile LONG g_inProbe = 0;

// probe_log_c：扫描文本，命中【真 UTF-16 中文文本】→ 写 CJK_probe_log.txt（去重限流）
// ★ v23c 修复（崩溃根因）：
//   sub_100F9CCA 有大量【资源加载】调用点（wave_0.xwc/GameClasses.dll/cam\ping 等
//   窄 ANSI 路径），这些调用 [a2+4] 不是合法 UTF-16 文本指针（窄字节对按 WORD 读
//   恰好偶中 CJK 区间）→ 原探针扫描时访问违例崩溃（dump 实证 Eip=RVA 0x3F71
//   probe_log_c 扫描循环 + Ebp=0x3A475758 垃圾指针）。
//   ① 判定收紧：前 32 WORD 中【≥3 个 CJK 汉字/标点】才算真中文文本（窄路径随机
//     字节对难凑 3 个）→ 过滤误判刷爆
//   ② SEH 保护：整个扫描+格式化用 __try/__except 包住 → 读坏指针直接跳过，永不崩溃
// cdecl 参数：probe_log_c(const char* tag, DWORD caller, const BYTE* txt)
static void probe_log_c(const char* tag, DWORD caller, const BYTE* txt)
{
    char  buf[640];
    char* p = buf;
    int   i, cjk = 0, sigMatch = 0;
    WORD  sig[4];
    static DWORD s_lastCaller = 0;
    static WORD  s_sig[4] = {0};

    if (!txt) return;
    __try
    {
        // 统计前 32 WORD 中 CJK 汉字/标点数量（真 UTF-16 中文文本特征）
        for (i = 0; i < 32; i++)
        {
            WORD w = *(WORD*)(txt + i * 2);
            if (w == 0) break;
            if ((w >= 0x4E00 && w <= 0x9FFF) || (w >= 0x3000 && w <= 0x30FF)) cjk++;
        }
        if (cjk < 3) return;   // 非中文文本（窄路径/资源名/短文本）→ 不记录
        // 去重：caller + 前 4 WORD 与上次相同 → 跳过（防高频重复刷爆）
        for (i = 0; i < 4; i++) sig[i] = *(WORD*)(txt + i * 2);
        if (caller == s_lastCaller && sig[0] == s_sig[0] && sig[1] == s_sig[1] &&
            sig[2] == s_sig[2] && sig[3] == s_sig[3]) return;
        s_lastCaller = caller;
        for (i = 0; i < 4; i++) s_sig[i] = sig[i];

        p += wsprintfA(p, "[%s] caller=%08X 文本前32WORD: ", tag, caller);
        for (i = 0; i < 32; i++)
        {
            WORD w = *(WORD*)(txt + i * 2);
            if (w == 0) break;
            if (w >= 0x20 && w <= 0x7E) p += wsprintfA(p, "%c", (char)w);
            else if ((w >= 0x4E00 && w <= 0x9FFF) || (w >= 0x3000 && w <= 0x30FF))
                p += wsprintfA(p, "[%04X]", w);
            else p += wsprintfA(p, "<%02X%02X>", w & 0xFF, w >> 8);
        }
        p += wsprintfA(p, "\n");
        HANDLE h = CreateFileA("CJK_probe_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) return;
        SetFilePointer(h, 0, NULL, FILE_END);
        DWORD written;
        WriteFile(h, buf, (DWORD)(p - buf), &written, NULL);
        CloseHandle(h);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // 非法指针/访问违例 → 静默跳过（探针永不崩溃）
    }
}

// 探针 tag 字符串（naked asm push offset 引用，必须在使用前声明）
static const char probe_tag_f9cca[] = "F9CCA";
static const char probe_tag_efcba[] = "EFCBA";

// ★ v23c：naked 里直接读 [a2+4] 也可能崩（a2 本身非法指针时读取即 AV）——
//   统一用 C 包装：指针解引用全部放进 __try/__except，探针永不崩溃。
static void probe_a2_c(const char* tag, DWORD caller, DWORD a2)
{
    __try
    {
        const BYTE* txt = a2 ? *(const BYTE**)(a2 + 4) : NULL;
        probe_log_c(tag, caller, txt);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

static void __declspec(naked) cjk_f9cca_probe(void)
{
    __asm
    {
        ; 进入：[esp]=返回地址(caller), [esp+4]=a2(CStr*), ecx=this
        pushad
        ; pushad 布局: [0x00]EDI [0x04]ESI [0x08]EBP [0x0C]ESP [0x10]EBX [0x14]EDX [0x18]ECX [0x1C]EAX
        ; [esp+0x20]=caller, [esp+0x24]=a2
        cmp  byte ptr [g_inProbe], 1
        je   f9_skip
        mov  byte ptr [g_inProbe], 1
        mov  eax, [esp + 0x24]          ; a2
        mov  ebx, [esp + 0x20]          ; caller
        push eax                        ; 参数3: a2
        push ebx                        ; 参数2: caller
        push offset probe_tag_f9cca     ; 参数1: tag
        call probe_a2_c
        add  esp, 12
    f9_done:
        mov  byte ptr [g_inProbe], 0
    f9_skip:
        popad
        jmp  dword ptr [g_f9ccaTramp]
    }
}

static void __declspec(naked) cjk_efcba_probe(void)
{
    __asm
    {
        ; 进入：[esp]=返回地址(caller), [esp+4]=arg_0(源CStr*), ecx=this
        pushad
        cmp  byte ptr [g_inProbe], 1
        je   ef_skip
        mov  byte ptr [g_inProbe], 1
        mov  eax, [esp + 0x24]          ; arg_0
        mov  ebx, [esp + 0x20]          ; caller
        push eax                        ; 参数3: a2
        push ebx                        ; 参数2: caller
        push offset probe_tag_efcba     ; 参数1: tag
        call probe_a2_c
        add  esp, 12
    ef_done:
        mov  byte ptr [g_inProbe], 0
    ef_skip:
        popad
        jmp  dword ptr [g_efcbaTramp]
    }
}

static int install_probe_hook(void)
{
    BYTE* e1;
    BYTE* e2;
    DWORD oldProt;
    static const BYTE expect1[5] = {0x8B, 0x54, 0x24, 0x04, 0x56}; // mov edx,[esp+4]; push esi
    // ★ v23b 修复：sub_100EFCBA 头 = push ebx(53) push esi(56) push edi(57) mov edi,[esp+0x10](8B 7C 24 10)
    //   3 个 push 后 esp 已 -12，所以 mov edi 的 [esp+0Ch+arg_0] 编码为 8B 7C 24 10（esp+0x10）！
    //   （原写 0x0C 错误 → 核验失败探针没装上，日志证实：53 56 57 8B 7C 24 10）
    static const BYTE expect2[7] = {0x53, 0x56, 0x57, 0x8B, 0x7C, 0x24, 0x10};
    if (g_f9ccaTramp && g_efcbaTramp) return 1;
    if (!g_gwBase) return 0;

    // P1: sub_100F9CCA 本体（5B）
    e1 = (BYTE*)g_gwBase + GW_F9CCA_BODY_RVA;
    if (memcmp(e1, expect1, 5) != 0)
    {
        log_msg("[CJK] v23 F9CCA 头部核验失败：%02X %02X %02X %02X %02X，跳过\n",
                e1[0], e1[1], e1[2], e1[3], e1[4]);
        return 0;
    }
    g_f9ccaTramp = (BYTE*)VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_f9ccaTramp) return 0;
    memcpy(g_origF9CCA, e1, 5);
    memcpy(g_f9ccaTramp, e1, 5);
    g_f9ccaTramp[5] = 0xE9;
    // ★ v23b 修复：E9 在 tramp[5]，下一条指令 = tramp+10，rel 必须相对 tramp+10！
    //   （原写 -11 多减 1 → 跳回 e1+4 重复执行 push esi → 栈破坏 → Eip 跳栈崩溃 C0000005）
    *(DWORD*)(g_f9ccaTramp + 6) = ((DWORD)e1 + 5) - ((DWORD)g_f9ccaTramp + 10);
    VirtualProtect(e1, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    e1[0] = 0xE9;
    *(DWORD*)(e1 + 1) = (DWORD)cjk_f9cca_probe - ((DWORD)e1 + 5);
    VirtualProtect(e1, 5, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), e1, 5);

    // P2: sub_100EFCBA 本体（7B）
    e2 = (BYTE*)g_gwBase + GW_EFCBA_BODY_RVA;
    if (memcmp(e2, expect2, 7) != 0)
    {
        log_msg("[CJK] v23 EFCBA 头部核验失败：%02X %02X %02X %02X %02X %02X %02X，跳过\n",
                e2[0], e2[1], e2[2], e2[3], e2[4], e2[5], e2[6]);
        return 0;
    }
    g_efcbaTramp = (BYTE*)VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_efcbaTramp) return 0;
    memcpy(g_origEFCBA, e2, 7);
    memcpy(g_efcbaTramp, e2, 7);
    g_efcbaTramp[7] = 0xE9;
    // ★ v23b 修复：E9 在 tramp[7]，下一条指令 = tramp+12，rel 必须相对 tramp+12！
    //   （原写 -13 多减 1 → 同样栈破坏崩溃）
    *(DWORD*)(g_efcbaTramp + 8) = ((DWORD)e2 + 7) - ((DWORD)g_efcbaTramp + 12);
    VirtualProtect(e2, 7, PAGE_EXECUTE_READWRITE, &oldProt);
    e2[0] = 0xE9;
    *(DWORD*)(e2 + 1) = (DWORD)cjk_efcba_probe - ((DWORD)e2 + 5);
    VirtualProtect(e2, 7, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), e2, 7);

    log_msg("[CJK] v23 只读探针安装：F9CCA本体=%08X EFCBA本体=%08X（CJK_probe_log.txt）\n",
            (DWORD)e1, (DWORD)e2);
    return 1;
}

// ═══════════════════════════════════════════════════════════════════════
// ★ v23d：EXE 文件 API IAT 探针——记录所有 .xrg 文件打开 + caller
//
//   ◆ 为什么需要：探针日志证明教程 TEXT（LM01.xrg「你拾起了一支火把」）
//     完全不经 GameWorld 的 sub_100F9CCA（F9CCA 只看到 NPC 对话，全部完整）。
//     教程 LM01.xrg 是 *dialogue 格式，但由 Enclave.exe 主程序直接解析渲染
//     （v16l 结论：教程直接渲染路径）→ 截断发生在 EXE 自己的文本存储/拷贝链。
//   ◆ 方案：hook Enclave.exe 的 KERNEL32.CreateFileA / ReadFile IAT 槽
//     （RVA 0x770DC / 0x770B4，解析导入表实证），记录：
//       - lpFileName（CreateFileA 参数1）
//       - caller（返回地址 = [esp] 保存）
//     只记录文件名含 ".xrg"/".XRG" 或 "LM0"/"DM" 的 → CJK_file_log.txt
//   ◆ 目的：定位 LM01.xrg 被哪个函数打开 → 反查该函数就是教程解析入口。
// ═══════════════════════════════════════════════════════════════════════
#define IAT_EXE_CREATEFILEA_RVA 0x770DCu  // Enclave.exe KERNEL32.CreateFileA IAT 槽
#define IAT_EXE_READFILE_RVA    0x770B4u  // Enclave.exe KERNEL32.ReadFile IAT 槽
#define IAT_GW_CREATEFILEA_RVA  0x13E0A8u // GameWorld KERNEL32.CreateFileA IAT 槽（DIALOGUES 加载器用）
#define IAT_GW_READFILE_RVA     0x13E07Cu // GameWorld KERNEL32.ReadFile IAT 槽
#define IAT_MS_CREATEFILEA_RVA  0x11C0A8u // MSystem KERNEL32.CreateFileA IAT 槽（CDiskUtil 文件核心）
#define IAT_MS_READFILE_RVA     0x11C084u // MSystem KERNEL32.ReadFile IAT 槽
// ★ v23i：EXE → MCCDyn.CCFile 的 IAT 槽（IDA 逆向 MCCDyn.dll 实证）——
//   教程 .xrg 由 CCFile::Open(VCStr) + Readln() 逐行读取，底层 CByteStream/CStream_XDF
//   自研虚拟文件系统完全绕过 CreateFileA（v23d/e/f 全 0 条的真因）。
//   这两个槽是 EXE 侧教程加载的【必经入口】，hook 它们必能抓到文件名+行内容。
#define IAT_EXE_MCC_OPEN_RVA   0x77268u // Enclave.exe MCCDyn.CCFile::Open(VCStr,int,ECompressTypes,ESettings) IAT 槽
#define IAT_EXE_MCC_READLN_RVA 0x77270u // Enclave.exe MCCDyn.CCFile::Readln() IAT 槽
static void* (__thiscall* g_origExeCcOpen)(void* self, void* vcstr, int a2, int a3, int a4);
static void* (__thiscall* g_origExeCcReadln)(void* self, void* out);
static volatile LONG g_inCcProbe = 0;
static DWORD g_tmpCcCaller = 0;   // naked 中转存
static void* g_tmpCcOut = NULL;   // naked 中转存
static BOOL   (WINAPI* g_origExeReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static BOOL   (WINAPI* g_origGwReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static HANDLE(WINAPI* g_origGwCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static HANDLE(WINAPI* g_origMsCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static BOOL   (WINAPI* g_origMsReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static volatile LONG g_inFileProbe = 0;

static void file_probe_log(const char* name, DWORD caller)
{
    char buf[300];
    static DWORD s_count = 0;
    if (!name) return;
    // ★ v23f：v23d/v23e 过滤 .xrg 后 0 条 → LM01.xrg 不走 CreateFileA 或文件名不同。
    //   改为记录【前 400 条全部文件打开】+ caller，看启动时真实文件访问序列。
    if (s_count >= 400) return;
    s_count++;
    wsprintfA(buf, "[%04d] caller=%08X name=%s\n", s_count, caller, name);
    HANDLE h = CreateFileA("CJK_file_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);
    DWORD written;
    WriteFile(h, buf, lstrlenA(buf), &written, NULL);
    CloseHandle(h);
}

// ★ v23i：CCFile::Open(VCStr) 文件名 log（教程 .xrg 加载必经）
//   v23k：加 SEH 保护（CCFile::Open 可能被非文本用途调用，VCStr.p 可能是坏指针）
static void cc_open_log(const char* file, DWORD caller)
{
    char buf[320];
    static DWORD s_cnt = 0;
    if (!file) return;
    if (s_cnt >= 200) return;
    __try
    {
        // 只记 xrg/对话/教程相关（过滤音效贴图等噪声）
        if (!(strstr(file, ".xrg") || strstr(file, ".XRG") ||
              strstr(file, "LM0") || strstr(file, "DM0") ||
              strstr(file, "Dialogues") || strstr(file, "DIALOGUES") ||
              strstr(file, "dialogue"))) return;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    s_cnt++;
    wsprintfA(buf, "[CC_OPEN %04d] caller=%08X file=%s\n", s_cnt, caller, file);
    HANDLE h = CreateFileA("CJK_cc_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);
    DWORD written;
    WriteFile(h, buf, lstrlenA(buf), &written, NULL);
    CloseHandle(h);
}

// ★ v23i：CCFile::Readln() 返回行内容 log（out = CStr* {vtable@+0, char* p@+4}）
//   p 指向行文本（宽路径=UTF-16LE，窄路径=ASCII）。按 WORD 解码输出，宽窄通吃。
static void cc_readln_log(DWORD caller, void* out)
{
    char buf[900];
    char* p = buf;
    const char* txt;
    static DWORD s_cnt = 0;
    int i;
    if (s_cnt >= 400) return;
    __try
    {
        if (!out) return;
        txt = *(const char**)((char*)out + 4);  // CStr.p @ +4
        if (!txt) return;
        for (i = 0; i < 48; i++)                // 预扫描：确认可读
        {
            if (*(WORD*)(txt + i * 2) == 0) break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    s_cnt++;
    p += wsprintfA(p, "[READLN %04d] caller=%08X ", s_cnt, caller);
    for (i = 0; i < 48; i++)
    {
        WORD w;
        __try { w = *(WORD*)(txt + i * 2); }
        __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        if (w == 0) break;
        if (w >= 0x20 && w <= 0x7E) p += wsprintfA(p, "%c", (char)w);
        else if ((w >= 0x4E00 && w <= 0x9FFF) || (w >= 0x3000 && w <= 0x30FF))
            p += wsprintfA(p, "[%04X]", w);
        else p += wsprintfA(p, "<%02X%02X>", w & 0xFF, w >> 8);
    }
    p += wsprintfA(p, "\n");
    HANDLE h = CreateFileA("CJK_cc_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);
    DWORD written;
    WriteFile(h, buf, (DWORD)(p - buf), &written, NULL);
    CloseHandle(h);
}

// ★ v23d：naked 完美转发——进入时栈=[ret, lpFileName, dwDesiredAccess, ...]
//   pushad 后 [esp+0x20]=caller(ret), [esp+0x24]=lpFileName
//   log 完 popad → jmp 原函数（栈原样，stdcall 参数完整）→ 零开销正确返回
static HANDLE(WINAPI* g_origExeCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

static void __declspec(naked) my_ExeCreateFileA(void)
{
    __asm
    {
        pushad
        ; pushad 布局: [0x20]=caller(ret), [0x24]=lpFileName, [0x28]=dwDesiredAccess ...
        cmp  byte ptr [g_inFileProbe], 1
        je   cf_skip
        mov  byte ptr [g_inFileProbe], 1
        mov  eax, [esp + 0x24]          ; lpFileName
        mov  ebx, [esp + 0x20]          ; caller
        push eax                        ; 参数2: name
        push ebx                        ; 参数1: caller
        call file_probe_log
        add  esp, 8
        mov  byte ptr [g_inFileProbe], 0
    cf_skip:
        popad
        jmp  dword ptr [g_origExeCreateFileA]
    }
}

static BOOL WINAPI my_ExeReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                                  LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    return g_origExeReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

// ★ v23i：MCCDyn.CCFile::Open(VCStr,int,ECompressTypes,ESettings) IAT hook
//   进入（EXE call [IAT]）：[esp]=EXE caller, [esp+4]=VCStr(8B: p,len),
//                          [esp+0xC]=int, [esp+0x10]=ECompressTypes, [esp+0x14]=ESettings, ecx=this
//   naked 完美转发：log 文件名 + caller → popad → jmp 原函数（栈原样）
static void __declspec(naked) my_ExeCcOpen(void)
{
    __asm
    {
        pushad
        ; pushad 布局: [0x00]EDI [0x04]ESI [0x08]EBP [0x0C]ESP [0x10]EBX [0x14]EDX [0x18]ECX [0x1C]EAX
        ; [esp+0x20]=原[esp]=caller, [esp+0x24]=VCStr.p
        cmp  byte ptr [g_inCcProbe], 1
        je   co_skip
        mov  byte ptr [g_inCcProbe], 1
        mov  eax, [esp + 0x24]          ; VCStr.p（文件名）
        mov  ebx, [esp + 0x20]          ; caller
        test eax, eax
        jz   co_done
        push eax                        ; 参数2: file
        push ebx                        ; 参数1: caller
        call cc_open_log
        add  esp, 8
    co_done:
        mov  byte ptr [g_inCcProbe], 0
    co_skip:
        popad
        jmp  dword ptr [g_origExeCcOpen]
    }
}

// ★ v23i：MCCDyn.CCFile::Readln() IAT hook —— 调用后处理模式
//   进入：[esp]=EXE caller, [esp+4]=out(sret CStr*), ecx=this
//   流程：保存 caller/out → call 原函数（原函数填 out）→ log out 行内容 → ret 4 回 EXE
static void __declspec(naked) my_ExeCcReadln(void)
{
    __asm
    {
        cmp  byte ptr [g_inCcProbe], 1
        je   rl_noop
        mov  byte ptr [g_inCcProbe], 1
        mov  eax, [esp]                 ; caller
        mov  edx, [esp + 4]             ; out
        mov  [g_tmpCcCaller], eax
        mov  [g_tmpCcOut], edx
        ; 调原函数（thiscall：ecx=this 保持，[esp+4]=out 保持）
        ; call 压返回地址 → 原函数入口 [esp]=my_ret, [esp+4]=out ✓
        call dword ptr [g_origExeCcReadln]
        ; ★ 原函数 ret 4：弹 my_ret + 清 out → 回到这里时 [esp]=EXE_ret
        pushad
        push [g_tmpCcOut]               ; 参数2: out
        push [g_tmpCcCaller]            ; 参数1: caller
        call cc_readln_log
        add  esp, 8
        popad
        mov  byte ptr [g_inCcProbe], 0
        ret                             ; 只弹 EXE_ret（out 已由原函数 ret 4 清理）
    rl_noop:
        jmp  dword ptr [g_origExeCcReadln]
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ★ v23j：hook MCCDyn.CCFile::Open(VCStr,...) 函数本体（RVA 0x233C0）
//   —— 一网打尽 EXE/GameWorld/MSystem 所有模块对该函数的调用！
//   v23i 只 hook EXE 的 IAT 槽（0x77268/0x77270）→ 0 条 → 教程读取不在 EXE；
//   解析导入表实证 GW(0x13E340/0x13E338) 与 MS(0x11C430/0x11C5A4) 也导入 CCFile。
//   与其补 4 个 IAT 槽，直接 hook 函数本体（所有调用最终都落到这里）。
//   函数头：mov eax, large fs:0 = 64 A1 00 00 00 00（6 字节完整指令）
//   trampoline 复制 6B + E9 jmp → 0x233C6（push 0FFFFFFFFh，完整指令）
// ═══════════════════════════════════════════════════════════════════════
#define MCC_CCFILE_OPEN_RVA 0x233C0u   // MCCDyn CCFile::Open(VCStr,int,ECompressTypes,ESettings)
// ★ v23k：必须用 BYTE* + VirtualAlloc(PAGE_EXECUTE_READWRITE)！
//   v23j 用 BYTE[16] 数组 → `jmp dword ptr [g_openTramp]` 读数组前 4 字节
//   （=原函数头 64 A1 00 00 = 0x0000A164）当地址跳转 → Eip=0xA164 崩溃（dump 实证）
static BYTE*  g_openTramp = NULL;
static volatile LONG g_inCcProbe2 = 0;

// 进入：[esp]=caller, [esp+4]=VCStr(8B: vtable,p), [esp+0xC]=int, [esp+0x10]=ECompressTypes,
//        [esp+0x14]=ESettings, ecx=this
//   ★ VCStr 按值传 8B：低 4B=vtable@原[esp+4]，高 4B=p@原[esp+8]
//   pushad 压 8 regs=32B：原[esp+0]→[esp+0x20]、原[esp+4]→[esp+0x24]、
//   原[esp+8]→[esp+0x28]、原[esp+0xC]→[esp+0x2C]
//   ★ v23o 修正：v23k 误读 [esp+0x2C]（=int 参数）当文件名 p → strstr(int值) AV →
//   异常分发二次崩溃（ntdll+0x502F8 dump 实证）。正确偏移 = [esp+0x28]。
static void __declspec(naked) my_McCcOpen(void)
{
    __asm
    {
        pushad
        cmp  byte ptr [g_inCcProbe2], 1
        je   mo_skip
        mov  byte ptr [g_inCcProbe2], 1
        mov  eax, [esp + 0x28]          ; VCStr.p（文件名）★ v23o 修正（原 0x2C 是 int 参数）
        mov  ebx, [esp + 0x20]          ; caller
        test eax, eax
        jz   mo_done
        push eax                        ; 参数2: file
        push ebx                        ; 参数1: caller
        call cc_open_log
        add  esp, 8
    mo_done:
        mov  byte ptr [g_inCcProbe2], 0
    mo_skip:
        popad
        jmp  dword ptr [g_openTramp]    ; ★ 间接跳转到 trampoline（VirtualAlloc 可执行内存）
    }
}

// 安装：校验头部字节 → VirtualAlloc 建 trampoline → patch E9
static int install_ccfile_open_hook(void)
{
    HMODULE hCc;
    BYTE*   target;
    DWORD   oldProt;

    hCc = GetModuleHandleA("MCCdyn.dll");
    if (!hCc) return 0;
    target = (BYTE*)hCc + MCC_CCFILE_OPEN_RVA;
    __try
    {
        // 校验：64 A1 00 00 00 00 = mov eax, large fs:0
        if (target[0] != 0x64 || target[1] != 0xA1)
        {
            log_msg("[CJK] v23k CCFile::Open 头校验失败：%02X %02X %02X %02X %02X %02X，跳过\n",
                    target[0], target[1], target[2], target[3], target[4], target[5]);
            return 0;
        }
        if (!g_openTramp)
        {
            g_openTramp = (BYTE*)VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE,
                                              PAGE_EXECUTE_READWRITE);
            if (!g_openTramp) return 0;
        }
        // trampoline：复制 6B + E9 rel jmp (target+6)。E9 在 tramp[6]，下一条=tramp+11
        memcpy(g_openTramp, target, 6);
        g_openTramp[6] = 0xE9;
        *(DWORD*)(g_openTramp + 7) = ((DWORD)target + 6) - ((DWORD)g_openTramp + 11);
        // patch 函数头
        VirtualProtect(target, 6, PAGE_EXECUTE_READWRITE, &oldProt);
        target[0] = 0xE9;
        *(DWORD*)(target + 1) = (DWORD)my_McCcOpen - ((DWORD)target + 5);
        VirtualProtect(target, 6, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), target, 6);
        log_msg("[CJK] v23k MCCDyn CCFile::Open 本体 hook：%08X -> %08X（CJK_cc_log.txt）\n",
                (DWORD)target, (DWORD)my_McCcOpen);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return 1;
}

// ★ v23e：GameWorld 的 CreateFileA 也探（DIALOGUES 加载器 sub_1008D500 打开 LM01.xrg 走这里）
static void __declspec(naked) my_GwCreateFileA(void)
{
    __asm
    {
        pushad
        cmp  byte ptr [g_inFileProbe], 1
        je   gf_skip
        mov  byte ptr [g_inFileProbe], 1
        mov  eax, [esp + 0x24]          ; lpFileName
        mov  ebx, [esp + 0x20]          ; caller
        push eax
        push ebx
        call file_probe_log
        add  esp, 8
        mov  byte ptr [g_inFileProbe], 0
    gf_skip:
        popad
        jmp  dword ptr [g_origGwCreateFileA]
    }
}

// ★ v23f：MSystem 的 CreateFileA（CDiskUtil 文件核心）
static void __declspec(naked) my_MsCreateFileA(void)
{
    __asm
    {
        pushad
        cmp  byte ptr [g_inFileProbe], 1
        je   mf_skip
        mov  byte ptr [g_inFileProbe], 1
        mov  eax, [esp + 0x24]          ; lpFileName
        mov  ebx, [esp + 0x20]          ; caller
        push eax
        push ebx
        call file_probe_log
        add  esp, 8
        mov  byte ptr [g_inFileProbe], 0
    mf_skip:
        popad
        jmp  dword ptr [g_origMsCreateFileA]
    }
}

static BOOL WINAPI my_GwReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                                 LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    return g_origGwReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

static BOOL WINAPI my_MsReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                                 LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    return g_origMsReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

// 安装：校验 IAT 槽现值 = kernel32 导出地址后替换
// ★ v23g：拆成两半——EXE 部分在 DllMain 里【立即】执行（教程 LM01.xrg 在启动极早期
//   就被 EXE 读取，等 GameWorld 加载再 hook 会错过）；GW/MS 部分保持等 GameWorld。
// 先定义 EXE 专用安装（供 DllMain 调用）
static int install_exe_file_probe_hook(void)
{
    HMODULE hK32;
    HMODULE hExe;
    DWORD*  slot;
    DWORD   oldProt;
    DWORD   cur;

    hK32 = GetModuleHandleA("kernel32.dll");
    hExe = GetModuleHandleA(NULL);
    if (!hK32 || !hExe) return 0;
    g_exeBase = (DWORD)hExe;

    // EXE CreateFileA 槽
    slot = (DWORD*)(g_exeBase + IAT_EXE_CREATEFILEA_RVA);
    __try
    {
        cur = *slot;
        if (cur != (DWORD)GetProcAddress(hK32, "CreateFileA"))
        {
            log_msg("[CJK] v23g EXE CreateFileA 槽校验失败：%08X != %08X，跳过\n",
                    cur, (DWORD)GetProcAddress(hK32, "CreateFileA"));
            return 0;
        }
        g_origExeCreateFileA = (HANDLE(WINAPI*)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE))cur;
        VirtualProtect(slot, 4, PAGE_READWRITE, &oldProt);
        *slot = (DWORD)my_ExeCreateFileA;
        VirtualProtect(slot, 4, oldProt, &oldProt);
        log_msg("[CJK] v23g EXE CreateFileA IAT hook：%08X -> %08X（CJK_file_log.txt）\n",
                (DWORD)slot, (DWORD)my_ExeCreateFileA);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

    // EXE ReadFile 槽
    slot = (DWORD*)(g_exeBase + IAT_EXE_READFILE_RVA);
    __try
    {
        cur = *slot;
        if (cur != (DWORD)GetProcAddress(hK32, "ReadFile"))
        {
            log_msg("[CJK] v23g EXE ReadFile 槽校验失败：%08X != %08X，跳过\n",
                    cur, (DWORD)GetProcAddress(hK32, "ReadFile"));
            return 0;
        }
        g_origExeReadFile = (BOOL(WINAPI*)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED))cur;
        VirtualProtect(slot, 4, PAGE_READWRITE, &oldProt);
        *slot = (DWORD)my_ExeReadFile;
        VirtualProtect(slot, 4, oldProt, &oldProt);
        log_msg("[CJK] v23g EXE ReadFile IAT hook：%08X -> %08X\n", (DWORD)slot, (DWORD)my_ExeReadFile);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

    // ★ v23i：EXE → MCCDyn.CCFile::Open / Readln IAT 槽（教程 .xrg 加载必经入口）
    //   IDA 逆向 MCCDyn.dll 实证：CCFile::Open(VCStr)=0x100233C0, Readln=0x100223F0,
    //   CStr 结构={vtable@+0, p@+4}；底层 CByteStream/CStream_XDF 自研虚拟文件系统
    //   完全绕过 CreateFileA（v23d/e/f 全 0 条的真因）。
    {
        HMODULE hCc = GetModuleHandleA("MCCdyn.dll");
        if (hCc)
        {
            // CCFile::Open(VCStr,int,ECompressTypes,ESettings)
            slot = (DWORD*)(g_exeBase + IAT_EXE_MCC_OPEN_RVA);
            __try
            {
                cur = *slot;
                FARPROC pOpen = GetProcAddress(hCc,
                    "?Open@CCFile@@QAEXVCStr@@HW4ECompressTypes@@W4ESettings@@@Z");
                if (cur != (DWORD)pOpen)
                {
                    log_msg("[CJK] v23i EXE CCFile::Open 槽校验失败：%08X != %08X，跳过\n",
                            cur, (DWORD)pOpen);
                    return 0;
                }
                g_origExeCcOpen = (void* (__thiscall*)(void*, void*, int, int, int))cur;
                VirtualProtect(slot, 4, PAGE_READWRITE, &oldProt);
                *slot = (DWORD)my_ExeCcOpen;
                VirtualProtect(slot, 4, oldProt, &oldProt);
                log_msg("[CJK] v23i EXE CCFile::Open IAT hook：%08X -> %08X（CJK_cc_log.txt）\n",
                        (DWORD)slot, (DWORD)my_ExeCcOpen);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

            // CCFile::Readln() → 返回 CStr
            slot = (DWORD*)(g_exeBase + IAT_EXE_MCC_READLN_RVA);
            __try
            {
                cur = *slot;
                FARPROC pRln = GetProcAddress(hCc,
                    "?Readln@CCFile@@QAE?AVCStr@@XZ");
                if (cur != (DWORD)pRln)
                {
                    log_msg("[CJK] v23i EXE CCFile::Readln 槽校验失败：%08X != %08X，跳过\n",
                            cur, (DWORD)pRln);
                    return 0;
                }
                g_origExeCcReadln = (void* (__thiscall*)(void*, void*))cur;
                VirtualProtect(slot, 4, PAGE_READWRITE, &oldProt);
                *slot = (DWORD)my_ExeCcReadln;
                VirtualProtect(slot, 4, oldProt, &oldProt);
                log_msg("[CJK] v23i EXE CCFile::Readln IAT hook：%08X -> %08X\n",
                        (DWORD)slot, (DWORD)my_ExeCcReadln);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
        }
        else
        {
            log_msg("[CJK] v23i MCCdyn.dll 未加载，CCFile hook 跳过\n");
        }
    }

    return 1;
}

// GW/MS 文件探针（等 GameWorld 加载后由 install_hook 调用）
static int install_file_probe_hook(void)
{
    HMODULE hK32;
    DWORD*  slot;
    DWORD   oldProt;
    DWORD   cur;

    hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return 0;

    // ★ v23e：GameWorld CreateFileA/ReadFile（DIALOGUES 加载器 sub_1008D500 打开 LM01.xrg 走这里）
    if (g_gwBase)
    {
        slot = (DWORD*)(g_gwBase + IAT_GW_CREATEFILEA_RVA);
        __try
        {
            cur = *slot;
            if (cur != (DWORD)GetProcAddress(hK32, "CreateFileA"))
            {
                log_msg("[CJK] v23e GW CreateFileA 槽校验失败：%08X != %08X，跳过\n",
                        cur, (DWORD)GetProcAddress(hK32, "CreateFileA"));
                return 0;
            }
            g_origGwCreateFileA = (HANDLE(WINAPI*)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE))cur;
            VirtualProtect(slot, 4, PAGE_READWRITE, &oldProt);
            *slot = (DWORD)my_GwCreateFileA;
            VirtualProtect(slot, 4, oldProt, &oldProt);
            log_msg("[CJK] v23e GW CreateFileA IAT hook：%08X -> %08X\n",
                    (DWORD)slot, (DWORD)my_GwCreateFileA);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

        slot = (DWORD*)(g_gwBase + IAT_GW_READFILE_RVA);
        __try
        {
            cur = *slot;
            if (cur != (DWORD)GetProcAddress(hK32, "ReadFile"))
            {
                log_msg("[CJK] v23e GW ReadFile 槽校验失败：%08X != %08X，跳过\n",
                        cur, (DWORD)GetProcAddress(hK32, "ReadFile"));
                return 0;
            }
            g_origGwReadFile = (BOOL(WINAPI*)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED))cur;
            VirtualProtect(slot, 4, PAGE_READWRITE, &oldProt);
            *slot = (DWORD)my_GwReadFile;
            VirtualProtect(slot, 4, oldProt, &oldProt);
            log_msg("[CJK] v23e GW ReadFile IAT hook：%08X -> %08X\n",
                    (DWORD)slot, (DWORD)my_GwReadFile);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    }

    // ★ v23f：MSystem CreateFileA/ReadFile（CDiskUtil::FileExists 文件核心）
    {
        HMODULE hMs = GetModuleHandleA("MSystem.dll");
        if (hMs)
        {
            slot = (DWORD*)((DWORD)hMs + IAT_MS_CREATEFILEA_RVA);
            __try
            {
                cur = *slot;
                if (cur != (DWORD)GetProcAddress(hK32, "CreateFileA"))
                {
                    log_msg("[CJK] v23f MS CreateFileA 槽校验失败：%08X != %08X，跳过\n",
                            cur, (DWORD)GetProcAddress(hK32, "CreateFileA"));
                    return 0;
                }
                g_origMsCreateFileA = (HANDLE(WINAPI*)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE))cur;
                VirtualProtect(slot, 4, PAGE_READWRITE, &oldProt);
                *slot = (DWORD)my_MsCreateFileA;
                VirtualProtect(slot, 4, oldProt, &oldProt);
                log_msg("[CJK] v23f MS CreateFileA IAT hook：%08X -> %08X\n",
                        (DWORD)slot, (DWORD)my_MsCreateFileA);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

            slot = (DWORD*)((DWORD)hMs + IAT_MS_READFILE_RVA);
            __try
            {
                cur = *slot;
                if (cur != (DWORD)GetProcAddress(hK32, "ReadFile"))
                {
                    log_msg("[CJK] v23f MS ReadFile 槽校验失败：%08X != %08X，跳过\n",
                            cur, (DWORD)GetProcAddress(hK32, "ReadFile"));
                    return 0;
                }
                g_origMsReadFile = (BOOL(WINAPI*)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED))cur;
                VirtualProtect(slot, 4, PAGE_READWRITE, &oldProt);
                *slot = (DWORD)my_MsReadFile;
                VirtualProtect(slot, 4, oldProt, &oldProt);
                log_msg("[CJK] v23f MS ReadFile IAT hook：%08X -> %08X\n",
                        (DWORD)slot, (DWORD)my_MsReadFile);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
        }
        else
        {
            log_msg("[CJK] v23f MSystem 未加载，文件探针跳过 MSystem 槽\n");
        }
    }

    return 1;
}

// ═══════════════════════════════════════════════════════════════════════
// ★ v18（x64dbg 动态取证定案）：hook Localize_SubstituteKeys 内 call 0x44EA 调用点
//   （MSystem RVA 0x10ABEA）——§L 键名展开的【最终写入点】！
//
//   ◆ x64dbg 断点实证（写断点 @ 0x001A96D1 命中，1 秒内）：
//     call 0x44EA 前参数：ecx=目标(v4), edx=1(目标宽), esi=0x03FFA3B2(源), edi=0x0B(长度)
//     源内容 = 27 53 50 41 43 45 27 00 = 'SPACE'（窄 ASCII 8 字节，带单引号包裹！）
//     但调用 push 0x01 声明【源为宽】→ 0x44EA 按 word 读 → 'S(0x5327) PA(0x4150) CE(0x4543)
//     伪宽字符 → 渲染器查字形表失败 → 全部回退 @（这就是「按@@@跳跃」的真身）
//     长度 edi=0x0B=11 也是按"宽字符"算的 → 越界读到堆垃圾 → 目标里出现 07 FF 残留
//
//   ◆ 修复：把 5 字节 call 0x44EA 替换为 jmp 到本 handler——
//     自扫源窄字节（直到 0x00），每个 ASCII 全角化（+0xFEE0）写宽目标，
//     返回前修正调用者 ebp(目标)/esi(源) 推进，jmp 回 0x10ABF6 继续循环。
//     这样键名 'SPACE → ＳＰＡＣＥ（全角，GB2312 新字库有字形）→ 正常显示！
//
//   ◆ 为什么是这里：教程 §L 展开走 SubstituteKeys（0x10AA20），不经过任何
//     Localize_Str IAT 槽（v16l-v17d 全部落空的原因）——此调用点是键名写入
//     渲染缓冲的唯一必经之路。
// ═══════════════════════════════════════════════════════════════════════
#define MS_CONV_BODY_RVA 0x44EAu        // 0x44EA 函数本体（编码转换，__fastcall(ecx,edx)+栈3参）
static BYTE  g_origConvBody[5];          // 备份原函数头
static void* g_convTramp = NULL;         // trampoline：原5B + jmp entry+5
static BOOL  g_hookedConv = FALSE;

// v18d handler：hook 0x44EA 函数本体（正常 call，栈上有返回地址）
// 进入：ecx=目标(窄指针), edx=目标宽标志(a2), [esp+0]=返回地址,
//       [esp+4]=源(a3), [esp+8]=源宽标志(a4), [esp+0xC]=长度(a5)
// 窄源->宽目标（a2==1 && a4==0）且非 § 控制符：逐字节全角化 -> ret 0x0C
// 其他（含源首字节 0xA7=§，§Z22 前缀保护）：jmp trampoline 走原逻辑
static void __declspec(naked) cjk_conv_impl(void)
{
    __asm
    {
        ; edx = 目标宽标志；[esp+8] = 源宽标志
        cmp  edx, 1
        jne  conv_orig                  ; 目标不是宽 -> 原逻辑
        cmp  dword ptr [esp + 8], 0
        jne  conv_orig                  ; 源是宽 -> 原逻辑（宽文本汉字不受影响）
        ; § 保护：源首字节 0xA7（§ 控制符，如 §Z22 窄前缀）→ 原逻辑（不破坏控制符）
        mov  eax, [esp + 4]             ; 源指针
        cmp  byte ptr [eax], 0xA7
        je   conv_orig
        ; -- 窄源->宽目标：逐字节全角化 --
        pushad
        ; pushad 后：[0x20]=返回地址 [0x24]=源 [0x28]=源宽标志 [0x2C]=长度
        mov  esi, [esp + 0x24]          ; 源（窄）
        mov  edi, [esp + 0x18]          ; 原 ecx = 目标（宽）
        mov  ebx, [esp + 0x2C]          ; 长度 a5
        xor  edx, edx                   ; 源偏移
    conv_loop:
        test ebx, ebx
        jz   conv_done
        movzx eax, byte ptr [esi + edx]
        test eax, eax
        jz   conv_fill                  ; 源 0x00（键名 NUL 提前于越界长度）-> 空格填充
        cmp  eax, 0x20
        jb   conv_raw
        cmp  eax, 0x7E
        ja   conv_raw
        add  eax, 0xFEE0                ; 半角 ASCII -> 全角（0xFF00-0xFF5E）
    conv_raw:
        mov  [edi], ax                  ; 写宽字符
        add  edi, 2
        inc  edx
        dec  ebx
        jmp  conv_loop
    conv_fill:
        mov  word ptr [edi], 0x3000     ; 全角空格填充剩余槽
        add  edi, 2
        dec  ebx
        jnz  conv_fill
    conv_done:
        popad
        ret  0x0C                       ; __stdcall 3 栈参（与 0x44EA 一致）
    conv_orig:
        jmp  dword ptr [g_convTramp]    ; 原 5B + jmp 0x100044F0 继续原逻辑
    }
}

static int install_conv_hook(void)
{
    BYTE* entry;
    DWORD oldProt;
    HMODULE hMs;
    // 0x44EA 函数头期望：8B 44 24 0C 85 C0（mov eax,[esp+0xC]; test eax,eax）
    static const BYTE expect[5] = {0x8B, 0x44, 0x24, 0x0C, 0x85};
    if (g_hookedConv) return 1;
    hMs = GetModuleHandleA("MSystem.dll");
    if (!hMs) return 0;
    g_msBase = (DWORD)hMs;
    // hook 0x44EA 本体
    entry = (BYTE*)(g_msBase + MS_CONV_BODY_RVA);
    if (memcmp(entry, expect, 5) != 0)
    {
        log_msg("[CJK] v18d 0x44EA 头部核验失败：%02X %02X %02X %02X %02X，跳过\\n",
                entry[0], entry[1], entry[2], entry[3], entry[4]);
        return 0;
    }
    g_convTramp = VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_convTramp) return 0;
    memcpy(g_origConvBody, entry, 5);
    memcpy(g_convTramp, entry, 5);
    ((BYTE*)g_convTramp)[5] = 0xE9;
    *(DWORD*)((BYTE*)g_convTramp + 6) = ((DWORD)entry + 5) - ((DWORD)g_convTramp + 11);
    if (!VirtualProtect(entry, 5, PAGE_EXECUTE_READWRITE, &oldProt)) return 0;
    entry[0] = 0xE9;
    *(DWORD*)(entry + 1) = (DWORD)cjk_conv_impl - ((DWORD)entry + 5);
    VirtualProtect(entry, 5, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), entry, 5);
    g_hookedConv = TRUE;
    log_msg("[CJK] v18d 0x44EA 本体 hook（窄源->宽目标全角化）：%08X -> %08X\\n",
            (DWORD)entry, (DWORD)cjk_conv_impl);
    return 1;
}

// ═══════════════════════════════════════════════════════════════════════
// ★ v18e：0x10ABEA 调用点 handler——【键名特征判别】（v18d push1→0 一刀切失败后回归）
//
//   ◆ v18d 教训：0x10ABEA 是所有 §L 宏展开值（不只键名）的通道——把 push 1→0
//     会把宽中文文本值（加载游戏/难度名）也当窄源 → 逐字节全角化 → 乱码。
//   ◆ v18e 判别【键名格式约定】：键名 = `'XXX'`（首尾单引号 U+0027）！
//     - 源首字节 0x27（窄键名 'SPACE）或首 word 0x0027（宽键名）→ 键名 → 全角化
//     - 其他 → 宽文本值 → 模拟原 call 0x44EA（push 返回地址 0x10ABEF → jmp 原 0x44EA
//       入口，hook 后 a4=1 走 trampoline 原逻辑）→ 宽文本完全不受影响
//   ◆ 键名全角化：写满 len 槽（NUL 用全角空格填充），推进 ebp/esi += 2*len，
//     jmp 回 0x10ABF9（test ax,ax + ax=0 → 内层循环退出）
// ═══════════════════════════════════════════════════════════════════════
#define MS_SUBST_CALL_RVA 0x10ABEAu     // call 0x44EA 指令地址（SubstituteKeys 内）
#define MS_SUBST_BACK_RVA 0x10ABF9u     // 循环退出点（test ax,ax）
#define MS_SUBST_RET_RVA  0x10ABEFu     // 原 call 返回地址（lea eax,[edi+edi]）

// ═══════════════════════════════════════════════════════════════════════
// ★ v23q：hook SubstituteKeys 本体（0x10AA20）入口 —— §L 宏预展开（竞态根治）
//
//   【问题】教程文本（.xrg *TEXT "按 §LTUTORIAL_WEAPON 取出武器"）渲染时由引擎
//   SubstituteKeys（MSystem 0x10AA20）展开 §L → 键名（半角 ASCII）逐字形写入输出
//   缓冲 ⟷ 渲染并行读 → 键名随机缺失 1-2 字符 + 半角 ASCII 无字形 → 句尾 @。
//   v23m 的预展开在 hook1（tfstr_cjk_wide 0x10054F00）内，但教程 TEXT 构造不走
//   hook1（tfstr_log 实证只有资源名 "SN"）→ 预展开从未生效（key_display_lookup
//   从未被调用）。v23l 的 text_fix_thread（全内存暴力补写）能临时掩盖但写坏内存崩。
//
//   【修法】在 SubstituteKeys 入口【原子预展开输入】：检测 §L → 展开为全角键名
//   （tfstr_expand_keys：§L→KB_→EXE 物理键表→全角）→ 写回输入缓冲（只缩短）。
//   引擎随后展开时无 §L 可展 → 无逐字形写入 → 竞态消失；键名已全角 → 无 @。
//   覆盖【所有】§L 文本路径（教程/菜单/字幕）——不依赖具体调用点。
//
//   【失败安全】改写只在【缩短】时进行（en < n），绝不扩展越界；VirtualProtect+SEH
//   保护；查不到键名时 tfstr_expand_keys 原样回退 §L（保留原文，最坏 = 现状）。
//   key_display_lookup = v23n 纯防御版（限长 64/跳 0 限 8/条目 ≤64）安全。
// ═══════════════════════════════════════════════════════════════════════
static int tfstr_expand_keys(const WORD* src, int n, WORD* dst, int cap);   // 定义在下方
#define MS_SUBST_ENTRY_RVA  0x10AA20u   // SubstituteKeys 本体（mov eax,fs:[0] 头 6B）
#define SUBST_ENTRY_HDR_BYTES 6
static BYTE  g_origSubstEntry[SUBST_ENTRY_HDR_BYTES];
static BYTE* g_substEntryTramp = NULL;
static BOOL  g_hookedSubstEntry = FALSE;

// 预展开 SubstituteKeys 输入文本（textPtr = UTF-16 §L 文本缓冲）
static void __declspec(noinline) cjk_subst_expand_input(DWORD textPtr)
{
    static volatile LONG s_cnt = 0, s_probe = 0;
    __try
    {
        if (textPtr < 0x10000 || textPtr > 0x7FFEFFFF) return;
        WORD* w = (WORD*)textPtr;
        int n = 0, hasSL = 0, hasCjk = 0, i;
        // 求长度 + 检测 §L（A7 00 4C 00）+ 统计 CJK/全角（§L 汉化文本必有中文正文，
        // 全 ASCII 的引擎内部缓冲【绝不改写】——防误判 A7 4C 误写坏内存）
        while (n < 252 && w[n])
        {
            WORD c = w[n];
            if (!hasSL && n + 1 < 252 && c == 0x00A7 && w[n + 1] == 0x004C) hasSL = 1;
            if ((c >= 0x4E00 && c <= 0x9FFF) || (c >= 0x3000 && c <= 0x303F) ||
                (c >= 0xFF00 && c <= 0xFFEF)) hasCjk = 1;
            n++;
        }
        // ★ v23q.7 诊断：记录【所有含中文的】输入（前 100 条）——加载画面 §LSTD_LOADING
        //   （纯 ASCII key 无中文）不记录防刷屏；教程提示（含中文正文）无论 SL=0/1 必记录，
        //   直接判定：教程文本到底经不经 SubstituteKeys 0x10AA20 入口、§L 是否已在上游展开。
        if (hasCjk)
        {
            LONG p = InterlockedIncrement(&s_probe);
            if (p <= 100)
            {
                char sb[380]; char* q = sb;
                q += wsprintfA(q, "[SUBST %ld] ptr=%08X n=%d SL=%d CJK=%d | ", p, textPtr, n, hasSL, hasCjk);
                for (i = 0; i < 20 && i < n + 1; i++) q += wsprintfA(q, "%04X ", (unsigned)w[i]);
                q += wsprintfA(q, "\n");
                HANDLE h = CreateFileA("CJK_subst_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                                       NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (h != INVALID_HANDLE_VALUE)
                {
                    SetFilePointer(h, 0, NULL, FILE_END);
                    DWORD wn; WriteFile(h, sb, (DWORD)(q - sb), &wn, NULL);
                    CloseHandle(h);
                }
            }
        }
        if (!hasSL || !hasCjk || n < 4) return;
        WORD ebuf[260];
        int en = tfstr_expand_keys(w, n, ebuf, 256);
        if (en <= 0 || en >= n) return;          // 只缩短才改写（绝不扩展越界）
        DWORD old;
        if (VirtualProtect((void*)textPtr, (n + 1) * 2, PAGE_READWRITE, &old))
        {
            for (i = 0; i < en; i++) w[i] = ebuf[i];
            w[en] = 0;
            VirtualProtect((void*)textPtr, (n + 1) * 2, old, &old);
            LONG c = InterlockedIncrement(&s_cnt);
            if (c <= 20)
                log_msg("[CJK] v23q SubstituteKeys 预展开：%d WORD -> %d WORD @ %08X\n",
                        n, en, textPtr);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
}

static void __declspec(naked) cjk_subst_entry_impl(void)
{
    __asm
    {
        ; 进入：[esp]=ret, [esp+4]=文本指针（SubstituteKeys 第一参数——反汇编实证：
        ;   0x1010AA2E mov eax,[esp+0x10] 是在 push -1/push handler/push eax(旧fs) 三个
        ;   SEH 头【之后】，即 = 原始 [esp+4]。★ v23q.2 修正：之前误取 [esp+0x10]（a4）。
        ; pushad 后：文本指针 = [esp+0x20+4] = [esp+0x24]
        pushad
        mov  eax, [esp + 0x24]
        test eax, eax
        jz   se_done
        push eax
        call cjk_subst_expand_input
        add  esp, 4
    se_done:
        popad
        jmp  dword ptr [g_substEntryTramp]   ; trampoline：原 6B + jmp 原函数+6
    }
}

static int install_subst_entry_hook(void)
{
    BYTE* entry;
    DWORD oldProt;
    HMODULE hMs;
    static const BYTE expect[SUBST_ENTRY_HDR_BYTES] = {0x64, 0xA1, 0x00, 0x00, 0x00, 0x00};
    if (g_hookedSubstEntry) return 1;
    hMs = GetModuleHandleA("MSystem.dll");
    if (!hMs) return 0;
    g_msBase = (DWORD)hMs;
    entry = (BYTE*)(g_msBase + MS_SUBST_ENTRY_RVA);
    if (memcmp(entry, expect, SUBST_ENTRY_HDR_BYTES) != 0)
    {
        log_msg("[CJK] v23q SubstituteKeys 入口核验失败：%02X %02X %02X %02X %02X %02X，跳过\n",
                entry[0], entry[1], entry[2], entry[3], entry[4], entry[5]);
        return 0;
    }
    memcpy(g_origSubstEntry, entry, SUBST_ENTRY_HDR_BYTES);
    // trampoline：VirtualAlloc 可执行（★ 铁律：不能 BYTE[16] 数组）
    g_substEntryTramp = (BYTE*)VirtualAlloc(NULL, 32, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!g_substEntryTramp) return 0;
    memcpy(g_substEntryTramp, entry, SUBST_ENTRY_HDR_BYTES);
    g_substEntryTramp[6] = 0xE9;
    *(DWORD*)(g_substEntryTramp + 7) = ((DWORD)entry + SUBST_ENTRY_HDR_BYTES) -
                                       ((DWORD)g_substEntryTramp + 11);
    if (!VirtualProtect(entry, SUBST_ENTRY_HDR_BYTES, PAGE_EXECUTE_READWRITE, &oldProt)) return 0;
    entry[0] = 0xE9;
    *(DWORD*)(entry + 1) = (DWORD)cjk_subst_entry_impl - ((DWORD)entry + 5);
    VirtualProtect(entry, SUBST_ENTRY_HDR_BYTES, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), entry, SUBST_ENTRY_HDR_BYTES);
    g_hookedSubstEntry = TRUE;
    log_msg("[CJK] v23q SubstituteKeys 本体 hook：%08X -> %08X（入口 §L 预展开，6B trampoline）\n",
            (DWORD)entry, (DWORD)cjk_subst_entry_impl);
    return 1;
}
static DWORD g_substBackVA = 0;         // 运行时 = g_msBase + MS_SUBST_BACK_RVA
static DWORD g_substRetVA  = 0;         // 运行时 = g_msBase + MS_SUBST_RET_RVA
static DWORD g_convOrigVA  = 0;         // 运行时 = g_msBase + MS_CONV_BODY_RVA（0x44EA 入口）
static BOOL  g_hookedSubst = FALSE;

// ★ v23q6：键名判别（C 函数）——解决 v23q5 第 3 字节判别的两难：
//   'MOUSE1'(27 4D 4F..) 第 3 字节字母被误判汉字（乱码）；"大"(27 59 76..) 被误判键名（乱码）。
//   正确判别：键名 = 'X...' 全 ASCII 字母数字，以 0x27(右引号) 或 0x00 结束；
//   汉字文本（UTF-16）字节序列含 >0x80 的高字节（"大恶魔"的魔 0x9B / "大多数人"的人 0xBA）→ 非键名。
static int __declspec(noinline) cjk_is_keyname(const char* s)
{
    int i;
    if (!s || s[0] != 0x27) return 0;
    for (i = 1; i < 64; i++)
    {
        unsigned char c = (unsigned char)s[i];
        if (c == 0x27) return 1;                 // 右引号 → 键名
        if (c == 0) return 1;                     // 无右引号（0 结束）→ 键名
        if (c >= 0x80) return 0;                  // >0x80 = 汉字 UTF-16 高字节 → 非键名
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_')) return 0;   // 非字母数字 → 非键名
    }
    return 0;
}

// ★ v23q7 诊断：v18e subst_key 分支实际处理的键名（前 200 次）——
//   确认竞态源：逐字形全角化写入目标缓冲 ⟷ 渲染并行读（缺尾部随机）
static void __declspec(noinline) cjk_key_diag(const char* src, int len, void* dst)
{
    static volatile LONG s_cnt = 0;
    LONG c = InterlockedIncrement(&s_cnt);
    if (c > 200) return;
    char sb[256]; char* q = sb;
    q += wsprintfA(q, "[KEYDIAG %ld] src=%08X dst=%08X len=%d | ", c, src, dst, len);
    for (int i = 0; i < 14 && i < len; i++) q += wsprintfA(q, "%02X ", (unsigned char)src[i]);
    q += wsprintfA(q, "| '");
    for (int i = 0; i < 14 && i < len; i++)
    {
        unsigned char ch = (unsigned char)src[i];
        *q++ = (ch >= 0x20 && ch < 0x7F) ? ch : '.';
    }
    *q++ = '\''; *q++ = '\n';
    HANDLE h = CreateFileA("CJK_keydiag_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        SetFilePointer(h, 0, NULL, FILE_END);
        DWORD wn; WriteFile(h, sb, (DWORD)(q - sb), &wn, NULL);
        CloseHandle(h);
    }
}

static void __declspec(naked) cjk_subst_key_impl(void)
{
    __asm
    {
        ; 进入：esp→src, esp+4→0x01(源宽标志), esp+8→len(v14); ecx=目标, edx=1
        ; 键名判别：解引用源指针读首字节 0x27（' 窄键名）或首 word 0x0027（宽键名）
        ; ★v18f：v18e 误写 byte ptr [esp]（读栈上源指针低字节，键名检测完全失效 + 随机误判）
        ; ★v23q6：cjk_is_keyname（C 函数）精确判别——'X...' 全 ASCII 以 27/0 结束 = 键名；
        ;   汉字"大"(U+5927 LE 27 59)低字节 0x27 巧合 + "大恶魔"字节含 0x9B(>0x80) → 非键名
        mov  eax, [esp]                 ; eax = 源指针
        cmp  byte ptr [eax], 0x27
        jne  ck_wide_word
        push ecx                        ; ★ 保存 ecx/edx（not_key 路径 jmp 0x44EA 需要原值）
        push edx
        push eax
        call cjk_is_keyname
        add  esp, 4
        pop  edx
        pop  ecx
        test eax, eax
        jnz  subst_key
        jmp  not_key
    ck_wide_word:
        cmp  word ptr [eax], 0x0027
        jne  not_key
    subst_key:
        ; ── 键名：全角化写入，写满 len 槽 ──
        pushad
        ; pushad 后：[0x20]=src [0x24]=0x01 [0x28]=len
        mov  esi, [esp + 0x20]          ; 源
        mov  edi, [esp + 0x18]          ; 原 ecx = 目标（宽）
        mov  ebx, [esp + 0x28]          ; len
        ; ★ v23q7 诊断：记录实际处理的键名（源/目标/长度/字节）
        push edi
        push ebx
        push esi
        call cjk_key_diag
        add  esp, 12
        xor  edx, edx                   ; 源偏移
        ; 宽窄判别：byte[1]==0 → 宽键名（逐宽字符）；否则窄键名（逐字节）
        cmp  byte ptr [esi + 1], 0
        je   k_wide
    k_nloop:
        test ebx, ebx
        jz   k_done
        movzx eax, byte ptr [esi + edx]
        test eax, eax
        jz   k_fill
        cmp  eax, 0x20
        jb   k_nraw
        cmp  eax, 0x7E
        ja   k_nraw
        add  eax, 0xFEE0                ; 半角 → 全角
    k_nraw:
        mov  [edi], ax
        add  edi, 2
        inc  edx
        dec  ebx
        jmp  k_nloop
    k_wide:
        ; 宽键名：逐宽字符（ASCII 全角化）
    k_wloop:
        test ebx, ebx
        jz   k_done
        movzx eax, word ptr [esi + edx*2]
        test eax, eax
        jz   k_fill
        cmp  eax, 0x20
        jb   k_wraw
        cmp  eax, 0x7E
        ja   k_wraw
        add  eax, 0xFEE0
    k_wraw:
        mov  [edi], ax
        add  edi, 2
        inc  edx
        dec  ebx
        jmp  k_wloop
    k_fill:
        mov  word ptr [edi], 0x3000     ; 全角空格填充剩余槽
        add  edi, 2
        dec  ebx
        jnz  k_fill
    k_done:
        ; ★ v18h：推进 = 2*实际写入数（edx）——v14 对窄键名越界（'SPACE 7字节→v14=11），
        ;   用 v14 推进会在键名后留 4 全角空格（用户抱怨「大量空格」）；
        ;   改推进 = 2*实际 → 主循环 v4 紧凑 → 键名段后直接接后续文本，无空格尾巴
        mov  eax, edx                   ; 实际写入字符数（k_nloop/k_wloop 每写 1 字符 inc edx）
        shl  eax, 1
        add  [esp + 0x08], eax          ; 保存的 EBP += 2*实际
        add  [esp + 0x04], eax          ; 保存的 ESI += 2*实际
        popad
        add  esp, 0x0C                  ; 清 3 参数（src/0x01/len）
        xor  eax, eax                   ; ax=0 → 0x10ABF9 test ax,ax 命中 jz → 内层退出
        jmp  dword ptr [g_substBackVA]
    not_key:
        ; ── 非键名（宽文本值）：模拟原 call 0x44EA ──
        ;   push 返回地址(0x10ABEF) → jmp 0x44EA 原入口（v18f 禁用 0x44EA 本体 hook，
        ;   直接走原逻辑；宽文本完全不受影响）
        push  dword ptr [g_substRetVA]
        jmp   dword ptr [g_convOrigVA]
    }
}

static int install_subst_hook(void)
{
    BYTE* entry;
    DWORD oldProt;
    HMODULE hMs;
    // 期望字节：E8 FB 98 EF FF = call 0x44EA
    static const BYTE expect[5] = {0xE8, 0xFB, 0x98, 0xEF, 0xFF};
    if (g_hookedSubst) return 1;
    hMs = GetModuleHandleA("MSystem.dll");
    if (!hMs) return 0;
    g_msBase = (DWORD)hMs;
    entry = (BYTE*)(g_msBase + MS_SUBST_CALL_RVA);
    if (memcmp(entry, expect, 5) != 0)
    {
        log_msg("[CJK] v18e 落点核验失败：%02X %02X %02X %02X %02X，跳过\n",
                entry[0], entry[1], entry[2], entry[3], entry[4]);
        return 0;
    }
    g_substBackVA = g_msBase + MS_SUBST_BACK_RVA;
    g_substRetVA  = g_msBase + MS_SUBST_RET_RVA;
    g_convOrigVA  = g_msBase + MS_CONV_BODY_RVA;
    if (!VirtualProtect(entry, 5, PAGE_EXECUTE_READWRITE, &oldProt)) return 0;
    entry[0] = 0xE9;
    *(DWORD*)(entry + 1) = (DWORD)cjk_subst_key_impl - ((DWORD)entry + 5);
    VirtualProtect(entry, 5, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), entry, 5);
    g_hookedSubst = TRUE;
    log_msg("[CJK] v18e SubstituteKeys 键名写入 hook：%08X -> %08X（键名'XXX'全角化，宽文本值模拟原调用）\n",
            (DWORD)entry, (DWORD)cjk_subst_key_impl);
    return 1;
}


// ═══════════════════════════════════════════════════════════════════════
// ★ v16t：hook CImage::Write（MSystem RVA 0x3DE10）——文本绘制的最终出口！
//   __thiscall Write(CImage* this, CRct rect(16B), const CStr& text)
//   text（CStr*）= [esp+0x14]（入口处）。函数头 = mov eax, fs:0（64 A1 00 00 00 00，6 字节）。
//   前置处理（不改返回地址）：hook_impl 里先全角化 text 数据（safe_fullwidth_expanded），
//   再 jmp trampoline 执行原函数 → 覆盖字幕/教程/UI 所有文本绘制（含教程缓冲！）。
// ═══════════════════════════════════════════════════════════════════════
#define MS_CIMAGE_WRITE_RVA 0x3DE10u
#define DRAWHDR_BYTES 6
static BYTE  g_origDrawBody[DRAWHDR_BYTES];
static void* g_drawTramp = NULL;
static BOOL  g_hookedDraw = FALSE;
static DWORD g_drawOrigRet = 0;

// ★ v16v：记录所有绘制文本前 32 WORD → CJK_draw2_log.txt（前 300 条，不过滤）——
//   教程缓冲若走 CImage::Write 必记录（v16u 的 hasHi 过滤可能误伤）
static void draw_log2(const WORD* data)
{
    static volatile LONG s_c = 0;
    LONG n;
    int i;
    char sb[900], *p;
    if (!data) return;
    __try
    {
        n = InterlockedIncrement(&s_c);
        if (n > 300) return;
        p = sb;
        p += wsprintfA(p, "[DRAW2 %ld] caller=%08X | ", n, g_drawOrigRet - g_msBase);
        for (i = 0; i < 32; i++)
            p += wsprintfA(p, "%04X ", (unsigned)data[i]);
        p += wsprintfA(p, "\n");
        {
            HANDLE h = CreateFileA("CJK_draw2_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                                   NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE)
            {
                SetFilePointer(h, 0, NULL, FILE_END);
                DWORD wn; WriteFile(h, sb, (DWORD)(p - sb), &wn, NULL);
                CloseHandle(h);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
}

// 前置处理：全角化 text（CStr*）数据 + 记录
static void __cdecl cjk_draw_pre(DWORD textPtr)
{
    WORD* data;
    if (!textPtr) return;
    __try
    {
        data = *(WORD**)(textPtr + 4);
        if (!data || data == (WORD*)-2) return;
        // data = [标志/窄前缀][UTF-16 正文…] → safe_fullwidth_expanded 从 data 起（§ 跳过逻辑处理前缀）
        safe_fullwidth_expanded((DWORD)data, g_drawOrigRet - g_msBase, 1024);
        draw_log2(data);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
}

static void __declspec(naked) cjk_draw_hook_impl(void)
{
    __asm
    {
        ; 进入：栈 [ret, rect0..3, text(CStr*)]
        pushad
        mov  eax, [esp + 0x34]                   ; text（CStr*）
        mov  ecx, [esp + 0x20]                   ; ret（原调用者）
        mov  g_drawOrigRet, ecx
        test eax, eax
        jz   skip
        push eax
        call cjk_draw_pre
        add  esp, 4
skip:
        popad
        jmp  dword ptr [g_drawTramp]             ; 原 6 字节 + jmp 原函数+6
    }
}

static int install_draw_hook(void)
{
    BYTE* entry;
    DWORD oldProt;
    HMODULE hMs;
    FARPROC pW;
    int i;
    static const BYTE expect[DRAWHDR_BYTES] = {0x64, 0xA1, 0x00, 0x00, 0x00, 0x00};
    if (g_hookedDraw) return 1;
    hMs = GetModuleHandleA("MSystem.dll");
    if (!hMs) return 0;
    // ★ v16u：GetProcAddress 拿真实运行时地址（不依赖 RVA 常量——v16t 用 RVA 0x3DE10
    //   落点核验失败：运行时 0x1003DE10 = 08 8B 4D DC 89 48 ≠ 文件 64 A1… → MSystem .text 运行时被改）
    pW = GetProcAddress(hMs, "?Write@CImage@@QAEXVCRct@@ABVCStr@@@Z");
    if (!pW) { log_msg("[CJK] GetProcAddress(CImage::Write) 失败\n"); return 0; }
    entry = (BYTE*)pW;
    memcpy(g_origDrawBody, entry, DRAWHDR_BYTES);
    log_msg("[CJK] v16u CImage::Write: hMs=%08X pW=%08X bytes=%02X %02X %02X %02X %02X %02X\n",
            (DWORD)hMs, (DWORD)pW,
            g_origDrawBody[0], g_origDrawBody[1], g_origDrawBody[2],
            g_origDrawBody[3], g_origDrawBody[4], g_origDrawBody[5]);
    for (i = 0; i < DRAWHDR_BYTES; i++)
        if (g_origDrawBody[i] != expect[i])
        {
            log_msg("[CJK] CImage::Write 落点核验失败（运行时被改，不 hook）：%02X %02X %02X %02X %02X %02X\n",
                    g_origDrawBody[0], g_origDrawBody[1], g_origDrawBody[2],
                    g_origDrawBody[3], g_origDrawBody[4], g_origDrawBody[5]);
            return 0;
        }
    g_drawTramp = VirtualAlloc(NULL, 20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_drawTramp) return 0;
    memcpy(g_drawTramp, g_origDrawBody, DRAWHDR_BYTES);
    ((BYTE*)g_drawTramp)[DRAWHDR_BYTES] = 0xE9;
    *(DWORD*)((BYTE*)g_drawTramp + DRAWHDR_BYTES + 1) =
        ((DWORD)entry + DRAWHDR_BYTES) - ((DWORD)g_drawTramp + DRAWHDR_BYTES + 5);
    if (!VirtualProtect(entry, DRAWHDR_BYTES, PAGE_EXECUTE_READWRITE, &oldProt)) return 0;
    entry[0] = 0xE9;
    *(DWORD*)(entry + 1) = (DWORD)cjk_draw_hook_impl - ((DWORD)entry + 5);
    entry[5] = 0x90;
    VirtualProtect(entry, DRAWHDR_BYTES, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), entry, DRAWHDR_BYTES);
    g_hookedDraw = TRUE;
    log_msg("[CJK] v16t CImage::Write 本体 hook：%08X -> %08X（文本绘制出口，前置全角化）\n",
            (DWORD)entry, (DWORD)cjk_draw_hook_impl);
    return 1;
}

// 改写一个 IAT 槽：校验通过才写。返回 1 = 成功
static int iat_hook_one(DWORD modBase, DWORD iatRva, FARPROC expected,
                        void* newFunc, void** pOrig, const char* tag)
{
    DWORD* slot;
    DWORD  oldProt;
    DWORD  cur;

    if (!modBase || !expected || !newFunc) return 0;
    slot = (DWORD*)(modBase + iatRva);

    __try
    {
        cur = *slot;
        if (cur != (DWORD)expected)
        {
            log_msg("[CJK] IAT %s 校验失败：槽 %08X 现值 %08X != 导出 %08X（跳过，不改）\n",
                    tag, (DWORD)slot, cur, (DWORD)expected);
            return 0;
        }
        if (!VirtualProtect(slot, sizeof(DWORD), PAGE_READWRITE, &oldProt)) return 0;
        *pOrig = (void*)cur;
        *slot  = (DWORD)newFunc;
        VirtualProtect(slot, sizeof(DWORD), oldProt, &oldProt);
        log_msg("[CJK] IAT %s hook 成功：%08X  %08X -> %08X\n",
                tag, (DWORD)slot, cur, (DWORD)newFunc);
        return 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
// ★ v14：TFStr 宽处理双 hook（2026-08-08 09:40）——"攀"句截断根治
//   根因（反汇编定案）：引擎对 UTF-16 字幕文本存在两处【单字节】处理：
//     ① 0x10054F00（TFStr<252> 构造）：vsnprintf %s + strlen 按单字节写文本
//        → UTF-16 低字节 0x00 字符（攀=6500 字节[00][65]、一=4E00、需=9700、开=5F00...
//          共 9 种 554 处）遇 0x00 截断 → "以及他们攀上..."只剩"以及他们"
//     ② 0x100EF94A（TFStr GetLength, vtable+0x64）：strlen 单字节 → 拼接(0x1008ECE0)
//        拷贝长度同样截断
//   修复：
//     ① hook 0x10054F00：文本参数字节1==0（UTF-16）→ 宽构造（wcslen + WORD 拷贝 + 00 00 终止）
//     ② hook 0x100EF94A：UTF-16 → 返回 wcslen×2（字节数，与原 strlen 字节数语义一致）
//   安全性：窄文本（UI/StringTable UTF-8）字节1≠0 → 走原逻辑，零影响
// ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
#define HOOK_TFSTR_RVA       0x54F00u    // TFStr<252> 构造
#define HOOK_TFSTRLEN_RVA    0xEF94Au    // TFStr GetLength (vtable+0x64)
#define TFSTR_VTABLE_RVA     0x1445FCu   // TFStr<252> vtable 地址（0x101445FC - 0x10000000）
#define TFSTR_HANDLER_RVA    0x12EAC8u   // 原函数 SEH handler（0x1012eac8 - 0x10000000）
#define TFSTR_RETOFF_RVA     0x54F07u    // 原函数 +7（跳过被 patch 的 7 字节）
#define TFSTR_MAX_WORDS      125         // 252 字节 / 2
#define TFSTR_GBK_MAX        250         // 内联缓冲 252 字节，留 1 字节终止 + 1 字节余量
#define CONCAT_BUF_DWORDS    63          // 拼接临时缓冲 252 字节 = 63 dword

static BYTE g_origTfstr[7];
static BYTE g_origTfstrLen[5];
static BOOL g_hookedTfstr = FALSE;
static BOOL g_hookedTfstrLen = FALSE;

// ────────────────────────────────────────────────────────────────────────
// ★ v16f 诊断：写 CJK_tfstr_log.txt
//   v16e 的教训：日志按「总条数」封顶，结果 0x8E362（常量 "SN..." 的构造，
//   每帧都调）在字幕出现之前就把 80 条配额吃光，真正想看的一条都没记上。
//   现在改为【按调用点分配额】：
//     · 未命中的调用点每个最多 3 条（够看清它是什么就行）
//     · 命中（识别为中文正文）的一律记录
//     · 全局总量 160 条封顶
// ────────────────────────────────────────────────────────────────────────
static void diag_write(const char* buf)
{
    static volatile LONG s_total = 0;
    if (InterlockedIncrement(&s_total) > 160) return;
    HANDLE h = CreateFileA("CJK_tfstr_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);
    DWORD written;
    WriteFile(h, buf, lstrlenA(buf), &written, NULL);
    CloseHandle(h);
}

#define DIAG_SITES      16
#define DIAG_PER_SITE   3

static void tfstr_diag(DWORD retRva, const WORD* w, int n, int strong, int hit)
{
    static DWORD s_site[DIAG_SITES];
    static LONG  s_cnt[DIAG_SITES];
    static int   s_sites = 0;
    int i, idx = -1;
    char buf[224];

    for (i = 0; i < s_sites; i++)
        if (s_site[i] == retRva) { idx = i; break; }
    if (idx < 0 && s_sites < DIAG_SITES)
    {
        idx = s_sites++;
        s_site[idx] = retRva;
        s_cnt[idx]  = 0;
    }
    if (idx >= 0)
    {
        s_cnt[idx]++;
        // 未命中的调用点：只留前 3 条，其余静默（否则会把配额刷爆）
        if (!hit && s_cnt[idx] > DIAG_PER_SITE) return;
    }

    wsprintfA(buf, "[TFSTR] ret=%05X n=%3d strong=%2d %s cnt=%d | %04X %04X %04X %04X %04X %04X\r\n",
              retRva, n, strong, hit ? "STASH" : "pass ", idx >= 0 ? s_cnt[idx] : 0,
              n > 0 ? w[0] : 0, n > 1 ? w[1] : 0, n > 2 ? w[2] : 0,
              n > 3 ? w[3] : 0, n > 4 ? w[4] : 0, n > 5 ? w[5] : 0);
    diag_write(buf);
}

// ────────────────────────────────────────────────────────────────────────
// ★ v23m：§L 键名预展开（原子完成，消灭渲染竞态）
//
//   x64dbg/CE 取证定案（2026-08-09）：
//     源头（未展开 §L、完整）→ 槽（未展开、完整）→ 展开器（§L→全角键名，
//     逐字形写入）⟷ 渲染（并行读取）→ 竞态 → 键名随机缺字（SPA/SPAC/MOU…）
//   ⇒ 修法：在【我们自己的写入者】tfstr_cjk_wide（hook 1，用户 CE 实证
//     6F155A65/6F155AF2 访问教程文本）里预展开 §L 宏，渲染读到已展开文本
//     → 无宏可展 → 竞态消失 → 键名稳定完整。
//
//   EXE 键名表（.data 0x48B830 → RVA 0x8B830，IDA 实证）：
//     每条 = [0x22 '"'][显示名]["KB_逻辑键名"]["unbind \""] 连续排布
//     例：'"C"'→"KB_CROUCH"、'"SPACE"'→"KB_JUMP"、'"F"'→"KB_DRINK_POTION"
//   教程映射（0x48C190 → RVA 0x8C190）TUTORIAL_X ↔ KB_X 语义对应：
//     TUTORIAL_JUMP → KB_JUMP → 显示名 "SPACE"（用户实证渲染 ＳＰＡＣＥ）
//   展开链：§LTUTORIAL_JUMP → 剥 "TUTORIAL_" 前缀拼 "KB_JUMP"
//          → 物理键表查逻辑键名 → 显示名 "SPACE" → ASCII+0xFEE0 全角化
// ────────────────────────────────────────────────────────────────────────
#define EXE_KEYTABLE_RVA 0x8B830u   // 物理键名表（IDA: 0x48B830 = 0x400000 + 0x8B830）

// 逻辑/教程键名 → 物理键显示名（查 EXE 物理键名表）
// ★ v23n：去掉 __try/__except，纯防御遍历【保证绝不触发异常】——
//   v23m 用 SEH + 无限 lstrlenA 扫描，读越界触发 AV → ntdll RtlpLookupFunctionEntry
//   （SEH 分发查函数表）二次崩溃（dump 实证：C0000005 @ ntdll RVA 0x502F8 mov ecx,[ecx]）
//   现在：字符串限长 64、跳过 0 限 8 DWORD、条目 ≤ 64
//   ⇒ 最多推进 64×(4+64+64+64+32)≈14KB，在 EXE .data（0x8B830→0xAF1B8）内，绝不越界
static const char* key_display_lookup(const char* key)
{
    char logical[80];
    BYTE* p;
    int   i, z;

    if (!g_exeBase || !key || !key[0]) return NULL;
    if (strncmp(key, "TUTORIAL_", 9) == 0)
        wsprintfA(logical, "KB_%s", key + 9);      // TUTORIAL_JUMP → KB_JUMP
    else if (strncmp(key, "KB_", 3) == 0)
        lstrcpynA(logical, key, sizeof(logical));
    else
        return NULL;

    p = (BYTE*)(g_exeBase + EXE_KEYTABLE_RVA);
    for (i = 0; i < 64; i++)
    {
        for (z = 0; z < 8 && *(volatile DWORD*)p == 0; z++) p += 4;  // 跳 0（限量）
        if (*(volatile DWORD*)p != 0x22) return NULL;                // 非 '"' → 表尾/异常
        p += 4;
        {
            int dl = 0; while (dl < 64 && p[dl]) dl++;               // 限长显示名
            const char* disp  = (const char*)p;
            p += dl + 1;
            int lg = 0; while (lg < 64 && p[lg]) lg++;               // 限长逻辑键名
            const char* logic = (const char*)p;
            if (lstrcmpiA(logic, logical) == 0) return disp;
            p += lg + 1;
            int ub = 0; while (ub < 64 && p[ub]) ub++;               // 限长 unbind 前缀
            p += ub + 1;
        }
    }
    return NULL;
}

// §L 宏展开：src（n WORD）→ dst（cap WORD），返回输出 WORD 数（不含终止符）
//   识别 §L（A7 00 4C 00）→ 提取键名（字母数字下划线）→ 查显示名 → 全角化；
//   查不到或失败时原样回退（不破坏原文本）。无 §L 时返回 0。
static int tfstr_expand_keys(const WORD* src, int n, WORD* dst, int cap)
{
    int si = 0, di = 0, found = 0;
    while (si < n && di < cap - 1)
    {
        WORD c = src[si];
        if (c == 0x00A7 && si + 1 < n && src[si + 1] == 0x004C)      // §L
        {
            int  keyStart = si + 2;
            char key[64];
            int  ki = 0;
            found = 1;
            while (keyStart + ki < n && ki < 63)
            {
                WORD kc = src[keyStart + ki];
                if (kc == 0 || kc == 0x20 || kc == 0x3000 || kc == 0x7C) break;
                if ((kc >= 'A' && kc <= 'Z') || (kc >= 'a' && kc <= 'z') ||
                    (kc >= '0' && kc <= '9') || kc == '_') key[ki] = (char)kc;
                else break;
                ki++;
            }
            key[ki] = 0;
            si = keyStart + ki;
            const char* disp = key_display_lookup(key);
            if (disp)
            {
                for (const char* q = disp; *q && di < cap - 1; q++)
                {
                    BYTE b = (BYTE)*q;
                    dst[di++] = (b >= 0x20 && b <= 0x7E) ? (WORD)b + 0xFEE0 : b;
                }
            }
            else
            {
                dst[di++] = 0x00A7;                                   // 回退 §L
                dst[di++] = 0x004C;
                for (int j = 0; j < ki && di < cap - 1; j++)
                    dst[di++] = src[keyStart + j];
            }
        }
        else
        {
            dst[di++] = c;
            si++;
        }
    }
    dst[di] = 0;
    return found ? di : 0;
}

// v23m 诊断：命中时记录输入形态（§L 检测 + 前 16 WORD 可读化）
static void tfstr_sl_diag(DWORD retRva, const WORD* w, int n, int hasSL, int expanded)
{
    static volatile LONG s_cnt = 0;
    char buf[320];
    char* p = buf;
    int   i;
    if (InterlockedIncrement(&s_cnt) > 60) return;
    p += wsprintfA(p, "[SL] ret=%05X n=%d §L=%d exp=%d | ", retRva, n, hasSL, expanded);
    for (i = 0; i < n && i < 16; i++)
    {
        WORD c = w[i];
        if (c == 0) { p += wsprintfA(p, "<00>"); break; }
        if (c >= 0x20 && c <= 0x7E) p += wsprintfA(p, "%c", (char)c);
        else if (c == 0x00A7)        p += wsprintfA(p, "§");
        else if (c >= 0x4E00 && c <= 0x9FFF) p += wsprintfA(p, "[%04X]", c);
        else if (c >= 0xFF00 && c <= 0xFF5E) p += wsprintfA(p, "F%02X", c & 0xFF);
        else                         p += wsprintfA(p, "<%04X>", c);
    }
    p += wsprintfA(p, "\r\n");
    diag_write(buf);
}

// 拼接收尾诊断：把最终写进目标对象的内容前若干字节原样 dump 出来
static void concat_diag(const char* tag, int prefixLen, int nWords, int total,
                        const BYTE* prefix, const WORD* w)
{
    static volatile LONG s_c = 0;
    char buf[256];
    if (InterlockedIncrement(&s_c) > 40) return;
    wsprintfA(buf, "[CONCAT] %s pfx=%d(%02X %02X %02X %02X) n=%d total=%d | %04X %04X %04X %04X\r\n",
              tag, prefixLen,
              prefixLen > 0 ? prefix[0] : 0, prefixLen > 1 ? prefix[1] : 0,
              prefixLen > 2 ? prefix[2] : 0, prefixLen > 3 ? prefix[3] : 0,
              nWords, total,
              nWords > 0 && w ? w[0] : 0, nWords > 1 && w ? w[1] : 0,
              nWords > 2 && w ? w[2] : 0, nWords > 3 && w ? w[3] : 0);
    diag_write(buf);
}

// ────────────────────────────────────────────────────────────────────────
// ★ v16f 宽文本暂存表
//   hook1 在字幕区识别出「UTF-16 中文正文」后，把整段宽文本按【目标对象指针】
//   存进来；hook4 在拼接收尾时用 [ebp+0xc]（正文对象）反查取回。
//   为什么要暂存而不是直接改对象：TFStr<252> 的数据要经过 vsnprintf/strlen 两道
//   单字节关卡，宽数据放在对象里必被腰斩；放在我们自己的表里则毫发无损。
// ────────────────────────────────────────────────────────────────────────
#define STASH_SLOTS   8
#define STASH_MAXW    125           // 252 字节 / 2

typedef struct
{
    void* obj;
    int   n;                        // WORD 数（0 = 该槽无效）
    WORD  w[STASH_MAXW];
} CjkStash;

static CjkStash g_stash[STASH_SLOTS];
static int      g_stashNext = 0;

static CjkStash* stash_find(void* obj)
{
    int i;
    if (!obj) return NULL;
    for (i = 0; i < STASH_SLOTS; i++)
        if (g_stash[i].obj == obj && g_stash[i].n > 0) return &g_stash[i];
    return NULL;
}

// n <= 0 表示「该对象这次构造的不是中文正文」→ 只作废旧记录，不写入。
// 这一步很关键：同一个栈对象会被反复复用，不作废就会拿旧内容顶替新内容。
static void stash_put(void* obj, const WORD* w, int n)
{
    int i, k = -1;
    if (!obj) return;
    for (i = 0; i < STASH_SLOTS; i++)
        if (g_stash[i].obj == obj) { k = i; break; }
    if (k < 0)
    {
        k = g_stashNext;
        g_stashNext = (g_stashNext + 1) % STASH_SLOTS;
    }
    g_stash[k].obj = NULL;          // 先失效，拷完再挂上
    g_stash[k].n   = 0;
    if (n <= 0 || n > STASH_MAXW) return;
    for (i = 0; i < n; i++) g_stash[k].w[i] = w[i];
    g_stash[k].n   = n;
    g_stash[k].obj = obj;
}

// ────────────────────────────────────────────────────────────────────────
// ★ v16f 核心数据结构：字节长度登记表
//
//   整个 bug 只有一个成因 —— 引擎在 4 个地方用【单字节 strlen】重新量长度，
//   而 UTF-16 正文里低字节为 0x00 的汉字（攀 6500 / 一 4E00 / 需 9700 …554 处）
//   会让 strlen 提前收工，把句子拦腰砍断。
//
//   注意：缓冲里是【窄前缀 §Z22 + 宽正文】的混合物，所以「wcslen×2」在收尾
//   阶段是错的。正确长度只有引擎自己知道（拼接时算在 eax 里）。
//   ⇒ 谁知道就谁登记：hook1 登记自建正文长度、hook4 登记拼接总长度，
//     后面的 strlen 点直接按【对象指针】查表取回，查不到就老老实实走原逻辑。
//
//   这样做的好处：不改变任何数据格式（v16c 已证明引擎原生就能正确渲染
//   「窄前缀 + UTF-16 正文」），只把被 strlen 弄错的长度纠正回来。
// ────────────────────────────────────────────────────────────────────────
#define LEN_SLOTS   32          // v16g：噪声不再占槽，32 槽给真实字幕留足余量（原为 12）
#define LEN_MAXB    249         // 252 内联缓冲 - 2 字节宽终止 - 1 字节余量

typedef struct
{
    void* obj;
    int   len;                  // 字节数（0 = 该槽无效）
} CjkLen;

static CjkLen g_len[LEN_SLOTS];
static int    g_lenNext = 0;

static int len_find(void* obj)
{
    int i;
    if (!obj) return 0;
    for (i = 0; i < LEN_SLOTS; i++)
        if (g_len[i].obj == obj && g_len[i].len > 0) return g_len[i].len;
    return 0;
}

// ★ v16g 抗刷槽修正：未命中（len<=0）且对象【不在表中】时，绝不占用/轮转槽位。
//   v16f 的致命缺陷：SND: 音效名（纯 ASCII、在字幕区间 0x8E362 内高频调用）
//   每次未命中都 len_put(obj,0) → 轮转吃掉 12 槽之一 → 字幕登记被挤出 → hook5
//   查不到 → 回落裸 strlen → 半截 + 句尾 @（表现即"闪烁"）。
//   现在：len<=0 只清「已存在」的条目；新对象一律不占槽，槽位专供真实字幕。
static void len_put(void* obj, int len)
{
    int i, k = -1;
    if (!obj) return;
    for (i = 0; i < LEN_SLOTS; i++)
        if (g_len[i].obj == obj) { k = i; break; }
    if (k >= 0)                       // 已存在 → 先作废（地址复用防串味）
    {
        g_len[k].obj = NULL;
        g_len[k].len = 0;
    }
    if (len <= 0 || len > LEN_MAXB) return;   // 未命中：不占新槽
    if (k < 0)                        // 仅新条目才轮转分配
    {
        k = g_lenNext;
        g_lenNext = (g_lenNext + 1) % LEN_SLOTS;
    }
    g_len[k].len = len;
    g_len[k].obj = obj;
}

// ────────────────────────────────────────────────────────────────────────
// ★ v16d 核心：字幕区 TFStr<252> 宽构造（用 C 实现，替代原汇编版）
//
//   为什么可以完全重写（反汇编定案 2026-07-22）：
//     0x100F18CA 基类构造 = 只写 vtable 0x101496DC，无其它字段
//     0x10054F3E             = 覆写 vtable 为 0x101445FC（TFStr<252>）
//     0x100F187A Assign      = GetCapacity 限长 → memcpy → 写 1 字节 0，【不存长度】
//   ⇒ TFStr<252> 的全部状态 = [obj+0] vtable + [obj+4..255] 内联数据缓冲。
//     所以「设 vtable + 拷贝数据 + 写终止符」与引擎原生构造等价。
//
//   原构造为什么会截断：0x10054F5D 调 vsnprintf(buf, 0xFC, 文本, va) —— 文本被当
//   【窄格式串】，UTF-16 里低字节为 0x00 的汉字（攀 U+6500 → 字节 00 65、一 4E00、
//   需 9700 …共 554 处）在此处终止 → "以及他们攀上…" 只剩 "以及他们"。
//
//   ★★★ v16f 路线定案（v16e 实测 + 反汇编交叉验证，2026-08-08 夜）★★★
//
//   v16e 曾把正文就地转成 GBK，理由是「渲染器是窄字节逐个取」。实测【整句消失】。
//   连同 v16c 的表现一起看，两条实证把结论钉死了：
//     · v16c：hook1 因 off-by-5 从未命中 ⇒ 对象里是引擎原生的 UTF-16（被 vsnprintf
//             截断过），屏幕上「以及他们」【显示完全正常】。
//     · v16e：写进合法 GBK ⇒ 屏幕上【一个字都没有】。
//   ⇒ 渲染器消费的是 UTF-16LE，不是 GBK。GBK 路线判死刑。
//   ⇒ 更重要的推论：引擎【原生就能正确渲染】「窄前缀 §Z22 + UTF-16 正文」的混合
//     缓冲。我们要做的根本不是改数据格式，而是【只把被 strlen 弄错的长度纠正回来】。
//
//   全链路 4 个单字节 strlen 点（已逐个反汇编确认）：
//     ① 0x10054F00  构造 vsnprintf(buf,0xFC,【文本当格式串】,va)   ← 本函数接管
//     ② 0x1008ED18  拼接取正文 GetLength                          ← hook3
//     ③ 0x1008EDA6 → 0x10054DA0 → 0x100EF96A  copy-ctor 裸 strlen  ← hook4
//     ④ 0x100F9B59  绘制前拷贝 0x100F9AFA 内的 strlen              ← hook5
//   拷贝动作本身全是 rep movsd，对 UTF-16 完全安全 —— 唯一的敌人就是 strlen。
//
//   本函数（①）做的事：识别出「UTF-16 中文正文」后，按 WORD 原样搬进内联缓冲，
//   补 2 字节宽终止，设回 TFStr<252> 的 vtable，并把真实字节长度登记进 g_len。
//   这与引擎原生构造【语义等价】（TFStr<252> 的全部状态就是 vtable + 内联缓冲，
//   没有长度字段），区别仅在于我们不会在 0x00 处停手。
//
//   返回 1 = 已完成构造（trampoline 直接 ret）；0 = 放行原逻辑。
// ────────────────────────────────────────────────────────────────────────
static int __cdecl tfstr_cjk_wide(void* obj, const void* text, DWORD retRva)
{
    const WORD* w = (const WORD*)text;
    int n = 0, strong = 0, pct = 0, hit = 0, i;

    if (!obj || !text) return 0;

    __try
    {
        // 1) 以「合法字幕正文字符」为边界求长度。
        //    ★ 刻意不以 0x0000 为界：万一判据误判窄串，也不会顺着堆内存一路扫到
        //      下一个 00 00，从而杜绝把堆垃圾拖进正文（句尾 @ 的经典成因）。
        //    上限 123 个 WORD（TFSTR_MAX_WORDS-2）：246 正文 + 4 前缀(§Z22) + 1 终止
        //    = 251 ≤ 252，永远触不到拼接函数的 clamp。
        //    ★ 为什么不是 124：拼接在 0x1008ED26 算 maxBody = 252 - 前缀 - 1 = 247（奇数），
        //      若正文 248 字节会被裁到 247 —— 正好把最后一个 UTF-16 码元切成半个，
        //      屏幕上就是一个无字形的垃圾字（句尾 @）。留 123 从根上避开。
        while (n < TFSTR_MAX_WORDS - 2 && is_body_char(w[n]))
        {
            WORD c = w[n];
            if (c == 0x0025) pct++;      // '%'：这是变参格式串，绝不接管
            if (c >= 0x4E00 && c <= 0x9FFF)
            {
                BYTE lo = (BYTE)(c & 0xFF);
                // 低字节不可打印 ⇒ 这个 WORD 不可能是「两个 ASCII 字符」的窄串误读
                if (lo < 0x20 || lo > 0x7E) strong++;
            }
            n++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

    // 2) 严格判据（宁可放行也不误判）：
    //    n >= 4      → 挡掉引擎窄格式串 "§Z%i"/"§Z22"（只有 2 个 WORD，其字节
    //                  A7 5A 25 69 误读成 WORD 后同样落在 CJK 区间），也挡掉
    //                  v16e 日志里刷屏 80 条的 "SN"（窄字节误读成 WORD 0x4E53）
    //    strong >= 2 → 至少两个「低字节不可打印的汉字」，纯 ASCII 窄串永远不满足
    //    pct == 0    → 含 '%' 的一律放行，保住 vsnprintf 的变参替换语义
    hit = (n >= 4 && strong >= 2 && pct == 0);

    if (hit)
    {
        int hasSL = 0, expanded = 0;
        __try
        {
            WORD* dst = (WORD*)((BYTE*)obj + 4);        // 数据【内联】在 +4
            // ★ v23m：检测 §L 宏（A7 00 4C 00）→ 预展开为全角键名（原子完成）
            //   ★ v23n：__try 内【绝不 return】（SEH 局部展开在 naked 调用上下文有风险），
            //     只设 expanded 标志，统一走函数尾部 return hit —— 与 v23k 控制流一致。
            for (i = 0; i < n - 1; i++)
                if (w[i] == 0x00A7 && w[i + 1] == 0x004C) { hasSL = 1; break; }
            if (hasSL)
            {
                WORD ebuf[TFSTR_MAX_WORDS];
                int  en = tfstr_expand_keys(w, n, ebuf, TFSTR_MAX_WORDS);
                if (en > 0 && en < TFSTR_MAX_WORDS - 1)
                {
                    for (i = 0; i < en; i++) dst[i] = ebuf[i];
                    dst[en] = 0;
                    *(DWORD*)obj = g_gwBase + TFSTR_VTABLE_RVA;
                    len_put(obj, en * 2);               // 登记展开后字节长度
                    expanded = 1;
                }
            }
            if (!expanded)
            {
                for (i = 0; i < n; i++) dst[i] = w[i];  // 按 WORD 搬，0x00 不再是边界
                dst[n] = 0;                             // 宽终止 00 00
                *(DWORD*)obj = g_gwBase + TFSTR_VTABLE_RVA; // TFStr<252> vtable
                len_put(obj, n * 2);                    // ★ 登记真实字节长度
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { hit = 0; }
        if (hit) tfstr_sl_diag(retRva, w, n, hasSL, expanded);   // v23m 诊断
    }
    else
    {
        // 没接管：纯 ASCII（UI/资源名/格式串 "SN" 等）一律【不占槽、不写日志】——
        // 它们是噪声，v16f 就靠它们刷爆了诊断与登记表。只有"像 CJK"（含高字节 WORD）
        // 却没达标的未命中，才清旧登记（防栈地址复用把上一句的宽长度串到这一句）。
        int looksCjk = 0;
        for (i = 0; i < n && i < 16; i++)
            if ((w[i] & 0xFF00) != 0) { looksCjk = 1; break; }
        if (looksCjk)
            len_put(obj, 0);
        else
            return 0;                       // 纯 ASCII 直接放行，跳过诊断
    }

    tfstr_diag(retRva, w, n, strong, hit);
    return hit;
}

// ★ hook 1：0x10054F00（TFStr<252> 构造）——UTF-16 宽构造
//   入口：[esp]=返回地址、[esp+4]=目标对象(this)、[esp+8]=格式串/文本（cdecl 变参，调用者清栈）
//   ★ v16d 改动：
//     ① 【调用者区间过滤】[0x8D000,0x8F000]（与 hook3 一致），不再逐个比对地址。
//        原因：旧版白名单 0x8DD09/0x8DD31/0x8E362/0x8DDE3 是【call 指令地址】，
//              而 trampoline 比对的是【返回地址】= call 地址 + 5 → 永远对不上
//              → 全部 fallback 走窄构造 → 攀(U+6500) 截断 + 句尾偶发 @。
//     ② 宽构造逻辑整体迁到 C（tfstr_wide_build），汇编只做过滤与转交。
//        原汇编版有三处从未被执行过、一旦命中即引爆的隐患：
//          a. movzx ebx,[ecx+1] 在 fallback 前破坏 EBX（callee-saved）→ 调用者寄存器损坏
//          b. pushad/popad 不配对（诊断插入后多出一个 popad）→ 栈错位
//          c. 空串时 mov ebx,ecx=0 → dec/jnz 变 4G 次循环 → 越界写死
//        C 版天然规避，并可用 SEH 保护指针扫描。
static void __declspec(naked) cjk_tfstr_trampoline_impl(void)
{
    __asm
    {
        ; ★ v16d 调用者区间过滤：返回地址 RVA ∈ [0x8D000,0x8F000] 才是字幕 TFStr 构造
        ;   只使用 EAX/ECX/EDX（caller-saved）。★ 绝不能碰 EBX/ESI/EDI/EBP：
        ;   fallback 会跳回原函数，原函数保存/恢复的是我们改坏的值 → 调用者寄存器损坏。
        mov eax, [esp]               ; 返回地址（原始 caller）
        sub eax, g_gwBase            ; → RVA
        cmp eax, SUB_LO
        jb  tfstr_fallback
        cmp eax, SUB_HI
        ja  tfstr_fallback
        mov ecx, [esp + 8]           ; 文本指针（arg2 / 格式串）
        test ecx, ecx
        jz  tfstr_fallback
        mov edx, [esp + 4]           ; 目标对象（arg1 / this）
        ; tfstr_cjk_wide(obj, text, retRva) —— 判据 + 宽拷贝 + 长度登记 + 诊断全在 C 侧
        push eax
        push ecx
        push edx
        call tfstr_cjk_wide
        add esp, 12
        test eax, eax
        jz  tfstr_fallback           ; 0 → 放行原逻辑（此时 EBX/ESI/EDI/EBP 仍为原值）
        mov eax, [esp + 4]           ; 已完成构造：返回 this（与原函数 mov eax,esi 一致）
        ret
    tfstr_fallback:
        ; 重放被覆盖的 7 字节（push -1; push 修正后 handler）+ 跳回原函数+7
        push -1
        mov eax, g_gwBase
        add eax, TFSTR_HANDLER_RVA
        push eax
        mov eax, g_gwBase
        add eax, TFSTR_RETOFF_RVA
        jmp eax
    }
}

// ★ hook 2：0x100EF94A（TFStr GetLength, vtable+0x64）——UTF-16 返回字节数
//   原逻辑：GetData([ecx+4]) → strlen（单字节）→ UTF-16 截断
//   修复：UTF-16 → wcslen×2（字节数，语义与原 strlen 一致）
static void __declspec(naked) cjk_tfstrlen_trampoline_impl(void)
{
    __asm
    {
        pushad
        mov eax, [ecx]               ; vtable
        call dword ptr [eax + 0x20]  ; GetData → eax = &[this+4]（数据指针）
        test eax, eax
        jz  tflen_zero
        cmp byte ptr [eax + 1], 0    ; UTF-16？
        jne tflen_strlen
        ; ★ UTF-16: wcslen × 2
        xor ecx, ecx
    tflen_wcs:
        cmp word ptr [eax + ecx*2], 0
        je  tflen_wcs_done
        inc ecx
        cmp ecx, TFSTR_MAX_WORDS
        jl  tflen_wcs
    tflen_wcs_done:
        lea eax, [ecx*2]             ; 字节数 = 字符 × 2
        jmp tflen_done
    tflen_strlen:
        ; 原 strlen（窄文本路径）
        lea edx, [eax + 1]
    tflen_str:
        mov cl, byte ptr [eax]
        inc eax
        test cl, cl
        jne tflen_str
        sub eax, edx
        jmp tflen_done
    tflen_zero:
        xor eax, eax
    tflen_done:
        mov [esp + 0x1C], eax        ; 写回 pushad 的 eax 槽
        popad
        ret
    }
}

// ★ hook 3：0x1008ED1A（字幕拼接 0x1008ECE0 内的正文 GetLength 调用点）
//   修复：GetLength（strlen 单字节）对 UTF-16 正文截断 → 检测 UTF-16 后重算 wcslen×2（字节数）
//   字幕专用（0x1008ECE0 唯一调用者 0x8DD44），不碰通用函数
//   patch 5 字节：FF 52 64 8B F8（call [edx+0x64]; mov edi,eax）
#define HOOK_CONCATLEN_RVA   0x8ED1Au
#define CONCATLEN_RET_RVA    0x8ED1Fu
static BYTE g_origConcatLen[5];
static BOOL g_hookedConcatLen = FALSE;

// hook3 用：按正文对象指针取回 hook1 登记的真实字节数（取不到返回 0 = 放行）
static int __cdecl cjk_text_len(void* textObj)
{
    if (!textObj) return 0;
    return len_find(textObj);
}

static void __declspec(naked) cjk_concat_len_trampoline_impl(void)
{
    __asm
    {
        ; 重放原指令（0x1008ED1A-0x1E）
        call dword ptr [edx + 0x64]     ; 正文 GetLength → eax
        mov edi, eax                    ; edi = 原始长度（原指令语义）

        ; ★ v16e：所有路径统一经过 pushad/popad，并且 pushad 时 eax 必须是【长度】。
        ;   旧版缺陷（潜伏至今）：过滤用的 retRVA 存在 eax 里就 pushad，
        ;   非修正路径 popad 后 eax = retRVA，紧接着 mov edi,eax 把长度污染成
        ;   0x8DDxx（≈58 万）→ 拼接取 min(容量-前缀-1, 58万) = 247 字节整段拷贝，
        ;   把正文缓冲尾部的残留一起拖进字幕。现在改为先 pushad 再算 retRVA。
        pushad

        ; 调用者过滤：sub_1008ECE0 共 7 个调用者，仅字幕区 [0x8D000,0x8F000] 才处理，
        ; 其余（资源名/字符串处理）原样放行，绝不误改长度。
        ; [ebp+4] = sub_1008ECE0 调用者的返回地址（入口 push ebp; mov ebp,esp）
        mov eax, [ebp + 4]
        sub eax, g_gwBase
        cmp eax, SUB_LO
        jb  tcl_pop
        cmp eax, SUB_HI
        ja  tcl_pop

        ; ★ v16e 新增：清零拼接临时缓冲 —— 根除句尾垃圾字节
        ;   0x1008ED35 的 lea ecx,[esp+0x10] 与此处 esp 完全一致（中间无任何压栈），
        ;   即临时 TFStr 对象位于 esp0+0x10、内联数据区 esp0+0x14，长 252 字节。
        ;   pushad 后 esp = esp0-0x20 ⇒ 数据区 = esp+0x34。
        ;   引擎在 0x1008ED9A 只写【1 字节】终止符，其后是未初始化的栈残留；
        ;   预先整块清零后，终止符落在已归零区，尾部天然干净。
        ;   范围 [esp0+0x14, esp0+0x110) 完整落在 sub esp,0x108 的局部帧内，且不碰
        ;   +0xC 的长度变量与 +0x114 起的 SEH 链。
        cld
        lea edi, [esp + 0x34]
        xor eax, eax
        mov ecx, CONCAT_BUF_DWORDS
        rep stosd

        ; ★ v16f：改为【查登记表】取真实长度，不再靠字节特征去猜。
        ;   旧的「字节[1] ∈ [0x4E,0xA0)」判据有真实漏洞：以全角引号开头的句子
        ;   （“ = U+201C → 字节 1C 20，字节[1]=0x20）会被误判成窄串而漏修。
        ;   现在 hook1 接管构造时就把准确字节数登记进 g_len，这里按对象指针取回，
        ;   命中才改，取不到就完全放行 —— 判据与 hook1 天然一致，不存在错配。
        push dword ptr [ebp + 0xc]      ; 正文对象
        call cjk_text_len
        add esp, 4
        test eax, eax
        jz  tcl_pop
        mov [esp + 0x1C], eax           ; 写回 pushad 的 eax 槽
    tcl_pop:
        popad                           ; eax = 原始长度 或 修正长度
        mov edi, eax
        mov eax, g_gwBase
        add eax, CONCATLEN_RET_RVA      ; 跳回 0x1008ED1F
        jmp eax
    }
}

// ════════════════════════════════════════════════════════════════════════
// ★ hook 4：0x1008ED9A（拼接收尾）—— 绕过 copy-ctor 的裸 strlen
//
//   反汇编现场（sub_1008ECE0 尾部）：
//     1008ED95  mov esi,[ebp+8]           ; esi = 目标 TFStr
//     1008ED98  add eax,ebx               ; ★ eax = 前缀 + 正文 = 真实总字节数
//     1008ED9A  mov byte [esp+eax+0x14],0 ; ← patch 这 5 字节（C6 44 04 14 00）
//     1008ED9F  lea eax,[esp+0x10]
//     1008EDA3  push eax
//     1008EDA4  mov ecx,esi
//     1008EDA6  call 0x10054DA0           ; copy-ctor → 0x100EF96A 裸 strlen（杀手）
//     1008EDAB  mov ecx,[esp+0x114]       ; ← 我们直接跳到这里，跳过 copy-ctor
//     1008EDB3  mov eax,esi               ; 收尾自己设返回值，无需我们操心
//
//   关键点：0x1008ED98 那一刻，【引擎自己已经把正确的总字节数算在 eax 里】。
//   copy-ctor 之所以会截断，纯粹是因为它把这个现成的长度丢掉，改用 strlen 重数。
//   所以 hook4 什么都不用猜 —— 拿 eax 直接做等价的 Assign，然后跳过 copy-ctor。
//
//   对窄串同样正确（窄串的 total 本来就等于 strlen 结果），所以无需区分宽窄，
//   区间过滤内可以无条件接管。顺带根除「strlen 冲过终止符吃到栈垃圾」的句尾 @。
// ════════════════════════════════════════════════════════════════════════
#define HOOK_CONCATFIN_RVA   0x8ED9Au
#define CONCATFIN_ORIG_RVA   0x8ED9Fu   // 放行：重放原指令后回到这里
#define CONCATFIN_SKIP_RVA   0x8EDABu   // 接管：跳过 copy-ctor 直达收尾
static BYTE g_origConcatFin[5];
static BOOL g_hookedConcatFin = FALSE;

static void h4_diag(void* dst, const BYTE* p, int total)
{
    static volatile LONG s_c = 0;
    char buf[256];
    if (InterlockedIncrement(&s_c) > 24) return;
    wsprintfA(buf, "[H4] dst=%08X total=%3d | %02X %02X %02X %02X %02X %02X %02X %02X | tail %02X %02X %02X %02X\r\n",
              (DWORD)dst, total,
              p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
              total >= 4 ? p[total - 4] : 0, total >= 3 ? p[total - 3] : 0,
              total >= 2 ? p[total - 2] : 0, total >= 1 ? p[total - 1] : 0);
    diag_write(buf);
}

// 返回 1 = 已完成写入（trampoline 跳过 copy-ctor）；0 = 放行原逻辑
static int __cdecl cjk_concat_finish(void* dst, const BYTE* tmp, int total)
{
    BYTE* d;
    int i;

    if (!dst || !tmp) return 0;
    if (total <= 0 || total > LEN_MAXB) return 0;   // 越界一律放行，绝不冒险

    // ★★ v16i 关键修正：v16g 的抗刷判据【是错的】，导致 SND: 音效名依然被接管+登记。
    //
    //   v16g 写法：扫描 WORD 是否落在 CJK 区 U+4E00–U+9FFF，≥2 个即判为字幕。
    //   实测反证（v16h 日志 72 条 [H4] 全是 "SND:xxx"）：
    //       "SND:Sats_ground" 的字节按 WORD 误读 = 4E53 3A44 6153 7374 ...
    //       0x4E53('SN') 0x6153('aS') 0x7374('ts') —— 全部落在 CJK 区！
    //   根因：ASCII 字节 ∈ 0x20–0x7E，两两拼成 WORD 就是 0x2020–0x7E7E，
    //         与 CJK 区 0x4E00–0x9FFF 大面积重叠 ⇒ 朴素区间判据对 ASCII 形同虚设。
    //
    //   正确判据（与 hook1 第 847-851 行的 strong 逻辑对齐，两道 ASCII 绝无法伪造的关）：
    //     ① 纯 ASCII 字节流（全部 <0x80 且无 0x00）→ 必是窄资源名，直接放行
    //     ② strong = 「低字节不可打印的汉字」或「全角区 U+FF01–U+FFEF」
    //        - 汉字低字节不可打印：ASCII 对的低字节 = 字节[1] ∈ 0x20–0x7E 必可打印 ⇒ 永不满足
    //        - 全角区高字节 0xFF：ASCII 对最大 0x7E7E ⇒ 永不满足
    {
        const WORD* w = (const WORD*)tmp;
        int nw = total / 2;
        int strong = 0;
        int allAscii = 1;

        for (i = 0; i < total; i++)                  // ① 纯 ASCII 窄串判定
        {
            BYTE b = tmp[i];
            if (b == 0 || b >= 0x80) { allAscii = 0; break; }
        }

        if (!allAscii)                               // ② strong 判据
        {
            for (i = 2; i < nw && i < 132; i++)      // 跳过窄前缀 §Z22（2 WORD），限 130 WORD
            {
                WORD c = w[i];
                if (c >= 0x4E00 && c <= 0x9FFF)
                {
                    BYTE lo = (BYTE)(c & 0xFF);
                    if (lo < 0x20 || lo > 0x7E) strong++;   // 低字节不可打印 ⇒ 真汉字
                }
                else if (c >= 0xFF01 && c <= 0xFFEF) strong++;  // 全角（高字节 0xFF）
                if (strong >= 2) break;
            }
        }

        if (allAscii || strong < 2)
        {
            static volatile LONG s_skip = 0;
            // 纯 ASCII 是已知噪声，不占诊断配额；只记「像宽串却没达标」的可疑帧
            if (!allAscii && InterlockedIncrement(&s_skip) <= 12)
            {
                char b[160];
                wsprintfA(b, "[H4-SKIP] dst=%08X total=%3d strong=%d | %02X %02X %02X %02X %02X %02X %02X %02X\r\n",
                          (DWORD)dst, total, strong,
                          tmp[0],tmp[1],tmp[2],tmp[3],tmp[4],tmp[5],tmp[6],tmp[7]);
                diag_write(b);
            }
            return 0;                                // 非字幕 → 放行原 copy-ctor
        }
    }

    __try
    {
        d = (BYTE*)dst + 4;                          // TFStr<252> 数据内联在 +4
        for (i = 0; i < total; i++) d[i] = tmp[i];
        d[total]     = 0;                            // 宽终止 00 00
        d[total + 1] = 0;                            // （窄读也只见 1 个 0，无害）
        *(DWORD*)dst = g_gwBase + TFSTR_VTABLE_RVA;
        len_put(dst, total);                         // ★ 登记给 hook5 用
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

    h4_diag(dst, tmp, total);
    return 1;
}

static void __declspec(naked) cjk_concat_fin_trampoline_impl(void)
{
    __asm
    {
        ; 进入时（jmp 而来，未压任何东西）：
        ;   eax = 总字节数（前缀+正文），ebx = 前缀字节数，ebp = 拼接函数栈帧
        ;   临时缓冲数据区 = esp+0x14；目标对象 = [ebp+8]
        pushad                          ; esp -= 0x20 ⇒ 临时数据区 = esp+0x34

        ; 调用者过滤：sub_1008ECE0 有 7 个调用者，只有字幕区 [0x8D000,0x8F000]
        ; 才接管；资源名/字符串处理一律原样放行。
        mov ecx, [ebp + 4]              ; 拼接函数调用者的返回地址
        sub ecx, g_gwBase
        cmp ecx, SUB_LO
        jb  h4_orig
        cmp ecx, SUB_HI
        ja  h4_orig

        ; cjk_concat_finish(dst, tmp, total)  —— cdecl，参数从右往左压
        lea ecx, [esp + 0x34]           ; ★ 先算地址，再压栈（顺序不能反）
        push eax                        ; total
        push ecx                        ; tmp
        push dword ptr [ebp + 8]        ; dst
        call cjk_concat_finish
        add esp, 12
        test eax, eax
        jz  h4_orig

        popad
        mov edx, g_gwBase
        add edx, CONCATFIN_SKIP_RVA     ; 跳过 copy-ctor（edx 在收尾段未被使用）
        jmp edx

    h4_orig:
        popad
        mov byte ptr [esp + eax + 0x14], 0   ; 重放被 patch 的原指令
        mov edx, g_gwBase
        add edx, CONCATFIN_ORIG_RVA          ; 0x1008ED9F 处 eax/edx 都会被重设
        jmp edx
    }
}

// ════════════════════════════════════════════════════════════════════════
// ★ hook 5：0x100F9B59（绘制前拷贝 0x100F9AFA 内的 strlen）—— 最后一道关卡
//
//   反汇编现场：
//     100F9B3A  call [eax+0x4c]      ; 源 IsNarrow?  TFStr<252> 恒返回 1 ⇒ 必走窄
//     100F9B45  call [edx+0x28]      ; 源 GetData → eax
//     100F9B59  mov ecx,eax          ; ← patch 这 5 字节（8B C8 8D 71 01）
//     100F9B5B  lea esi,[ecx+1]
//     100F9B5E  mov dl,[ecx]/inc ecx/test dl,dl/jne   ; ★裸 strlen
//     100F9B67  mov edx,[edi] / sub ecx,esi
//     100F9B6B  push ecx / push eax / mov ecx,edi / call [edx+0x68]  ; 目标 Assign
//     100F9BA4  收尾（mov eax,edi）
//
//   注：这个函数其实有一条完整的【宽分支】（0x100F9B90 按 WORD 做 wcslen +
//   call [edx+0x88] AssignWide），但 TFStr<252> 的 vtable 把 +0x4C/+0x50 硬编码成
//   1/0（"我是窄类型"），所以永远走不到。曾考虑伪造 vtable 把它掰到宽分支，
//   但缓冲里是【窄前缀 §Z22 + 宽正文】的混合物，整块按 UTF-16 解释会让
//   0x1008DD8B 的 cmp byte [eax],0xA7 之后的字号解析错乱 —— 风险远大于收益。
//   ⇒ 仍走窄分支，只是把长度从 g_len 查回来，其余一切保持引擎原生。
// ════════════════════════════════════════════════════════════════════════
#define HOOK_DRAWLEN_RVA     0xF9B59u
#define DRAWLEN_ORIG_RVA     0xF9B5Eu   // 放行：重放 2 条原指令后回到这里
#define DRAWLEN_DONE_RVA     0xF9BA4u   // 接管：自己 Assign 完直达收尾
static BYTE g_origDrawLen[5];
static BOOL g_hookedDrawLen = FALSE;

// head[] = 绘制现场缓冲的头 10 字节。这是判定「是否还存在第 5 个截断点」的关键证据：
//   期望看到 A7 5A 32 32 开头（窄前缀 §Z22），紧跟正文的 UTF-16 码元。
// v16n：改为记录 data 前 64 字节（窄字节），区间外绘制（教程/UI）也可见
// v16o：纯 ASCII（资源名/路径如 "Main\Default"）不写日志 —— 否则刷爆配额，
//       只保留含 >0x7F 字节（UTF-16 中文/§Z22 前缀）的绘制文本
static void h5_diag(DWORD retRva, int found, int slen, const BYTE* data)
{
    static volatile LONG s_c = 0;
    char buf[340];
    char* p;
    int i, hasHi = 0;
    if (InterlockedIncrement(&s_c) > 400) return;
    p = buf;
    p += wsprintfA(p, "[H5] ret=%05X len=%3d strlen=%3d %-7s | ", retRva, found, slen,
                   found > 0 ? "RESCUED" : "miss");
    __try
    {
        for (i = 0; i < 64 && data[i]; i++)
        {
            if (data[i] > 0x7F) hasHi = 1;
            p += wsprintfA(p, "%02X ", data[i]);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
    if (!hasHi) return;
    p += wsprintfA(p, "\r\n");
    diag_write(buf);
}

// 返回 >0 = 用这个字节数；0 = 放行原 strlen
static int __cdecl cjk_draw_len(const void* data, DWORD retRva)
{
    void* obj;
    int len = 0, slen = 0, i;
    BYTE head[10];

    if (!data) return 0;
    for (i = 0; i < 10; i++) head[i] = 0;
    __try
    {
        // 0x100F9AFA 拿到的是 GetData 的结果（obj+4），回退 4 字节即对象指针
        obj = (void*)((BYTE*)data - 4);
        len = len_find(obj);
        while (slen < 252 && ((const BYTE*)data)[slen]) slen++;
        for (i = 0; i < 10; i++) head[i] = ((const BYTE*)data)[i];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

    h5_diag(retRva, len, slen, (const BYTE*)data);
    // ★ v18i：宽扫描接管（WORD 到 0x0000）——低字节 0x00 汉字（一/攀/需/开…）在窄 strlen 被腰斩！
    //   「你拾起了一支火把」→「你拾起了」：一=U+4E00（LE 字节 00 4E），窄 strlen 在 00 处停。
    //   宽扫描 > 窄扫描（存在 0x00 截断）→ 用宽长度（不限区间，0x00 汉字对象才触发，低风险；
    //   窄对象宽扫描越界会 >LEN_MAXB 自动不接管）
    {
        int wcnt = 0;
        while (wcnt < 252 && ((const WORD*)data)[wcnt]) wcnt++;
        int slen_wide = wcnt * 2;
        if (slen_wide > slen && slen_wide <= LEN_MAXB)
            return slen_wide;
    }
    // v16n：区间外（教程/UI 绘制）只记录不接管 —— 防止误改非字幕文本长度
    if (retRva < SUB_LO || retRva > SUB_HI) return 0;
    return (len > slen && len <= LEN_MAXB) ? len : 0;
}

static void __declspec(naked) cjk_draw_len_trampoline_impl(void)
{
    __asm
    {
        ; 进入时：eax = 数据指针，edi = 目标 CStr
        ;   0x100F9AFA 入口后压了 6 个 dword（-1/handler/fs/ecx/esi/edi）
        ;   ⇒ 此处返回地址 = [esp+0x18]；pushad 后 = [esp+0x38]
        pushad

        mov ecx, [esp + 0x38]
        sub ecx, g_gwBase               ; v16n：去掉区间过滤 —— 区间外（教程/UI）只记录不接管

        push ecx                        ; retRva
        push eax                        ; data
        call cjk_draw_len
        add esp, 8
        test eax, eax
        jz  h5_orig

        mov [esp + 0x18], eax           ; 长度写回 pushad 的 ECX 槽
        popad                           ; ⇒ ecx = 长度，eax = 数据指针（原样）

        mov edx, [edi]                  ; 目标 CStr 的 vtable
        push ecx                        ; len
        push eax                        ; ptr
        mov ecx, edi
        call dword ptr [edx + 0x68]     ; CStr::Assign(ptr, len)（被调用者清栈）
        mov eax, g_gwBase
        add eax, DRAWLEN_DONE_RVA       ; 0x100F9BA4 处 eax 会被 mov eax,edi 重设
        jmp eax

    h5_orig:
        popad
        mov ecx, eax                    ; 重放原指令 ①
        lea esi, [ecx + 1]              ; 重放原指令 ②
        mov edx, g_gwBase
        add edx, DRAWLEN_ORIG_RVA       ; 原 strlen 只用 dl，随后 mov edx,[edi] 重设
        jmp edx
    }
}

static BOOL install_hook(void)
{
    if (g_hooked) return TRUE;
    g_hGameWorld = GetModuleHandleA("GameWorld.dll");
    if (!g_hGameWorld) return FALSE;
    g_gwBase = (DWORD)g_hGameWorld;
    g_retVA = g_gwBase + RET_VA;
    g_thunkVA = g_gwBase + THUNK_RVA;

    // ★ v16i：IAT hook —— 覆盖所有 Localize_Str 调用点（§L 展开产物全角化）
    {
        HMODULE hMs = GetModuleHandleA("MSystem.dll");
        if (!hMs)
        {
            log_msg("[CJK] MSystem.dll 未加载，IAT hook 跳过（§L 全角化不生效）\n");
        }
        else
        {
            // ★ v16p：hook Localize_Str(wide) 函数本体（终极统一——所有变体最终都调它）
            install_wide_body_hook();
            // ★ v16q：hook Localize_FindKeyValue 本体（教程 §L 键名查表点 → 键名汉字映射）
            install_findkey_hook();
            // ★ v17d：hook CRegistry::GetValue(PBD)（0x100607B0）——教程渲染【读 DYNAMIC 值】的最终点！
            //   反汇编实证：EXE 7 个注册点（0x407553 等）vtable+0x124 = SetThisKey(this,key) 单参
            //   （只进节点不设值，v17b 的 SetThisKey(PBD,VCStr) 是另一重载，EXE 没调——移除）；
            //   教程渲染用运行时 §L 名（.xrg）查 DYNAMIC → GetValue(PBD) → 返回 '键名'。
            //   post 模式：key 含 TUTORIAL_ → 返回值 data 改写（'键名' → 中文）+ 日志。
            install_getval_hook();
            // ★ v20：hook GetValue 未命中分支【调用点】0x10060615（call 0x1000960A）
            //   ——修复「你拾起了一支火把」→「你拾起了」（低字节 0x00 汉字截断）！
            //   关键修正 vs v19：v19 hook 0x1000960A 函数本体（53 个调用点全拦）
            //   → 死循环；v20 只 hook GetValue 未命中这一处调用点（影响面最小），
            //   检测源是 UTF-16 宽文本 → 模拟 call 跳宽版 0x100096BA（WORD 扫不截断）。
            install_getval_call_hook();
            // ★ v21：hook GameWorld sub_1008E1C0 内 TEXT 存储调用点 0x8E20C
            //   （call sub_100F9CCA）——修复「你拾起了一支火把」→「你拾起了」！
            //   x64dbg 单步实证：教程 TEXT 首字符全角空格 0x3000（LE 00 30）→
            //   sub_100F9CCA 判定 [文本+1]&0x40 = 0 → 判窄 → 深拷贝窄 strlen 截断
            //   「一」(00 4E)；对白「救」0x6551 判宽完整。v20 未命中分支 hook 无效
            //   （教程查表命中）。v21 handler 检测 UTF-16 宽文本 → 强制走宽路径
            //   （sub_100FFD90 引用共享，不截断）。
            install_text_store_hook();
            // ★ v23：只读探针（F9CCA/EFCBA 本体）——log 含 CJK 文本的必经路径
            // ★ v23o：**禁用**（崩溃修复）——探针 trampoline 在 GameWorld 动态区执行，
            //   54296 dump 实证 Eip 落在 GameWorld+0xF9AC2 非指令边界（探针区域附近）。
            //   纯诊断用途，禁用不影响修复。
            // install_probe_hook();
            // ★ v18f：hook 0x10ABEA 调用点（键名'XXX'首字符判别——键名全角化，
            //   宽文本值模拟原 call 0x44EA 原样处理）。
            //   【v18f 禁用 0x44EA 本体 hook】：v18e 实测崩溃（0xC0000096 空跳转）——
            //   0x44EA 有 10 个调用点，本体 hook 拦截全部，其他场景特殊数据被全角化
            //   破坏 → 崩溃风险。仅保留 0x10ABEA 调用点 handler（影响面最小）。
            install_subst_hook();
            // ★ v23q：hook SubstituteKeys 本体入口——§L 预展开（竞态根治）。
            //   教程/菜单/字幕所有 §L 文本必经 SubstituteKeys（0x10AA20）；
            //   入口原子预展开 → 引擎无 §L 可展 → 键名随机缺失/句尾 @ 消失。
            install_subst_entry_hook();
            // ★ v16t：hook CImage::Write 本体（文本绘制出口，前置全角化 → 覆盖教程/字幕/UI）
            install_draw_hook();

            FARPROC pC = GetProcAddress(hMs, "?Localize_Str@@YAXVCStr@@PAGH@Z");
            FARPROC pN = GetProcAddress(hMs, "?Localize_Str@@YAXPBDPAGH@Z");
            FARPROC pW = GetProcAddress(hMs, "?Localize_Str@@YAXPBGPAGH@Z");
            HMODULE hGc;

            g_iatCount += iat_hook_one(g_gwBase, IAT_GW_CSTR_RVA,   pC,
                                       (void*)my_LocCStr,   (void**)&g_origLocCStr,   "GW/CStr");
            g_iatCount += iat_hook_one(g_gwBase, IAT_GW_NARROW_RVA, pN,
                                       (void*)my_LocNarrow, (void**)&g_origLocNarrow, "GW/narrow");
            g_iatCount += iat_hook_one(g_gwBase, IAT_GW_WIDE_RVA,   pW,
                                       (void*)my_LocWide,   (void**)&g_origLocWide,   "GW/wide");

            // ★ v16k：Enclave.exe（主程序）同样导入 3 个变体 —— 教程 HUD 走这里！
            //   实测导入表 IAT_RVA 0x773B0(CStr)/0x773B4(narrow)/0x773B8(wide)
            {
                HMODULE hExe = GetModuleHandleA(NULL);
                if (hExe)
                {
                    g_exeBase = (DWORD)hExe;
                    g_iatCount += iat_hook_one(g_exeBase, IAT_EXE_CSTR_RVA,   pC,
                                               (void*)my_LocExeCStr,   (void**)&g_origExeLocCStr,   "EXE/CStr");
                    g_iatCount += iat_hook_one(g_exeBase, IAT_EXE_NARROW_RVA, pN,
                                               (void*)my_LocExeNarrow, (void**)&g_origExeLocNarrow, "EXE/narrow");
                    g_iatCount += iat_hook_one(g_exeBase, IAT_EXE_WIDE_RVA,   pW,
                                               (void*)my_LocExeWide,   (void**)&g_origExeLocWide,   "EXE/wide");
                }
                else
                {
                    log_msg("[CJK] GetModuleHandle(NULL) 失败，EXE IAT 跳过\n");
                }
            }

            // ★ v23d：EXE CreateFileA/ReadFile IAT 探针（记录 .xrg 文件打开 + caller）
            //   —— 教程 LM01.xrg 由 EXE 直接解析渲染，不走 GameWorld 的 F9CCA。
            //   v23g：EXE 部分已在 DllMain 立即安装（启动极早期就读 LM01.xrg），
            //   这里只装 GW/MS 部分（依赖 g_gwBase）。
            // ★ v23o：**禁用**（崩溃修复）——文件探针与 CCFile 探针同属诊断链，
            //   与崩溃风险源同批移除。教程读取路径已由 hook1 预展开覆盖。
            // install_file_probe_hook();

            // ★ v16m：渲染最终出口 GDI TextOutW —— 教程文本的唯一观察点（直接渲染路径）
            {
                HMODULE hGdi = GetModuleHandleA("GDI32.dll");
                FARPROC pTW = hGdi ? GetProcAddress(hGdi, "TextOutW") : NULL;
                if (pTW)
                {
                    g_iatCount += iat_hook_one(g_gwBase, IAT_GW_TEXTOUTW_RVA, pTW,
                                               (void*)my_TextOutW, (void**)&g_origTextOutW, "GW/TextOutW");
                    if (g_exeBase)
                        g_iatCount += iat_hook_one(g_exeBase, IAT_EXE_TEXTOUTW_RVA, pTW,
                                                   (void*)my_TextOutW, (void**)&g_origTextOutW, "EXE/TextOutW");
                }
                else
                {
                    log_msg("[CJK] GDI32 TextOutW 未解析，渲染诊断跳过\n");
                }
            }

            hGc = GetModuleHandleA("GameClasses.dll");
            if (hGc)
            {
                g_gcBase = (DWORD)hGc;
                g_iatCount += iat_hook_one(g_gcBase, IAT_GC_NARROW_RVA, pN,
                                           (void*)my_LocGcNarrow, (void**)&g_origLocGcNarrow, "GC/narrow");
            }
            else
            {
                log_msg("[CJK] GameClasses.dll 未加载，跳过其 IAT（可稍后由 wait_thread 重试）\n");
            }
        }
    }

    DWORD oldProt;
    // ── 原有 hook：0x20FB2（字幕 Localize_Str 判据）──
    BYTE* target = (BYTE*)(g_gwBase + HOOK_RVA);
    BYTE* hook   = (BYTE*)cjk_trampoline_impl;
    if (target[0] != 0xE8)
    {
        log_msg("[CJK] 0x%X 非 call (0x%02X)，跳过 hook\n", HOOK_RVA, target[0]);
        return FALSE;
    }
    memcpy(g_origBytes, target, 5);
    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &oldProt)) return FALSE;
    target[0] = 0xE9;
    DWORD rel = (DWORD)hook - ((DWORD)target + 5);
    memcpy(target + 1, &rel, 4);
    VirtualProtect(target, 5, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), target, 5);
    g_hooked = TRUE;

    // ── v14 hook 1：0x10054F00（TFStr 构造）——patch 7 字节 ──
    BYTE* tfstr = (BYTE*)(g_gwBase + HOOK_TFSTR_RVA);
    memcpy(g_origTfstr, tfstr, 7);
    if (VirtualProtect(tfstr, 7, PAGE_EXECUTE_READWRITE, &oldProt))
    {
        tfstr[0] = 0xE9;
        rel = (DWORD)cjk_tfstr_trampoline_impl - ((DWORD)tfstr + 5);
        memcpy(tfstr + 1, &rel, 4);
        tfstr[5] = 0x90; tfstr[6] = 0x90;   // nop nop 补齐
        VirtualProtect(tfstr, 7, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), tfstr, 7);
        g_hookedTfstr = TRUE;
        log_msg("[CJK] v14 TFStr 构造 hook: 0x%X -> %08X\n", HOOK_TFSTR_RVA, (DWORD)cjk_tfstr_trampoline_impl);
    }

    // ── v15b hook 3：0x1008ED1A（字幕拼接内 GetLength 修正）——patch 5 字节 ──
    //   （替代原 hook 2 通用 GetLength——中文 UTF-16 高字节≠0，字节[1]==0 检测漏检）
    BYTE* clen = (BYTE*)(g_gwBase + HOOK_CONCATLEN_RVA);
    memcpy(g_origConcatLen, clen, 5);
    if (VirtualProtect(clen, 5, PAGE_EXECUTE_READWRITE, &oldProt))
    {
        clen[0] = 0xE9;
        rel = (DWORD)cjk_concat_len_trampoline_impl - ((DWORD)clen + 5);
        memcpy(clen + 1, &rel, 4);
        VirtualProtect(clen, 5, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), clen, 5);
        g_hookedConcatLen = TRUE;
        log_msg("[CJK] v15b 拼接长度修正 hook: 0x%X -> %08X\n", HOOK_CONCATLEN_RVA, (DWORD)cjk_concat_len_trampoline_impl);
    }

    // ── v16f hook 4：0x1008ED9A（拼接收尾，绕过 copy-ctor 裸 strlen）──
    //    ★ 上线前逐字节核对原指令，地址对不上宁可不装也不能乱写
    //      C6 44 04 14 00 = mov byte ptr [esp+eax+0x14], 0
    {
        static const BYTE expect4[5] = { 0xC6, 0x44, 0x04, 0x14, 0x00 };
        BYTE* cfin = (BYTE*)(g_gwBase + HOOK_CONCATFIN_RVA);
        if (memcmp(cfin, expect4, 5) != 0)
        {
            log_msg("[CJK] !! 0x%X 字节不符（%02X %02X %02X %02X %02X），跳过 hook4\n",
                    HOOK_CONCATFIN_RVA, cfin[0], cfin[1], cfin[2], cfin[3], cfin[4]);
        }
        else
        {
            memcpy(g_origConcatFin, cfin, 5);
            if (VirtualProtect(cfin, 5, PAGE_EXECUTE_READWRITE, &oldProt))
            {
                cfin[0] = 0xE9;
                rel = (DWORD)cjk_concat_fin_trampoline_impl - ((DWORD)cfin + 5);
                memcpy(cfin + 1, &rel, 4);
                VirtualProtect(cfin, 5, oldProt, &oldProt);
                FlushInstructionCache(GetCurrentProcess(), cfin, 5);
                g_hookedConcatFin = TRUE;
                log_msg("[CJK] v16f 拼接收尾 hook: 0x%X -> %08X\n",
                        HOOK_CONCATFIN_RVA, (DWORD)cjk_concat_fin_trampoline_impl);
            }
        }
    }

    // ── v16f hook 5：0x100F9B59（绘制前拷贝的 strlen）──
    //      8B C8 8D 71 01 = mov ecx,eax; lea esi,[ecx+1]
    {
        static const BYTE expect5[5] = { 0x8B, 0xC8, 0x8D, 0x71, 0x01 };
        BYTE* dlen = (BYTE*)(g_gwBase + HOOK_DRAWLEN_RVA);
        if (memcmp(dlen, expect5, 5) != 0)
        {
            log_msg("[CJK] !! 0x%X 字节不符（%02X %02X %02X %02X %02X），跳过 hook5\n",
                    HOOK_DRAWLEN_RVA, dlen[0], dlen[1], dlen[2], dlen[3], dlen[4]);
        }
        else
        {
            memcpy(g_origDrawLen, dlen, 5);
            if (VirtualProtect(dlen, 5, PAGE_EXECUTE_READWRITE, &oldProt))
            {
                dlen[0] = 0xE9;
                rel = (DWORD)cjk_draw_len_trampoline_impl - ((DWORD)dlen + 5);
                memcpy(dlen + 1, &rel, 4);
                VirtualProtect(dlen, 5, oldProt, &oldProt);
                FlushInstructionCache(GetCurrentProcess(), dlen, 5);
                g_hookedDrawLen = TRUE;
                log_msg("[CJK] v16f 绘制长度 hook: 0x%X -> %08X\n",
                        HOOK_DRAWLEN_RVA, (DWORD)cjk_draw_len_trampoline_impl);
            }
        }
    }

    log_msg("[CJK] EnclaveCJK " CJK_VERSION " Hook 安装成功：0x%X -> %08X"
            " (base=%08X, tfstr=%d, clen=%d, cfin=%d, dlen=%d, iat=%d/4)\n",
            HOOK_RVA, (DWORD)hook, g_gwBase, g_hookedTfstr, g_hookedConcatLen,
            g_hookedConcatFin, g_hookedDrawLen, g_iatCount);
    return TRUE;
}

static DWORD WINAPI wait_thread(LPVOID)
{
    // 阶段 1：等 GameWorld 就绪，装主 hook（含 GW 3 槽 IAT）
    while (!install_hook())
        Sleep(100);
    // 阶段 2：v16j —— GameClasses 通常晚于 install_hook 加载。
    //         原代码 install_hook 一次成功（g_hooked=TRUE）就 return，
    //         GC/narrow IAT 永远补不上 → 教程 HUD（若在 GameClasses）
    //         的 §L 键名永不全角化 → 「按 @@@@ 拔出武器」。
    //         这里持续轮询直到 GC/narrow 补 hook 成功（最多 30 秒）。
    for (int tries = 0; tries < 300; tries++)
    {
        if (g_origLocGcNarrow) return 0;              // 已补成功
        HMODULE hMs = GetModuleHandleA("MSystem.dll");
        HMODULE hGc = GetModuleHandleA("GameClasses.dll");
        if (hMs && hGc && !g_origLocGcNarrow)
        {
            FARPROC pN = GetProcAddress(hMs, "?Localize_Str@@YAXPBDPAGH@Z");
            g_gcBase = (DWORD)hGc;
            int n = iat_hook_one(g_gcBase, IAT_GC_NARROW_RVA, pN,
                                 (void*)my_LocGcNarrow,
                                 (void**)&g_origLocGcNarrow, "GC/narrow");
            g_iatCount += n;
            log_msg("[CJK] wait_thread 补 GC/narrow IAT: %s (iat=%d/4)\n",
                    n ? "成功" : "校验失败/跳过", g_iatCount);
            if (n) return 0;
        }
        Sleep(100);
    }
    log_msg("[CJK] wait_thread 30s 超时：GameClasses 未加载，GC/narrow 未补\n");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// ★ v23l：运行时截断文本补全线程（放弃 x64dbg 断点后的终极方案）
//   证据链（x64dbg 三处内存实证）：
//     堆源头(完整·未展开§L) → 拷贝①(strlen 截断「一」004E) → 槽(截断·未展开)
//     → 展开②(§L→全角ＳＰＡＣＥ) → 栈渲染缓冲(截断·展开后) → 屏幕
//   「一支火把」在拷贝①就丢了；槽预填且只读（写断点不命中）；槽地址每次运行
//   变化（0x7BE01C→0x8BB800，堆池）。断点路线风险高（栈缓冲写断点导致游戏崩）。
//   方案：后台线程每 3 秒扫描内存，找截断形态「测试你拾起了」+ 0000 终止，
//   把「一支火把」(00 4E 2F 65 6B 70 8A 62 00 00) 补到「了」后。
//   槽补全 → 渲染（从槽拷贝+展开）→ 显示完整。
// ═══════════════════════════════════════════════════════════════════════
static DWORD WINAPI text_fix_thread(LPVOID)
{
    // 截断形态：「测 试 你 拾 起 了」+ 00 00（UTF-16LE 终止）
    static const BYTE patTrunc[] = {0x4B,0x6D,0xD5,0x8B,0x60,0x4F,0xFE,0x62,
                                    0x77,0x8D,0x86,0x4E,0x00,0x00};
    // 补丁：「一 支 火 把」+ 00 00
    static const BYTE patchTail[] = {0x00,0x4E,0x2F,0x65,0x6B,0x70,0x8A,0x62,0x00,0x00};
    static DWORD s_patched[256];          // 已补地址（去重）
    static int   s_patchCnt = 0;
    SYSTEM_INFO si;
    BYTE* curAddr;
    BYTE* maxAddr;
    int   totalPatched = 0;

    GetSystemInfo(&si);
    maxAddr = (BYTE*)si.lpMaximumApplicationAddress;

    for (;;)
    {
        Sleep(3000);
        curAddr = (BYTE*)0x00010000;
        __try
        {
            while (curAddr < maxAddr)
            {
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery(curAddr, &mbi, sizeof(mbi)) == 0) break;
                if (mbi.State == MEM_COMMIT &&
                    (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                                    PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) &&
                    mbi.RegionSize >= sizeof(patTrunc))
                {
                    BYTE*  base = (BYTE*)mbi.BaseAddress;
                    SIZE_T size = mbi.RegionSize;
                    for (SIZE_T i = 0; i + sizeof(patTrunc) <= size; i++)
                    {
                        if (base[i] != 0x4B) continue;   // 快速首字节过滤
                        if (memcmp(base + i, patTrunc, sizeof(patTrunc)) == 0)
                        {
                            DWORD hitAddr = (DWORD)(base + i);
                            int j, dup = 0;
                            for (j = 0; j < s_patchCnt; j++)
                                if (s_patched[j] == hitAddr) { dup = 1; break; }
                            if (dup) { i += sizeof(patTrunc) - 1; continue; }
                            // 补丁：在「了」(864E) 后的 0000 处写入「一支火把」
                            DWORD old;
                            if (VirtualProtect(base + i + 12, sizeof(patchTail),
                                               PAGE_READWRITE, &old))
                            {
                                memcpy(base + i + 12, patchTail, sizeof(patchTail));
                                VirtualProtect(base + i + 12, sizeof(patchTail), old, &old);
                                if (s_patchCnt < 256) s_patched[s_patchCnt++] = hitAddr;
                                totalPatched++;
                                log_msg("[CJK] v23l 补全截断文本 @ %08X（累计 %d 处）\n",
                                        hitAddr, totalPatched);
                            }
                            i += sizeof(patTrunc) - 1;
                        }
                    }
                }
                curAddr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
                if (curAddr <= mbi.BaseAddress) break;   // 防死循环
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { }
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        // ★ v23g：EXE 文件 API 探针必须在【进程最早阶段】安装——
        //   教程 LM01.xrg 在启动极早期（GameWorld 加载前）就被 EXE 读取，
        //   wait_thread 等 GameWorld 会错过。这里同步立即 hook。
        // ★ v23o：**禁用** v23 系列纯诊断探针（崩溃修复）——
        //   探针只用于诊断（记录文件打开），不参与修复；其 naked+trampoline+
        //   SEH 组合是 v23m/v23n 崩溃（ntdll+0x502F8 二次崩溃）的风险源。
        //   教程文本写入者已由用户 CE 实证 = 我们自己的 tfstr_cjk_wide（hook1），
        //   诊断任务已完成，探针可安全移除。保留函数体供参考。
        // install_exe_file_probe_hook();
        // ★ v23j：MCCDyn.CCFile::Open 函数本体 hook（EXE/GW/MS 所有模块调用一网打尽）
        //   MCCDyn 被 EXE 静态导入，进程启动即加载；教程 .xrg 读取走 CCFile 必然命中。
        // ★ v23o：**禁用**（崩溃修复）——my_McCcOpen 偏移 bug（[esp+0x2C] 是 int 参数
        //   非 VCStr.p）+ naked 调用带 SEH 的 C 函数（cc_open_log）→ strstr AV →
        //   异常分发查函数表二次崩溃。纯诊断用途，禁用不影响修复功能。
        // install_ccfile_open_hook();
        // ★ v23l 线程已禁用（v23o 崩溃修复）：全内存扫描+写入风险不可控
#if 0
        {
            HANDLE h2 = CreateThread(NULL, 0, text_fix_thread, NULL, 0, NULL);
            if (h2) CloseHandle(h2);
        }
#endif
        HANDLE h = CreateThread(NULL, 0, wait_thread, NULL, 0, NULL);
        if (h) CloseHandle(h);
    }
    return TRUE;
}
