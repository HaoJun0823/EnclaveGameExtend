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
#define CJK_VERSION "v16k"

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
                data[i] = (w == 0x20) ? 0x3000 : (w + 0xFEE0);  // 全角化
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
                if (i >= limit || out[i] == 0) break;
                i++;                                                        // 码字母（Z/C/…）
                while (i < limit && out[i] >= 0x30 && out[i] <= 0x39) i++;  // 数字参数
                continue;
            }
            if (w >= 0x21 && w <= 0x7E) { out[i] = (WORD)(w + 0xFEE0); fixed++; }  // 半角 → 全角
            else if (w == 0x20)         { out[i] = 0x3000;             fixed++; }  // 半角空格 → 全角
            i++;
        }
        if (fixed) InterlockedExchangeAdd((volatile LONG*)&g_keyFixed, fixed);

        // ★ v16i 取证升级：记录【外层调用者 RVA】。
        //   0x20FB2 是 GameWorld 9 个 Localize_Str(CStr) 调用点之一，其上游还有
        //   021942 / 021E9B / 03319F / 0334CF / 05E3AF / 05E6DF / 0E3D37 / 0E3E37。
        //   若教程提示不走本点，这份日志会是空的 —— 那就直接锁定"要改 hook 点"。
        if (hasAscii && (hasNl || post_quota(callerRva, 0)))
        {
            char buf[1152];
            char* p = buf;
            p += wsprintfA(p, "[POST %ld] caller=%05X out=%08X len=%d fixed=%d nl=%d cap=%d\n",
                           n, callerRva, outPtr, i, fixed, hasNl, cap);
            for (int k = 0; k < 160 && k < i; k++)
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
//       实测导入表：IAT_RVA 0x773B0 = CStr / 0x773B4 = narrow / 0x773B8 = wide
#define IAT_EXE_CSTR_RVA   0x773B0u   // Enclave.exe ?Localize_Str@@YAXVCStr@@PAGH@Z
#define IAT_EXE_NARROW_RVA 0x773B4u   // Enclave.exe ?Localize_Str@@YAXPBDPAGH@Z
#define IAT_EXE_WIDE_RVA   0x773B8u   // Enclave.exe ?Localize_Str@@YAXPBGPAGH@Z

typedef struct { DWORD lo, hi; } CStrVal;      // CStr 按值 = 8 字节

typedef void (__cdecl *pfn_LocCStr)(CStrVal, WORD*, int);
typedef void (__cdecl *pfn_LocNarrow)(const char*, WORD*, int);
typedef void (__cdecl *pfn_LocWide)(const WORD*, WORD*, int);

static pfn_LocCStr   g_origLocCStr   = NULL;
static pfn_LocNarrow g_origLocNarrow = NULL;
static pfn_LocWide   g_origLocWide   = NULL;
static pfn_LocNarrow g_origLocGcNarrow = NULL;   // GameClasses.dll 那一份

static int g_iatCount = 0;                       // 成功改写的 IAT 项数

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
    g_origExeLocWide(src, out, cap);
    InterlockedIncrement((volatile LONG*)&g_postHits);
    safe_fullwidth_expanded((DWORD)out,
                            (DWORD)_ReturnAddress() - g_exeBase, cap);
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
        __try
        {
            WORD* dst = (WORD*)((BYTE*)obj + 4);        // 数据【内联】在 +4
            for (i = 0; i < n; i++) dst[i] = w[i];      // 按 WORD 搬，0x00 不再是边界
            dst[n] = 0;                                 // 宽终止 00 00
            *(DWORD*)obj = g_gwBase + TFSTR_VTABLE_RVA; // TFStr<252> vtable
            len_put(obj, n * 2);                        // ★ 登记真实字节长度
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { hit = 0; }
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
static void h5_diag(DWORD retRva, int found, int slen, const BYTE* head)
{
    static volatile LONG s_c = 0;
    char buf[224];
    if (InterlockedIncrement(&s_c) > 24) return;
    wsprintfA(buf, "[H5] ret=%05X len=%3d strlen=%3d %-7s | %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\r\n",
              retRva, found, slen,
              found > 0 ? (found > slen ? "RESCUED" : "same") : "miss",
              head[0], head[1], head[2], head[3], head[4],
              head[5], head[6], head[7], head[8], head[9]);
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

    h5_diag(retRva, len, slen, head);
    // 只有「查到的长度比 strlen 更长」才值得接管；否则一切照旧，零风险
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
        sub ecx, g_gwBase
        cmp ecx, SUB_LO
        jb  h5_orig
        cmp ecx, SUB_HI
        ja  h5_orig

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

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        HANDLE h = CreateThread(NULL, 0, wait_thread, NULL, 0, NULL);
        if (h) CloseHandle(h);
    }
    return TRUE;
}
