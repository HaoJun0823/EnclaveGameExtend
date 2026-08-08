// EnclaveCJK v17r 恢复版（= v16.7 逻辑，用户确认"能显示@@中文"的版本）
//
// v17r 逻辑（v20.2 失败后回滚，2026-08-08 07:12）：
//   hook GameWorld 0x20FB2（原 call 0x101005C4 Localize_Str）
//   判据：[esp+0x48A4] RVA ∈ [0x8D000,0x8F000]
//   处理：[esp+0x24] = data_head → 置宽 flags|0x8000 + 剥§Z + ASCII→全角
//   日志：字幕每次 + 非字幕每 500 条（限流）
//
// ★ v20.2 结论（07:10）：vtable 替换（Util2D vtable+0xB8 → fake stub）
//   即使 pushfd/popfd 保护 EFLAGS + 纯汇编零副作用，字幕仍乱码。
//   → vtable 替换路径彻底不可行（7+2 次尝试全失败）。
//   → 字幕渲染路径（0x10020F60 / vtable+184 / 拼接/GetKey）不可 hook。
//   → 字幕中文 = 引擎原样渲染（字库补齐后 UTF-16 天然正确）。
//   → "前面固定@@ / 尾部@@@@ / 闪烁" = 引擎原样渲染 §Z22 前缀 + 缓冲垃圾。

#include "pch.h"

#define HOOK_RVA    0x20FB2u    // call Localize_Str 调用点
#define THUNK_RVA   0x1005C4u   // Localize_Str IAT thunk
#define RET_VA      0x20FB7u    // 原 call 返回点（add esp,10h）
#define SUB_LO      0x8D000u    // 字幕 Render 区
#define SUB_HI      0x8F000u

#include <windows.h>

static HMODULE  g_hGameWorld = NULL;
static DWORD    g_gwBase     = 0;
static BYTE     g_origBytes[8];
static DWORD    g_retVA      = 0;
static DWORD    g_thunkVA    = 0;
static BOOL     g_hooked     = FALSE;
static volatile LONG g_hits      = 0;
static volatile LONG g_subHits   = 0;
static volatile LONG g_uiHits    = 0;

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
        if (w == 0x3002 || w == 0x3001 || w == 0xFF01 || w == 0xFF1F
            || w == 0x2014 || w == 0xFF0C)
        {
            WORD wn = (i + 1 < 120) ? data[i + 1] : 0;
            if (wn != 0 && ((wn & 0xFF) == 0 || (wn & 0xFF00) == 0))
                break;                                  // 标点后紧贴残留终止符 → 截断
        }
        if ((w & 0xFF00) != 0 && (w & 0xFF) != 0 && is_body_char(w))
        {
            WORD wn = (i + 1 < 120) ? data[i + 1] : 0;
            if (wn != 0 && (wn & 0xFF) == 0 && (wn & 0xFF00) != 0 && wn != 0x3000)
                break;                                  // 汉字后紧贴 [00][XX] 残留 → 截断
        }
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
        push g_retVA
        jmp dword ptr [g_thunkVA]
    }
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

static BYTE g_origTfstr[7];
static BYTE g_origTfstrLen[5];
static BOOL g_hookedTfstr = FALSE;
static BOOL g_hookedTfstrLen = FALSE;

// ★ hook 1：0x10054F00（TFStr<252> 构造）——UTF-16 宽构造
//   入口：[esp]=返回地址、[esp+4]=目标对象、[esp+8]=文本指针（cdecl，2 参数，调用者批量清理）
//   ★ v15（09:55）：加"调用者过滤"——只有字幕路径的 3 个调用点走宽构造，
//     其他调用（UI/菜单等）原样 fallback → 修复 v14 误伤通用函数写坏栈的崩溃
//     字幕调用点（返回地址 RVA）：0x1008DD09（正文构造）/ 0x1008DD31（§Z前缀）/ 0x1008E362（Load TEXT）
#define TFSTR_CALLER_1       0x8DD09u
#define TFSTR_CALLER_2       0x8DD31u
#define TFSTR_CALLER_3       0x8E362u
static void __declspec(naked) cjk_tfstr_trampoline_impl(void)
{
    __asm
    {
        ; ★ v15 调用者过滤：返回地址 [esp] ∈ 字幕 3 个调用点 → 宽构造；否则 fallback
        mov eax, [esp]               ; 返回地址
        sub eax, g_gwBase            ; 转 RVA
        cmp eax, TFSTR_CALLER_1
        je  tfstr_check
        cmp eax, TFSTR_CALLER_2
        je  tfstr_check
        cmp eax, TFSTR_CALLER_3
        je  tfstr_check
        jmp tfstr_fallback           ; 非字幕调用 → 原逻辑
    tfstr_check:
        ; ★ v15b（09:56）：去掉 UTF-16 检测——字幕 3 个调用点的文本必然是 UTF-16
        ;   （xrg 是 UTF-16；中文高字节≠0，"字节[1]==0"检测只对 ASCII UTF-16 有效 → 中文漏检）
        mov eax, [esp + 8]           ; 文本指针
        test eax, eax
        jz  tfstr_fallback
        ; ★ UTF-16 宽构造（完全重写，不经过 vsnprintf %s）
        pushad
        mov esi, [esp + 0x24]        ; 目标（pushad 后 [esp+0x20+4]）
        mov edi, [esp + 0x28]        ; 文本（[esp+0x20+8]）
        ; 1) 设 TFStr vtable
        mov eax, g_gwBase
        add eax, TFSTR_VTABLE_RVA
        mov dword ptr [esi], eax
        ; 2) wcslen（数 WORD 到 0，上限 125）
        xor ecx, ecx
    tfstr_wcs:
        cmp word ptr [edi + ecx*2], 0
        je  tfstr_wcs_done
        inc ecx
        cmp ecx, TFSTR_MAX_WORDS
        jl  tfstr_wcs
    tfstr_wcs_done:
        ; 3) WORD 拷贝到 [esi+4]（内嵌数据区，GetData=[ecx+4]）
        lea eax, [esi + 4]
        mov ebx, ecx
    tfstr_copy:
        mov dx, word ptr [edi]
        mov word ptr [eax], dx
        add edi, 2
        add eax, 2
        dec ebx
        jnz tfstr_copy
        mov word ptr [eax], 0        ; 宽终止符 00 00
        popad
        mov eax, [esp + 4]           ; 返回目标对象（原函数返回 eax=目标）
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

static void __declspec(naked) cjk_concat_len_trampoline_impl(void)
{
    __asm
    {
        ; 重放原指令（0x1008ED1A-0x1E）
        call dword ptr [edx + 0x64]     ; 正文 GetLength → eax
        mov edi, eax
        ; ★ 修正：检测正文 UTF-16 → 重算字节数（wcslen × 2）
        pushad
        mov eax, [ebp + 0xc]            ; 正文对象
        mov eax, [eax + 4]              ; data（TFStr GetData = [对象+4]）
        test eax, eax
        jz  tcl_done
        ; UTF-16 检测：字节[1]==0（ASCII UTF-16）或 字节[1]∈[0x4E,0xA0)（CJK UTF-16）
        movzx ecx, byte ptr [eax + 1]
        test ecx, ecx
        jz  tcl_utf16
        cmp ecx, 0x4E
        jb  tcl_done                    ; <0x4E → 窄
        cmp ecx, 0xA0
        jae tcl_done                    ; >=0xA0 → 窄（UTF-8/GBK 首字节/续字节）
    tcl_utf16:
        xor ecx, ecx
    tcl_loop:
        cmp word ptr [eax + ecx*2], 0
        je  tcl_utf16_done
        inc ecx
        cmp ecx, TFSTR_MAX_WORDS
        jl  tcl_loop
    tcl_utf16_done:
        lea eax, [ecx*2]                ; 字节数 = 字符 × 2
        mov [esp + 0x1C], eax           ; 写回 pushad 的 eax 槽
    tcl_done:
        popad
        mov edi, eax                    ; edi = 修正后长度
        mov eax, g_gwBase
        add eax, CONCATLEN_RET_RVA      ; 跳回 0x1008ED1F
        jmp eax
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

    log_msg("[CJK] Hook 安装成功：0x%X -> %08X (base=%08X, tfstr=%d, clen=%d)\n",
            HOOK_RVA, (DWORD)hook, g_gwBase, g_hookedTfstr, g_hookedConcatLen);
    return TRUE;
}

static DWORD WINAPI wait_thread(LPVOID)
{
    for (;;)
    {
        if (install_hook())
            return 0;
        Sleep(100);
    }
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
