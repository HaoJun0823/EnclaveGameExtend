// dllmain.cpp : Binkw32Proxy 代理 DLL
// 功能：
//   1. 游戏启动加载 binkw32.dll（本代理）时，读取同目录 proxy_dll.ini
//   2. 按顺序 LoadLibraryA 挂载 ini 中列出的每个 DLL（如 EnclaveCJK.dll）
//   3. 85 个 Bink 导出通过 binkw32.def 转发到 binkw32_orig.dll（原版改名）
// 部署：
//   binkw32.dll        <- 本代理编译产物
//   binkw32_orig.dll   <- 原版 binkw32.dll 改名
//   proxy_dll.ini      <- 要挂载的 DLL 列表（每行一个，按序加载）
//   EnclaveCJK.dll     <- 实际修复逻辑
#include "pch.h"
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

static HMODULE g_hOrigBink = NULL;

// 从 proxy_dll.ini 按序挂载 DLL
static void MountDllsFromIni(HMODULE hSelf)
{
    char iniPath[MAX_PATH] = { 0 };
    char selfPath[MAX_PATH] = { 0 };

    if (!GetModuleFileNameA(hSelf, selfPath, MAX_PATH))
        return;
    // 取代理自身目录（游戏根目录）
    char* slash = strrchr(selfPath, '\\');
    if (!slash) return;
    *slash = 0;
    strcpy_s(iniPath, selfPath);
    strcat_s(iniPath, "\\proxy_dll.ini");

    HANDLE hFile = CreateFileA(iniPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize > 4096) { CloseHandle(hFile); return; }

    char* buf = (char*)malloc(fileSize + 1);
    DWORD read = 0;
    ReadFile(hFile, buf, fileSize, &read, NULL);
    CloseHandle(hFile);
    buf[read] = 0;

    char* line = buf;
    while (line && *line)
    {
        // 取一行
        char* nl = strchr(line, '\n');
        if (nl) *nl = 0;
        // 去尾 \r 与空白
        int len = (int)strlen(line);
        while (len > 0 && (line[len-1] == '\r' || line[len-1] == ' ' || line[len-1] == '\t'))
            line[--len] = 0;
        // 去首空白
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        // 跳过空行与注释
        if (*p && *p != ';' && *p != '#')
        {
            // 支持相对路径：拼接代理目录
            char full[MAX_PATH];
            if (strchr(p, '\\') || strchr(p, '/') || (len >= 2 && p[1] == ':'))
            {
                strcpy_s(full, p);
            }
            else
            {
                strcpy_s(full, selfPath);
                strcat_s(full, "\\");
                strcat_s(full, p);
            }
            // 按序挂载
            HMODULE hMod = LoadLibraryA(full);
            if (hMod)
                OutputDebugStringA("  [Binkw32Proxy] mounted ");
            else
                OutputDebugStringA("  [Binkw32Proxy] FAILED ");
            OutputDebugStringA(full);
            OutputDebugStringA("\n");
        }
        line = nl ? nl + 1 : NULL;
    }
    free(buf);
}

// 加载真实 binkw32（binkw32_orig.dll），转发导出由 .def 交给 loader 处理，
// 这里仅确保它已加载（.def 转发时 loader 会自动加载，此处是双保险）
static void EnsureOrigLoaded(HMODULE hSelf)
{
    char selfPath[MAX_PATH] = { 0 };
    if (!GetModuleFileNameA(hSelf, selfPath, MAX_PATH))
        return;
    char* slash = strrchr(selfPath, '\\');
    if (!slash) return;
    *slash = 0;

    char origPath[MAX_PATH];
    strcpy_s(origPath, selfPath);
    strcat_s(origPath, "\\binkw32_orig.dll");
    g_hOrigBink = LoadLibraryA(origPath);
    if (!g_hOrigBink)
    {
        OutputDebugStringA("[Binkw32Proxy] WARNING: binkw32_orig.dll not loaded\n");
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        // 1) 确保真实 binkw32 已加载（.def 转发依赖它）
        EnsureOrigLoaded(hModule);
        // 2) 按序挂载 proxy_dll.ini 里的 DLL
        MountDllsFromIni(hModule);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
