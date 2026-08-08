# build_all.ps1 - 编译 Binkw32Proxy 和 EnclaveCJK（Win32 Release，命令行 cl.exe）
# 用法: powershell -ExecutionPolicy Bypass -File build_all.ps1

$ErrorActionPreference = "Stop"

$VC   = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.50.35717"
$SDK  = "C:\Program Files (x86)\Windows Kits\10"
$SDKVer = "10.0.26100.0"

$env:INCLUDE = "$VC\include;$SDK\Include\$SDKVer\ucrt;$SDK\Include\$SDKVer\um;$SDK\Include\$SDKVer\shared"
$env:LIB     = "$VC\lib\x86;$SDK\Lib\$SDKVer\ucrt\x86;$SDK\Lib\$SDKVer\um\x86"

$cl  = "$VC\bin\Hostx86\x86\cl.exe"
$link = "$VC\bin\Hostx86\x86\link.exe"

function Build-Proxy {
    Write-Host "=== Building Binkw32Proxy (binkw32.dll) ===" -ForegroundColor Cyan
    Push-Location "G:\Projects\EnclaveGameExtend\Binkw32Proxy"
    # 编译 dllmain.cpp -> dllmain.obj
    & $cl /nologo /c /W3 /O2 /MT /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_USRDLL" /D "BINKW32PROXY_EXPORTS" /Fo"dllmain.obj" dllmain.cpp 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "cl failed" }
    # 链接 + .def 转发
    & $link /nologo /DLL /OUT:"binkw32.dll" /DEF:"binkw32.def" dllmain.obj kernel32.lib user32.lib shlwapi.lib /SUBSYSTEM:WINDOWS 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "link failed" }
    Get-ChildItem binkw32.dll | Select-Object Name, Length, LastWriteTime
    Pop-Location
}

function Build-CJK {
    Write-Host "=== Building EnclaveCJK (EnclaveCJK.dll) ===" -ForegroundColor Cyan
    Push-Location "G:\Projects\EnclaveGameExtend\EnclaveCJK"
    & $cl /nologo /c /W3 /O2 /MT /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_USRDLL" /D "ENCLAVECJK_EXPORTS" /Fo"dllmain.obj" dllmain.cpp 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "cl failed" }
    & $link /nologo /DLL /OUT:"EnclaveCJK.dll" dllmain.obj kernel32.lib /SUBSYSTEM:WINDOWS 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "link failed" }
    Get-ChildItem EnclaveCJK.dll | Select-Object Name, Length, LastWriteTime
    Pop-Location
}

Build-Proxy
Build-CJK
Write-Host "=== Done ===" -ForegroundColor Green
