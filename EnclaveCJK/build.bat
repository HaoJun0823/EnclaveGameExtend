@echo off
set VSDIR=C:\Program Files\Microsoft Visual Studio\18\Community
set MSVC=%VSDIR%\VC\Tools\MSVC\14.50.35717
set SDKINC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0
set SDKLIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0
set PATH=%MSVC%\bin\Hostx64\x86;%PATH%
set INCLUDE=%MSVC%\include;%SDKINC%\ucrt;%SDKINC%\um;%SDKINC%\shared
set LIB=%MSVC%\lib\x86;%SDKLIB%\ucrt\x86;%SDKLIB%\um\x86
rem user32.lib = wsprintfA/wvsprintfA（诊断日志用），漏掉会报 LNK2019 __imp__wsprintfA
cl /nologo /O2 /MT /DNDEBUG /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS /LD dllmain.cpp /Fe:EnclaveCJK.dll /link user32.lib kernel32.lib
