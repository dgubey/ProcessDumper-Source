@echo off
cd /d "%~dp0"
title ProcessDumper v4.2 Master Build
echo ========================================================
echo Building ProcessDumper v4.2 Pro (Multi-Engine Dumper)
echo ========================================================

g++ -std=c++17 -O2 -m64 -DUNICODE -D_UNICODE -DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00 ^
    main.cpp dumper.cpp export_gen.cpp ptr_chain.cpp chain_verifier.cpp ^
    engine_il2cpp.cpp engine_ue.cpp engine_mono.cpp engine_cs2_ext.cpp ^
    engine_vad.cpp vtable_scan.cpp cs2_autoregen.cpp meta_parser.cpp km_read.cpp ^
    -o ..\ProcessDumper.exe ^
    -lcomctl32 -lpsapi -ldwmapi -luxtheme -lshell32 -lgdi32 -luser32 -lkernel32 -ladvapi32 ^
    -mwindows -static-libgcc -static-libstdc++

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================================
    echo  BUILD SUCCESSFUL -- ProcessDumper.exe Updated!
    echo ========================================================
) else (
    echo.
    echo [ERROR] Build failed! Check compiler errors above.
)
pause
