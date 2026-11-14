@echo off
cd /d "%~dp0"
title ProcessDumper v4.2 Visual Studio MSBuild
echo ========================================================
echo Building ProcessDumper v4.2 Pro via Visual Studio MSBuild
echo ========================================================

:: Try locating vswhere.exe to find MSBuild
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "MSBUILD="

if exist "%VSWHERE%" (
    for /f "tokens=*" %%i in ('"%VSWHERE%" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe') do (
        set "MSBUILD=%%i"
    )
)

if "%MSBUILD%"=="" (
    :: Fallback to common MSBuild paths
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" (
        set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
    ) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe" (
        set "MSBUILD=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
    )
)

if "%MSBUILD%"=="" (
    echo [!] MSBuild.exe not found automatically.
    echo Please open ProcessDumper.sln directly in Visual Studio 2019 / 2022 and press Build Solution (Ctrl+Shift+B).
    pause
    exit /b 1
)

echo Found MSBuild: "%MSBUILD%"
"%MSBUILD%" ProcessDumper.sln /p:Configuration=Release /p:Platform=x64 /v:minimal

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================================
    echo  VISUAL STUDIO BUILD SUCCESSFUL -- ProcessDumper.exe Updated!
    echo ========================================================
) else (
    echo.
    echo [ERROR] Visual Studio Build failed!
)
pause
