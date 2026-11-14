@echo off
setlocal enabledelayedexpansion
title ProcDumperKM - Driver Build Script

echo =========================================================
echo  ProcDumperKM WDM Driver Builder
echo  Target: x64 Release Kernel Mode
echo =========================================================
echo.

:: ---------------------------------------------------------------
:: Step 1 - Check test-signing state
:: ---------------------------------------------------------------
echo [*] Checking test signing mode...
bcdedit /enum | findstr /i "testsigning" | findstr /i "yes" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] WARNING: Test signing is NOT enabled.
    echo     You must enable it to load unsigned drivers:
    echo.
    echo     1. Open CMD as Administrator
    echo     2. Run: bcdedit /set testsigning on
    echo     3. Reboot
    echo.
    echo     Also disable Secure Boot in BIOS/UEFI if needed.
    echo.
    set /p CONTINUE="Continue anyway? (y/N): "
    if /i not "!CONTINUE!"=="y" exit /b 1
)

:: ---------------------------------------------------------------
:: Step 2 - Locate WDK
:: ---------------------------------------------------------------
echo [*] Searching for Windows Driver Kit...
set WDK_ROOT=

:: Try registry key (WDK 10)
for /f "tokens=2*" %%A in ('reg query "HKLM\SOFTWARE\Microsoft\Windows Kits\Installed Roots" /v "KitsRoot10" 2^>nul') do (
    set WDK_ROOT=%%B
)

:: Fallback: common install locations
if not defined WDK_ROOT (
    set CANDIDATES=^
        "C:\Program Files (x86)\Windows Kits\10"^
        "C:\Program Files\Windows Kits\10"^
        "C:\WDK"
    for %%C in (!CANDIDATES!) do (
        if exist %%C\Include\10.0.22621.0\km\ntddk.h (
            set WDK_ROOT=%%~C
        )
    )
)

if not defined WDK_ROOT (
    echo.
    echo [!] ERROR: Windows Driver Kit (WDK) NOT FOUND.
    echo.
    echo     To install WDK:
    echo     ----------------------------------------------------------
    echo     1. Install Visual Studio 2022 (Community or higher)
    echo        https://visualstudio.microsoft.com/downloads/
    echo        - Include: "Desktop development with C++"
    echo        - Include: "MSVC v143 - VS 2022 C++ x64/x86 build tools"
    echo.
    echo     2. Download WDK for Windows 11 (10.0.22621 or newer):
    echo        https://go.microsoft.com/fwlink/?linkid=2196230
    echo        - Run the installer
    echo        - The VS extension installs automatically
    echo.
    echo     3. (Optional) Install WDK via winget:
    echo        winget install Microsoft.WindowsDriverKit
    echo.
    echo     4. Verify install:
    echo        dir "C:\Program Files (x86)\Windows Kits\10\Include\"
    echo     ----------------------------------------------------------
    echo.
    echo     After installing, re-run this script.
    exit /b 1
)

echo [+] WDK found at: !WDK_ROOT!

:: ---------------------------------------------------------------
:: Step 3 - Locate newest SDK/WDK version
:: ---------------------------------------------------------------
set WDK_VER=
for /d %%V in ("!WDK_ROOT!\Include\*") do (
    set WDK_VER=%%~nV
)
echo [+] Using WDK version: !WDK_VER!

:: ---------------------------------------------------------------
:: Step 4 - Locate MSBuild
:: ---------------------------------------------------------------
echo [*] Searching for MSBuild...
set MSBUILD=

:: VS 2022
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe" (
    set MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe
)

:: Try vswhere
if not defined MSBUILD (
    set VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe
    if exist "!VSWHERE!" (
        for /f "tokens=*" %%P in ('"!VSWHERE!" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe') do (
            set MSBUILD=%%P
        )
    )
)

if not defined MSBUILD (
    echo [!] ERROR: MSBuild not found. Install Visual Studio 2022 with C++ workload.
    exit /b 1
)

echo [+] MSBuild: !MSBUILD!

:: ---------------------------------------------------------------
:: Step 5 - Generate .vcxproj
:: ---------------------------------------------------------------
echo [*] Generating ProcDumperKM.vcxproj...
set PROJ=%~dp0ProcDumperKM.vcxproj
set SRC=%~dp0driver.c

(
echo ^<?xml version="1.0" encoding="utf-8"?^>
echo ^<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"^>
echo   ^<ItemGroup Label="ProjectConfigurations"^>
echo     ^<ProjectConfiguration Include="Release^|x64"^>
echo       ^<Configuration^>Release^</Configuration^>
echo       ^<Platform^>x64^</Platform^>
echo     ^</ProjectConfiguration^>
echo   ^</ItemGroup^>
echo   ^<PropertyGroup Label="Globals"^>
echo     ^<ProjectGuid^>{DEADBEEF-1337-CAFE-BABE-DEADBEEFCAFE}^</ProjectGuid^>
echo     ^<ConfigurationType^>Driver^</ConfigurationType^>
echo     ^<DriverType^>WDM^</DriverType^>
echo     ^<TargetName^>ProcDumperKM^</TargetName^>
echo   ^</PropertyGroup^>
echo   ^<Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" /^>
echo   ^<PropertyGroup Condition="'$(Configuration)^|$(Platform)'=='Release^|x64'" Label="Configuration"^>
echo     ^<ConfigurationType^>Driver^</ConfigurationType^>
echo     ^<PlatformToolset^>WindowsKernelModeDriver10.0^</PlatformToolset^>
echo     ^<DriverType^>WDM^</DriverType^>
echo   ^</PropertyGroup^>
echo   ^<Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" /^>
echo   ^<ImportGroup Label="ExtensionSettings" /^>
echo   ^<PropertyGroup Condition="'$(Configuration)^|$(Platform)'=='Release^|x64'"^>
echo     ^<OutDir^>$(SolutionDir)bin\$(Configuration)\^</OutDir^>
echo     ^<IntDir^>$(SolutionDir)obj\$(Configuration)\^</IntDir^>
echo   ^</PropertyGroup^>
echo   ^<ItemDefinitionGroup Condition="'$(Configuration)^|$(Platform)'=='Release^|x64'"^>
echo     ^<ClCompile^>
echo       ^<AdditionalIncludeDirectories^>$(KernelDirectory);$(KernelDirectory)..\km;%(AdditionalIncludeDirectories)^</AdditionalIncludeDirectories^>
echo       ^<PreprocessorDefinitions^>_KERNEL_MODE;WIN64;NDEBUG;%(PreprocessorDefinitions)^</PreprocessorDefinitions^>
echo       ^<WarningLevel^>Level4^</WarningLevel^>
echo       ^<TreatWarningsAsErrors^>true^</TreatWarningsAsErrors^>
echo       ^<Optimization^>Disabled^</Optimization^>
echo     ^</ClCompile^>
echo     ^<Link^>
echo       ^<EntryPointSymbol^>DriverEntry^</EntryPointSymbol^>
echo       ^<AdditionalDependencies^>ntoskrnl.lib;hal.lib;wdm.lib;%(AdditionalDependencies)^</AdditionalDependencies^>
echo     ^</Link^>
echo   ^</ItemDefinitionGroup^>
echo   ^<ItemGroup^>
echo     ^<ClCompile Include="driver.c" /^>
echo   ^</ItemGroup^>
echo   ^<Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" /^>
echo   ^<ImportGroup Label="ExtensionTargets" /^>
echo ^</Project^>
) > "%PROJ%"

echo [+] .vcxproj generated

:: ---------------------------------------------------------------
:: Step 6 - Build
:: ---------------------------------------------------------------
echo [*] Building driver...
"!MSBUILD!" "%PROJ%" /p:Configuration=Release /p:Platform=x64 /t:Build /m /nologo

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Build FAILED. Check MSBuild output above.
    exit /b 1
)

echo.
echo [+] Build SUCCEEDED.
echo [+] Output: %~dp0bin\Release\ProcDumperKM.sys
echo.
echo [*] To load the driver (admin CMD):
echo     sc create ProcDumperKM type= kernel binPath= "C:\path\to\ProcDumperKM.sys"
echo     sc start ProcDumperKM
echo.
echo [*] To sign for test: use signtool with a self-signed cert
echo     makecert -r -pe -ss MY -n "CN=TestCert" TestCert.cer
echo     signtool sign /fd sha256 /s MY /n "TestCert" ProcDumperKM.sys
echo.
endlocal
exit /b 0
