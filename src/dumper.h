// dumper.h -- Multi-Engine Process Offset Dumper v4.0
// *the grand orchestrator, now commanding 12 specialized engines*
#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <functional>
#include <map>
#include <cstdint>

// ---------------------------------------------------------------------------
// Core structures
// ---------------------------------------------------------------------------
struct ProcessEntry {
    DWORD        pid;
    std::wstring name;
    std::wstring exePath;
    DWORD        threadCount;
    BOOL         is64bit;
};

struct ModuleEntry {
    std::wstring name;
    std::wstring path;
    uintptr_t    base;
    size_t       size;
};

struct ExportEntry {
    std::string  name;
    std::string  moduleName;
    uintptr_t    rva;
    uintptr_t    va;
    WORD         ordinal;
};

struct SectionEntry {
    char      name[9];
    uintptr_t rva;
    size_t    virtualSize;
    size_t    rawSize;
    DWORD     characteristics;
};

struct PatternResult {
    std::string  label;
    uintptr_t    address;
    uintptr_t    offset;
    uintptr_t    rawMatchAddr;
    uintptr_t    rawMatchOffset;
    std::string  moduleName;
    std::string  notes;
    std::string  engineVer;
    // v4: confidence
    int          confidence; // 0=DEAD 1=LOW 2=MEDIUM 3=HIGH
    uintptr_t    liveValue;
    std::string  hexDump;
};

struct PointerChainDump {
    std::string  label;
    bool         valid;
    uintptr_t    finalAddress;
    uintptr_t    finalValue;
    std::string  chain;
};

// ---------------------------------------------------------------------------
// Engine detection enums
// ---------------------------------------------------------------------------
enum EngineType {
    ENGINE_UNKNOWN      = 0,
    ENGINE_SOURCE1      = 1,
    ENGINE_SOURCE2      = 2,
    ENGINE_UNREAL       = 3,
    ENGINE_UNITY_IL2CPP = 4,
    ENGINE_UNITY_MONO   = 5,
};

enum UEVersion {
    UE_UNKNOWN = 0,
    UE_425 = 1, UE_426 = 2, UE_427 = 3,
    UE_50  = 4, UE_51  = 5, UE_52  = 6, UE_53  = 7, UE_54  = 8,
};

// ---------------------------------------------------------------------------
// Full dump result
// ---------------------------------------------------------------------------
struct DumpResult {
    // Core
    std::wstring               processName;
    DWORD                      pid;
    EngineType                 engine;
    UEVersion                  ueVersion;

    // Module / PE
    std::vector<ModuleEntry>   modules;
    std::vector<ExportEntry>   exports;
    std::vector<ExportEntry>   il2cppKeyExports;
    std::vector<SectionEntry>  sections;

    // Pattern results (all engines)
    std::vector<PatternResult> patterns;

    // Pointer chain results
    std::vector<PointerChainDump> chains;

    // Engine-specific extended data (formatted text blocks)
    std::string  il2cppMetadataText;   // IL2CPP domain walk
    std::string  il2cppFileMetaText;   // global-metadata.dat parse
    std::string  ueObjectsText;        // UE GObjects walk
    std::string  ueNamesText;          // UE GNames decode
    std::string  monoMetaText;         // Mono assembly walk
    std::string  vadDumpText;          // VAD region map + hidden modules
    std::string  vtableText;           // Vtable + RTTI scan
    std::string  conVarText;           // Source ConVar list
    std::string  regenPatternsText;    // CS2 auto-regen suggestions
    std::string  verificationText;     // Confidence scoring results

    // JSON export
    std::string  jsonText;

    // Combined output
    std::string  rawText;

    // Flags
    bool         usedKernelDriver;
    bool         hasHiddenModules;
    uintptr_t    processEventAddr;
};

using ProgressCallback = std::function<void(const std::wstring&, int)>;

// ---------------------------------------------------------------------------
// Function declarations
// ---------------------------------------------------------------------------
std::vector<ProcessEntry> EnumerateProcesses();
bool DumpProcess(DWORD pid, DumpResult& result, ProgressCallback progress = nullptr);
bool WriteOffsets(const DumpResult& result, const std::wstring& outputPath);
bool WriteJSON(const DumpResult& result, const std::wstring& outputPath);
bool WriteCppHeader(const DumpResult& result, const std::wstring& outputPath);

BOOL IsProcess64Bit(HANDLE hProcess);
bool EnableDebugPrivilege();
bool IsBattEyeRunning();
bool SafeReadMemory(HANDLE hProcess, uintptr_t address, void* buffer, size_t size);
EngineType DetectEngine(const std::vector<ModuleEntry>& modules, const std::wstring& procName);
UEVersion  DetectUEVersion(HANDLE hProcess, const std::vector<ModuleEntry>& modules);
const char* EngineTypeName(EngineType e);
const char* UEVersionName(UEVersion v);
