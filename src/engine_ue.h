// engine_ue.h -- Unreal Engine 4/5 Deep Scanner
#pragma once
#include "dumper.h"
#include <cstdint>
#include <string>
#include <vector>
#include <map>

// -----------------------------------------------------------------------
// UE object record decoded from GObjects array
// -----------------------------------------------------------------------
struct UEObject {
    uintptr_t address;      // object VA in process
    uintptr_t classAddr;    // UClass* VA
    std::string name;       // decoded from GNames
    std::string className;  // class name
    uint32_t    index;      // FUObjectArray index
};

// -----------------------------------------------------------------------
// Single GNames entry
// -----------------------------------------------------------------------
struct UENameEntry {
    uint32_t    id;
    std::string name;
};

// -----------------------------------------------------------------------
// Aggregated result of a full UE dump pass
// -----------------------------------------------------------------------
struct UEDumpResult {
    std::vector<UEObject>    objects;           // all UObjects found
    std::vector<UENameEntry> names;             // all GNames decoded
    uintptr_t                gObjectsAddr;
    uintptr_t                gNamesAddr;
    uintptr_t                gWorldAddr;
    uintptr_t                processEventAddr;  // UObject::ProcessEvent VA
    std::string              formattedText;
};

// -----------------------------------------------------------------------
// API
// -----------------------------------------------------------------------

// Full UE dump: walks GObjects array + decodes GNames pool
bool DumpUnrealEngine(HANDLE hProcess,
                      const std::vector<ModuleEntry>& modules,
                      const std::vector<PatternResult>& patterns,
                      UEVersion version,
                      UEDumpResult& result,
                      ProgressCallback progress = nullptr);

// Decode a FName ID to string using GNames
std::string DecodeFName(HANDLE hProcess,
                        uintptr_t gNamesAddr,
                        uint32_t nameIndex,
                        UEVersion ver);

// Find ProcessEvent vtable slot (slot 61 UE4, slot 62 UE5)
uintptr_t FindProcessEvent(HANDLE hProcess,
                           uintptr_t gObjectsAddr,
                           UEVersion ver);
