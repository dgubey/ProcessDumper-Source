// engine_mono.h -- Unity Mono Runtime Assembly Walker
// Supports: mono.dll / mono-2.0-bdwgc.dll (most Unity versions pre-2020)
// Memory model: 64-bit little-endian, Windows x64
#pragma once
#include "dumper.h"
#include <cstdint>
#include <string>
#include <vector>

// -----------------------------------------------------------------------
// A single field decoded from MonoClassField
// -----------------------------------------------------------------------
struct MonoField {
    std::string name;
    std::string typeName;
    uint32_t    offset;
    bool        isStatic;
};

// -----------------------------------------------------------------------
// A single class decoded from a MonoImage type table
// -----------------------------------------------------------------------
struct MonoClass {
    std::string name;
    std::string namespaceName;
    std::string assemblyName;
    uintptr_t   classPtr;
    uint32_t    instanceSize;
    std::vector<MonoField> fields;
};

// -----------------------------------------------------------------------
// Aggregated result of full Mono runtime walk
// -----------------------------------------------------------------------
struct MonoDumpResult {
    std::vector<MonoClass> classes;
    uintptr_t              domainAddr;
    std::string            formattedText;
};

// -----------------------------------------------------------------------
// API
// -----------------------------------------------------------------------

// Full mono dump: resolves domain -> assemblies -> images -> classes -> fields
bool DumpMonoRuntime(HANDLE hProcess,
                     const std::vector<ModuleEntry>& modules,
                     const std::vector<ExportEntry>& exports,
                     MonoDumpResult& result,
                     ProgressCallback progress = nullptr);
