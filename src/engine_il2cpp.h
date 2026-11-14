// engine_il2cpp.h -- Unity IL2CPP Full Metadata Dumper
#pragma once
#include "dumper.h"
#include <cstdint>
#include <string>
#include <vector>

struct IL2CppField {
    std::string name;
    std::string typeName;
    uint32_t    fieldOffset;   // offset in instance layout
    bool        isStatic;
    uintptr_t   staticValueAddr;
};

struct IL2CppMethod {
    std::string name;
    std::string returnType;
    uintptr_t   methodPtr;
    uintptr_t   rva;
    uint32_t    numParams;
};

struct IL2CppClass {
    std::string               name;
    std::string               namespaceName;
    std::string               assemblyName;
    uintptr_t                 classPtr;
    uint32_t                  objSize;
    std::vector<IL2CppField>  fields;
    std::vector<IL2CppMethod> methods;
    bool                      hasStaticFields;
};

struct IL2CppDumpResult {
    std::vector<IL2CppClass> classes;
    uintptr_t                domainAddr;
    size_t                   assemblyCount;
    std::string              formattedText;
};

bool DumpIL2CPP(HANDLE hProcess,
                const std::vector<ModuleEntry>& modules,
                const std::vector<ExportEntry>& exports,
                IL2CppDumpResult& result,
                ProgressCallback progress = nullptr);

std::string FormatIL2CppClass(const IL2CppClass& cls);
