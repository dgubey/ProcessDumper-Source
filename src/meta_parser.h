// meta_parser.h -- IL2CPP global-metadata.dat Disk Parser
#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct MetaTypeInfo {
    std::string name;
    std::string namespaceName;
    int32_t     fieldStart;
    uint16_t    fieldCount;
    int32_t     methodStart;
    uint16_t    methodCount;
};

struct MetaFieldDef {
    std::string name;
    std::string typeName;
    int32_t     typeIndex;
};

struct MetaDumpResult {
    std::vector<MetaTypeInfo> types;
    std::vector<MetaFieldDef> fields;
    uint32_t    version;
    bool        valid;
    std::string formattedText;
};

bool ParseMetadataDat(const std::wstring& filePath, MetaDumpResult& result);
std::wstring FindMetadataFile(const std::wstring& exePath);
