#include <windows.h>
// meta_parser.cpp -- IL2CPP global-metadata.dat Parser
#include "meta_parser.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

static const uint32_t META_MAGIC = 0xFAB11BAF;

struct MetaTableEntry { int32_t offset; int32_t count; };

struct Il2CppTypeDefinition {
    int32_t nameIndex;
    int32_t namespaceIndex;
    int32_t customAttributeIndex;
    int32_t byvalTypeIndex;
    int32_t declaringTypeIndex;
    int32_t parentIndex;
    int32_t elementTypeIndex;
    int32_t genericContainerIndex;
    uint32_t flags;
    int32_t fieldStart;
    int32_t methodStart;
    int32_t eventStart;
    int32_t propertyStart;
    int32_t nestedTypesStart;
    int32_t interfacesStart;
    int32_t vtableStart;
    int32_t interfaceOffsetsStart;
    uint16_t method_count;
    uint16_t property_count;
    uint16_t field_count;
    uint16_t event_count;
    uint16_t nested_type_count;
    uint16_t vtable_count;
    uint16_t interfaces_count;
    uint16_t interface_offsets_count;
    uint32_t bitfield;
    uint32_t token;
};

struct Il2CppFieldDefinition {
    int32_t nameIndex;
    int32_t typeIndex;
    uint32_t token;
};

bool ParseMetadataDat(const std::wstring& filePath, MetaDumpResult& result) {
    result = {};
    result.valid = false;

    // Open stream with c_str() for wchar_t compatibility in MinGW
    std::ifstream f(filePath.c_str(), std::ios::binary);
    if (!f.is_open()) return false;

    f.seekg(0, std::ios::end);
    size_t sz = (size_t)f.tellg();
    f.seekg(0);

    if (sz < 64 || sz > 256*1024*1024) return false;
    std::vector<uint8_t> buf(sz);
    f.read((char*)buf.data(), sz);
    if (!f) return false;

    uint32_t magic = 0; memcpy(&magic, buf.data(), 4);
    if (magic != META_MAGIC) return false;
    uint32_t ver = 0; memcpy(&ver, buf.data()+4, 4);
    result.version = ver;

    auto getTable = [&](int idx) -> MetaTableEntry {
        MetaTableEntry e = {0, 0};
        size_t off = 8 + idx * 8;
        if (off + 8 <= buf.size()) memcpy(&e, buf.data() + off, 8);
        return e;
    };

    // IL2CPP Global Metadata Table Indices:
    // 0: stringLiteral, 1: stringLiteralData, 2: string (names pool!), 11: fields, 19: typeDefinitions
    MetaTableEntry stringTable  = getTable(2);
    MetaTableEntry fieldDefs    = getTable(11);
    MetaTableEntry typeDefs     = getTable(19);

    if (typeDefs.offset <= 0 || typeDefs.count <= 0) {
        // Fallback for alternate versions (try tables 18, 10, 1)
        typeDefs = getTable(18);
        fieldDefs = getTable(10);
        stringTable = getTable(1);
    }

    if (typeDefs.offset <= 0 || typeDefs.count <= 0) return false;

    auto getString = [&](int32_t idx) -> std::string {
        if (idx < 0 || (uint32_t)idx >= (uint32_t)stringTable.count) return "";
        size_t off = (size_t)stringTable.offset + idx;
        if (off >= buf.size()) return "";
        const char* s = (const char*)buf.data() + off;
        size_t maxLen = std::min((size_t)256, buf.size() - off);
        return std::string(s, strnlen(s, maxLen));
    };

    size_t typeCount = std::min((uint32_t)typeDefs.count, (uint32_t)10000);
    result.types.reserve(typeCount);
    for (size_t i = 0; i < typeCount; i++) {
        size_t off = (size_t)typeDefs.offset + i * sizeof(Il2CppTypeDefinition);
        if (off + sizeof(Il2CppTypeDefinition) > buf.size()) break;
        Il2CppTypeDefinition td;
        memcpy(&td, buf.data() + off, sizeof(td));
        MetaTypeInfo mt;
        mt.name          = getString(td.nameIndex);
        mt.namespaceName = getString(td.namespaceIndex);
        mt.fieldStart    = td.fieldStart;
        mt.fieldCount    = td.field_count;
        mt.methodStart   = td.methodStart;
        mt.methodCount   = td.method_count;
        if (!mt.name.empty()) result.types.push_back(std::move(mt));
    }

    if (fieldDefs.offset > 0 && fieldDefs.count > 0) {
        size_t fc = std::min((uint32_t)fieldDefs.count, (uint32_t)100000);
        result.fields.reserve(fc);
        for (size_t i = 0; i < fc; i++) {
            size_t off = (size_t)fieldDefs.offset + i * sizeof(Il2CppFieldDefinition);
            if (off + sizeof(Il2CppFieldDefinition) > buf.size()) break;
            Il2CppFieldDefinition fd;
            memcpy(&fd, buf.data() + off, sizeof(fd));
            MetaFieldDef mf;
            mf.name      = getString(fd.nameIndex);
            mf.typeIndex = fd.typeIndex;
            mf.typeName  = "";
            if (!mf.name.empty()) result.fields.push_back(std::move(mf));
        }
    }

    std::ostringstream out;
    out << "================================================================\r\n";
    out << "  [IL2CPP METADATA.DAT STATIC PARSE]\r\n";
    out << "================================================================\r\n";
    out << "  Version : " << ver << "\r\n";
    out << "  Types   : " << result.types.size() << "\r\n";
    out << "  Fields  : " << result.fields.size() << "\r\n\r\n";

    size_t limit = std::min(result.types.size(), (size_t)500);
    for (size_t i = 0; i < limit; i++) {
        auto& t = result.types[i];
        std::string fn = t.namespaceName.empty() ? t.name : t.namespaceName + "." + t.name;
        out << "  class " << fn;
        if (t.fieldCount > 0) {
            out << " { // " << t.fieldCount << " fields\r\n";
            size_t fEnd = (size_t)t.fieldStart + t.fieldCount;
            for (size_t fi = t.fieldStart; fi < fEnd && fi < result.fields.size(); fi++) {
                out << "    " << result.fields[fi].name << ";\r\n";
            }
            out << "  }\r\n";
        } else {
            out << " {};\r\n";
        }
    }
    if (result.types.size() > 500) out << "  ... (" << result.types.size() - 500 << " more types)\r\n";

    result.formattedText = out.str();
    result.valid = !result.types.empty();
    return result.valid;
}

std::wstring FindMetadataFile(const std::wstring& exePath) {
    std::wstring dir = exePath;
    size_t sl = dir.find_last_of(L"\\/");
    if (sl != std::wstring::npos) dir = dir.substr(0, sl);

    static const wchar_t* PATHS[] = {
        L"\\cpp_data\\Metadata\\global-metadata.dat",
        L"\\TaskBarHero_Data\\Managed\\Metadata\\global-metadata.dat",
        L"\\Managed\\Metadata\\global-metadata.dat",
        L"\\Metadata\\global-metadata.dat",
        L"\\global-metadata.dat",
        nullptr
    };
    for (int i = 0; PATHS[i]; i++) {
        std::wstring full = dir + PATHS[i];
        if (GetFileAttributesW(full.c_str()) != INVALID_FILE_ATTRIBUTES) return full;
    }

    // Search all subdirectories under game directory
    WIN32_FIND_DATAW fd = {};
    std::wstring pat = dir + L"\\*";
    HANDLE fh = FindFirstFileW(pat.c_str(), &fd);
    if (fh != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                std::wstring candidates[] = {
                    dir + L"\\" + fd.cFileName + L"\\Metadata\\global-metadata.dat",
                    dir + L"\\" + fd.cFileName + L"\\Managed\\Metadata\\global-metadata.dat"
                };
                for (auto& cand : candidates) {
                    if (GetFileAttributesW(cand.c_str()) != INVALID_FILE_ATTRIBUTES) {
                        FindClose(fh); return cand;
                    }
                }
            }
        } while (FindNextFileW(fh, &fd));
        FindClose(fh);
    }
    return L"";
}

