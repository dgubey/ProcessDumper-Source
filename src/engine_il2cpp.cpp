// engine_il2cpp.cpp -- IL2CPP Runtime Metadata Walker
// *the Il2CppDomain opens like a filing cabinet, every drawer a MonoAssembly*
#include "engine_il2cpp.h"
#include <cstdint>
#include <sstream>
#include <iomanip>

// ---------------------------------------------------------------------------
// IL2CPP internal struct layouts (runtime 29.x / Unity 2021-2023)
// Field offsets are stable across most IL2CPP versions for these core structs
// ---------------------------------------------------------------------------

// Offsets into Il2CppDomain
#define DOMAIN_ASSEMBLIES_OFFSET    0x08   // GSList* assemblies

// Offsets into Il2CppAssembly
#define ASSEMBLY_IMAGE_OFFSET       0x00   // Il2CppImage*

// Offsets into Il2CppImage
#define IMAGE_NAME_OFFSET           0x00   // const char* name
#define IMAGE_TYPE_COUNT_OFFSET     0x1C   // uint32 typeCount
#define IMAGE_TYPESTART_OFFSET      0x20   // int32 typeStart (index into typeDefinitions)
#define IMAGE_CLASS_CACHE_OFFSET    0x40   // Il2CppHashTable class cache (alt path)

// Offsets into Il2CppClass (type object, not instance)
#define CLASS_NAME_OFFSET           0x10   // const char* name
#define CLASS_NAMESPACE_OFFSET      0x18   // const char* namespaze
#define CLASS_IMAGE_OFFSET          0x28   // Il2CppImage*
#define CLASS_INSTANCE_SIZE_OFFSET  0x5C   // uint32 instance_size
#define CLASS_FIELD_COUNT_OFFSET    0x118  // uint16 field_count (may vary)
#define CLASS_FIELDS_OFFSET         0xA8   // FieldInfo* fields (ptr to array)
#define CLASS_METHOD_COUNT_OFFSET   0x11C  // uint16 method_count
#define CLASS_METHODS_OFFSET        0xB0   // MethodInfo** methods
#define CLASS_STATIC_FIELDS_OFFSET  0xB8   // void* static_fields

// Offsets into FieldInfo
#define FIELD_NAME_OFFSET           0x00   // const char* name
#define FIELD_TYPE_OFFSET           0x08   // Il2CppType*
#define FIELD_PARENT_OFFSET         0x10   // Il2CppClass*
#define FIELD_OFFSET_OFFSET         0x18   // int32 offset

// Offsets into MethodInfo
#define METHOD_METHODPTR_OFFSET     0x00   // Il2CppMethodPointer (fn ptr)
#define METHOD_NAME_OFFSET          0x10   // const char* name
#define METHOD_RETURN_TYPE_OFFSET   0x30   // Il2CppType* return_type
#define METHOD_PARAM_COUNT_OFFSET   0x38   // uint8 parameters_count

// Il2CppType
#define TYPE_DATA_OFFSET            0x00   // typeid or class ptr
#define TYPE_ATTRS_OFFSET           0x08   // uint16 attrs
#define TYPE_TYPE_OFFSET            0x0A   // uint8 type enum

// GSList
#define GSLIST_DATA_OFFSET          0x00   // void* data
#define GSLIST_NEXT_OFFSET          0x08   // GSList* next

// ---------------------------------------------------------------------------
// Safe string read from target process
// ---------------------------------------------------------------------------
static std::string ReadCString(HANDLE hProc, uintptr_t addr, size_t maxLen = 256) {
    if (!addr) return "";
    char buf[257] = {};
    SIZE_T got = 0;
    if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(addr), buf,
                           std::min(maxLen, (size_t)256), &got))
        return "";
    buf[got] = 0;
    // Validate printable
    for (size_t i = 0; i < got; i++) {
        if (buf[i] == 0) break;
        if ((unsigned char)buf[i] < 0x20 || (unsigned char)buf[i] > 0x7E) {
            buf[i] = '?';
        }
    }
    return std::string(buf);
}

static bool RPM(HANDLE h, uintptr_t addr, void* buf, size_t sz) {
    SIZE_T got = 0;
    return ReadProcessMemory(h, reinterpret_cast<LPCVOID>(addr), buf, sz, &got) && got == sz;
}

static uintptr_t ReadPtr(HANDLE h, uintptr_t addr) {
    uintptr_t val = 0;
    RPM(h, addr, &val, sizeof(val));
    return val;
}

static uint32_t ReadU32(HANDLE h, uintptr_t addr) {
    uint32_t val = 0;
    RPM(h, addr, &val, sizeof(val));
    return val;
}

static uint16_t ReadU16(HANDLE h, uintptr_t addr) {
    uint16_t val = 0;
    RPM(h, addr, &val, sizeof(val));
    return val;
}

static int32_t ReadI32(HANDLE h, uintptr_t addr) {
    int32_t val = 0;
    RPM(h, addr, &val, sizeof(val));
    return val;
}

// ---------------------------------------------------------------------------
// IL2CPP type enum to name
// ---------------------------------------------------------------------------
static const char* IL2CppTypeStr(uint8_t typeEnum) {
    static const char* names[] = {
        "END","void","bool","char","int8","uint8","int16","uint16",
        "int32","uint32","int64","uint64","float","double","string",
        "ptr","byref","valuetype","class","var","array","genericinst",
        "typedbyref","I","U","fnptr","object","szarray","mvar","cmod_reqd",
        "cmod_opt","internal","modifier","sentinel","pinned"
    };
    if (typeEnum < sizeof(names)/sizeof(names[0])) return names[typeEnum];
    return "unknown";
}

// ---------------------------------------------------------------------------
// Read a FieldInfo array
// ---------------------------------------------------------------------------
static std::vector<IL2CppField> ReadFields(HANDLE hProc, uintptr_t classPtr) {
    std::vector<IL2CppField> fields;

    uint16_t fieldCount = ReadU16(hProc, classPtr + CLASS_FIELD_COUNT_OFFSET);
    uintptr_t fieldsPtr = ReadPtr(hProc, classPtr + CLASS_FIELDS_OFFSET);

    if (!fieldsPtr || fieldCount == 0 || fieldCount > 1024) return fields;

    // Each FieldInfo is about 0x20 bytes
    const size_t FIELD_STRIDE = 0x20;
    for (uint16_t i = 0; i < fieldCount; i++) {
        uintptr_t fBase = fieldsPtr + i * FIELD_STRIDE;

        IL2CppField f;
        uintptr_t namePtr = ReadPtr(hProc, fBase + FIELD_NAME_OFFSET);
        f.name = ReadCString(hProc, namePtr);
        if (f.name.empty()) f.name = "(unnamed_" + std::to_string(i) + ")";

        int32_t offset = ReadI32(hProc, fBase + FIELD_OFFSET_OFFSET);
        f.fieldOffset = (uint32_t)offset;

        // Type info
        uintptr_t typePtr = ReadPtr(hProc, fBase + FIELD_TYPE_OFFSET);
        if (typePtr) {
            uint8_t typeEnum = 0;
            RPM(hProc, typePtr + TYPE_TYPE_OFFSET, &typeEnum, 1);
            f.typeName = IL2CppTypeStr(typeEnum);
            // Static if offset == 0xFFFFFFFF and not value type
            f.isStatic = (offset < 0);
        } else {
            f.typeName = "?";
            f.isStatic = false;
        }

        if (f.isStatic) {
            uintptr_t staticFields = ReadPtr(hProc, classPtr + CLASS_STATIC_FIELDS_OFFSET);
            if (staticFields && f.fieldOffset != (uint32_t)-1) {
                f.staticValueAddr = staticFields + (uint32_t)(f.fieldOffset & 0x7FFFFFFF);
            }
        }

        fields.push_back(std::move(f));
    }
    return fields;
}

// ---------------------------------------------------------------------------
// Read a MethodInfo* array
// ---------------------------------------------------------------------------
static std::vector<IL2CppMethod> ReadMethods(HANDLE hProc, uintptr_t classPtr) {
    std::vector<IL2CppMethod> methods;

    uint16_t methodCount = ReadU16(hProc, classPtr + CLASS_METHOD_COUNT_OFFSET);
    uintptr_t methodsPtrPtr = ReadPtr(hProc, classPtr + CLASS_METHODS_OFFSET);

    if (!methodsPtrPtr || methodCount == 0 || methodCount > 4096) return methods;

    for (uint16_t i = 0; i < methodCount; i++) {
        // methods is MethodInfo** — double pointer array
        uintptr_t mPtr = ReadPtr(hProc, methodsPtrPtr + i * sizeof(uintptr_t));
        if (!mPtr) continue;

        IL2CppMethod m;
        uintptr_t fnPtr = ReadPtr(hProc, mPtr + METHOD_METHODPTR_OFFSET);
        m.methodPtr = fnPtr;
        m.rva       = fnPtr; // caller can subtract module base

        uintptr_t namePtr = ReadPtr(hProc, mPtr + METHOD_NAME_OFFSET);
        m.name = ReadCString(hProc, namePtr);
        if (m.name.empty()) m.name = "(anonymous_" + std::to_string(i) + ")";

        uint8_t numParams = 0;
        RPM(hProc, mPtr + METHOD_PARAM_COUNT_OFFSET, &numParams, 1);
        m.numParams = numParams;

        // Return type
        uintptr_t retTypePtr = ReadPtr(hProc, mPtr + METHOD_RETURN_TYPE_OFFSET);
        if (retTypePtr) {
            uint8_t typeEnum = 0;
            RPM(hProc, retTypePtr + TYPE_TYPE_OFFSET, &typeEnum, 1);
            m.returnType = IL2CppTypeStr(typeEnum);
        } else {
            m.returnType = "void";
        }

        methods.push_back(std::move(m));
    }
    return methods;
}

// ---------------------------------------------------------------------------
// Find export by name in export table
// ---------------------------------------------------------------------------
static uintptr_t FindExportAddr(const std::vector<ExportEntry>& exports,
                                 const char* name) {
    for (auto& e : exports)
        if (e.name == name) return e.va;
    return 0;
}

// ---------------------------------------------------------------------------
// Main IL2CPP dump
// ---------------------------------------------------------------------------
bool DumpIL2CPP(HANDLE hProcess,
                const std::vector<ModuleEntry>& modules,
                const std::vector<ExportEntry>& exports,
                IL2CppDumpResult& result,
                ProgressCallback progress) {

    result = {};
    auto prog = [&](const std::string& msg, int pct) {
        if (progress) {
            std::wstring wmsg(msg.begin(), msg.end());
            progress(wmsg, pct);
        }
    };

    // Find GameAssembly module base
    uintptr_t gaBase = 0;
    for (auto& m : modules) {
        std::wstring nl = m.name;
        for (auto& c : nl) c = towlower(c);
        if (nl == L"gameassembly.dll" || nl == L"il2cpp.dll") {
            gaBase = m.base;
            break;
        }
    }
    if (!gaBase) return false;

    prog("Finding il2cpp_domain_get...", 5);

    // Step 1: get domain via il2cpp_domain_get export
    uintptr_t domainGetAddr = FindExportAddr(exports, "il2cpp_domain_get");
    if (!domainGetAddr) return false;

    // Read first 64 bytes of il2cpp_domain_get function to find RIP-relative pointer
    BYTE instrBuf[64] = {};
    if (!RPM(hProcess, domainGetAddr, instrBuf, sizeof(instrBuf))) return false;

    uintptr_t domainPtrAddr = 0;
    for (size_t i = 0; i < 56; i++) {
        // Pattern 1: MOV RAX, [RIP+disp32] -> 48 8B 05 XX XX XX XX
        // Pattern 2: LEA RAX, [RIP+disp32] -> 48 8D 05 XX XX XX XX
        // Pattern 3: MOV RCX, [RIP+disp32] -> 48 8B 0D XX XX XX XX
        if (instrBuf[i] == 0x48 && (instrBuf[i+1] == 0x8B || instrBuf[i+1] == 0x8D) && (instrBuf[i+2] == 0x05 || instrBuf[i+2] == 0x0D)) {
            int32_t disp = 0;
            memcpy(&disp, instrBuf + i + 3, 4);
            domainPtrAddr = domainGetAddr + i + 7 + disp;
            break;
        }
        // Pattern 4: JMP relative -> E9 XX XX XX XX
        if (i == 0 && instrBuf[0] == 0xE9) {
            int32_t jmpDisp = 0;
            memcpy(&jmpDisp, instrBuf + 1, 4);
            uintptr_t targetFn = domainGetAddr + 5 + jmpDisp;
            BYTE targetBuf[32] = {};
            if (RPM(hProcess, targetFn, targetBuf, sizeof(targetBuf))) {
                for (size_t j = 0; j < 24; j++) {
                    if (targetBuf[j] == 0x48 && (targetBuf[j+1] == 0x8B || targetBuf[j+1] == 0x8D) && (targetBuf[j+2] == 0x05 || targetBuf[j+2] == 0x0D)) {
                        int32_t disp = 0;
                        memcpy(&disp, targetBuf + j + 3, 4);
                        domainPtrAddr = targetFn + j + 7 + disp;
                        break;
                    }
                }
            }
            if (domainPtrAddr) break;
        }
    }

    if (!domainPtrAddr) return false;

    uintptr_t domainAddr = ReadPtr(hProcess, domainPtrAddr);
    if (!domainAddr) return false;
    result.domainAddr = domainAddr;

    prog("Walking assemblies...", 15);

    // Step 2: get assembly list from domain
    // domain->domain_assemblies is a GSList*
    uintptr_t assemblyList = ReadPtr(hProcess, domainAddr + DOMAIN_ASSEMBLIES_OFFSET);
    if (!assemblyList) return false;

    int classesProcessed = 0;
    int maxClasses = 500; // cap to avoid infinite loop / huge files

    // Step 3: walk assembly GSList
    uintptr_t node = assemblyList;
    int assemblyIdx = 0;
    while (node && assemblyIdx < 64) {
        uintptr_t assemblyPtr = ReadPtr(hProcess, node + GSLIST_DATA_OFFSET);
        node = ReadPtr(hProcess, node + GSLIST_NEXT_OFFSET);
        if (!assemblyPtr) { assemblyIdx++; continue; }

        // Step 4: get image from assembly
        uintptr_t imagePtr = ReadPtr(hProcess, assemblyPtr + ASSEMBLY_IMAGE_OFFSET);
        if (!imagePtr) { assemblyIdx++; continue; }

        uintptr_t namePtr = ReadPtr(hProcess, imagePtr + IMAGE_NAME_OFFSET);
        std::string assemblyName = ReadCString(hProcess, namePtr);
        if (assemblyName.empty()) assemblyName = "assembly_" + std::to_string(assemblyIdx);

        int pct = 15 + (assemblyIdx * 60 / 64);
        prog("Walking: " + assemblyName, pct);

        // Step 5: enumerate classes via type_count and typeStart
        uint32_t typeCount = ReadU32(hProcess, imagePtr + IMAGE_TYPE_COUNT_OFFSET);
        if (typeCount == 0 || typeCount > 10000) { assemblyIdx++; continue; }

        // Il2CppClass** typeInfos — image has a TypeInfos array ptr
        // In newer IL2CPP: image->metadataHandle -> TypeDefinitions
        // We use the class cache approach: walk image's internal class array
        // The TypeInfos pointer is usually at image + 0x50 or image + 0x58
        // Try a few known offsets
        uintptr_t typeInfosArr = 0;
        for (size_t tryOff : { (size_t)0x50, (size_t)0x58, (size_t)0x48, (size_t)0x60 }) {
            uintptr_t candidate = ReadPtr(hProcess, imagePtr + tryOff);
            if (candidate && candidate != imagePtr) {
                // Validate: first element should be a valid-looking class ptr
                uintptr_t firstClass = ReadPtr(hProcess, candidate);
                if (firstClass && (firstClass & 0xFFFF) == 0) { // aligned
                    typeInfosArr = candidate;
                    break;
                }
            }
        }

        if (!typeInfosArr) { assemblyIdx++; continue; }

        uint32_t limit = std::min(typeCount, (uint32_t)300);
        for (uint32_t ci = 0; ci < limit && classesProcessed < maxClasses; ci++) {
            uintptr_t classPtr = ReadPtr(hProcess, typeInfosArr + ci * sizeof(uintptr_t));
            if (!classPtr) continue;

            IL2CppClass cls;
            cls.classPtr    = classPtr;
            cls.assemblyName= assemblyName;

            uintptr_t clsNamePtr = ReadPtr(hProcess, classPtr + CLASS_NAME_OFFSET);
            uintptr_t clsNsPtr   = ReadPtr(hProcess, classPtr + CLASS_NAMESPACE_OFFSET);
            cls.name          = ReadCString(hProcess, clsNamePtr);
            cls.namespaceName = ReadCString(hProcess, clsNsPtr);
            if (cls.name.empty()) continue;

            cls.objSize = ReadU32(hProcess, classPtr + CLASS_INSTANCE_SIZE_OFFSET);

            // Fields
            cls.fields  = ReadFields(hProcess, classPtr);
            cls.methods = ReadMethods(hProcess, classPtr);
            cls.hasStaticFields = ReadPtr(hProcess, classPtr + CLASS_STATIC_FIELDS_OFFSET) != 0;

            result.classes.push_back(std::move(cls));
            classesProcessed++;
        }
        assemblyIdx++;
    }

    result.assemblyCount = assemblyIdx;

    prog("Formatting IL2CPP output...", 85);

    // Format output
    std::ostringstream out;
    out << "================================================================\r\n";
    out << "  [IL2CPP METADATA DUMP]\r\n";
    out << "================================================================\r\n";
    out << "  Domain    : 0x" << std::hex << std::uppercase << result.domainAddr << "\r\n";
    out << "  Assemblies: " << std::dec << result.assemblyCount << "\r\n";
    out << "  Classes   : " << result.classes.size() << "\r\n";
    out << "\r\n";

    for (auto& cls : result.classes) {
        out << "----------------------------------------------------------------\r\n";
        std::string fullName = cls.namespaceName.empty()
            ? cls.name
            : cls.namespaceName + "." + cls.name;
        out << "  class " << fullName << " [" << cls.assemblyName << "]";
        out << "  size=0x" << std::hex << cls.objSize << std::dec;
        out << "  ptr=0x" << std::hex << cls.classPtr << std::dec << "\r\n";
        out << "  {\r\n";

        if (cls.fields.empty()) {
            out << "    // (no fields accessible)\r\n";
        } else {
            for (auto& f : cls.fields) {
                out << "    ";
                if (f.isStatic) out << "static ";
                out << std::left << std::setw(12) << f.typeName << " ";
                out << std::left << std::setw(40) << f.name;
                if (!f.isStatic) {
                    out << "  // offset=0x" << std::hex << f.fieldOffset << std::dec;
                } else {
                    out << "  // static addr=0x" << std::hex << f.staticValueAddr << std::dec;
                }
                out << "\r\n";
            }
        }

        if (!cls.methods.empty()) {
            out << "\r\n    // -- Methods --\r\n";
            for (auto& m : cls.methods) {
                out << "    " << std::left << std::setw(8) << m.returnType << " "
                    << std::left << std::setw(40) << m.name
                    << "(params=" << m.numParams << ")"
                    << "  // addr=0x" << std::hex << m.methodPtr << std::dec << "\r\n";
            }
        }

        out << "  }\r\n\r\n";
    }

    result.formattedText = out.str();
    prog("IL2CPP dump complete.", 100);
    return !result.classes.empty();
}

std::string FormatIL2CppClass(const IL2CppClass& cls) {
    std::ostringstream out;
    std::string fn = cls.namespaceName.empty() ? cls.name : cls.namespaceName + "." + cls.name;
    out << "class " << fn << " (size=0x" << std::hex << cls.objSize << ") {\r\n";
    for (auto& f : cls.fields) {
        out << "    ";
        if (f.isStatic) out << "static ";
        out << f.typeName << " " << f.name;
        if (!f.isStatic) out << "; // 0x" << std::hex << f.fieldOffset;
        out << "\r\n";
    }
    out << "}\r\n";
    return out.str();
}

