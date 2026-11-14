// engine_ue.cpp -- Unreal Engine 4/5 Deep Scanner
#include "engine_ue.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

static bool RPM(HANDLE h, uintptr_t a, void* b, size_t s) {
    SIZE_T g=0; return ReadProcessMemory(h,(LPCVOID)a,b,s,&g)&&g==s;
}
static uintptr_t RPtr(HANDLE h, uintptr_t a){ uintptr_t v=0; RPM(h,a,&v,8); return v; }
static uint32_t  RU32(HANDLE h, uintptr_t a){ uint32_t  v=0; RPM(h,a,&v,4); return v; }
static uint16_t  RU16(HANDLE h, uintptr_t a){ uint16_t  v=0; RPM(h,a,&v,2); return v; }

static std::string ReadCString(HANDLE h, uintptr_t a, size_t mx=128) {
    if(!a) return "";
    char buf[129]={}; SIZE_T g=0;
    ReadProcessMemory(h,(LPCVOID)a,buf,std::min(mx,(size_t)128),&g);
    buf[g]=0;
    for(size_t i=0;i<g;i++) if((unsigned char)buf[i]<0x20||(unsigned char)buf[i]>0x7E) buf[i]='?';
    return buf;
}

// Decode UE4 FName
static std::string DecodeFNameUE4(HANDLE h, uintptr_t gNamesAddr, uint32_t nameIndex) {
    if (!gNamesAddr || nameIndex == 0) return "";
    uint32_t chunkIdx = nameIndex / 16384;
    uint32_t withinChunk = nameIndex % 16384;

    uintptr_t chunkArray = RPtr(h, gNamesAddr);
    if (!chunkArray) return "";

    uintptr_t chunkPtr = RPtr(h, chunkArray + chunkIdx * 8);
    if (!chunkPtr) return "";

    uintptr_t entryPtr = RPtr(h, chunkPtr + withinChunk * 8);
    if (!entryPtr) return "";

    uint16_t header = RU16(h, entryPtr);
    uint32_t len = header >> 6;
    if (len == 0 || len > 256) return "";

    return ReadCString(h, entryPtr + 2, len);
}

// Decode UE5 FNamePool
static std::string DecodeFNameUE5(HANDLE h, uintptr_t gNamesAddr, uint32_t nameIndex) {
    if (!gNamesAddr || nameIndex == 0) return "";
    uint32_t blockIdx = nameIndex >> 16;
    uint32_t offset   = nameIndex & 0xFFFF;

    uintptr_t blockPtr = RPtr(h, gNamesAddr + 0x10 + blockIdx * 8);
    if (!blockPtr) return "";

    uintptr_t entryPtr = blockPtr + offset * 2;
    uint16_t header = RU16(h, entryPtr);
    uint32_t len = header >> 6;
    if (len == 0 || len > 256) return "";

    return ReadCString(h, entryPtr + 2, len);
}

std::string DecodeFName(HANDLE hProcess, uintptr_t gNamesAddr, uint32_t nameIndex, UEVersion ver) {
    if (ver >= UE_50) return DecodeFNameUE5(hProcess, gNamesAddr, nameIndex);
    return DecodeFNameUE4(hProcess, gNamesAddr, nameIndex);
}

uintptr_t FindProcessEvent(HANDLE hProcess, uintptr_t gObjectsAddr, UEVersion ver) {
    if (!gObjectsAddr) return 0;
    // Walk first 100 UObjects to find valid vtable
    uintptr_t objArray = RPtr(hProcess, gObjectsAddr);
    if (!objArray) return 0;

    int slot = (ver >= UE_50) ? 62 : 61;

    for (uint32_t i = 1; i < 100; i++) {
        uintptr_t obj = RPtr(hProcess, objArray + i * 0x18);
        if (!obj) continue;

        uintptr_t vtable = RPtr(hProcess, obj);
        if (!vtable) continue;

        uintptr_t peFunc = RPtr(hProcess, vtable + slot * 8);
        if (peFunc && peFunc > 0x10000 && peFunc < 0x7FFFFFFFFFFF) return peFunc;
    }
    return 0;
}

bool DumpUnrealEngine(HANDLE hProcess,
                      const std::vector<ModuleEntry>& modules,
                      const std::vector<PatternResult>& patterns,
                      UEVersion version,
                      UEDumpResult& result,
                      ProgressCallback progress)
{
    result = {};
    auto prog = [&](const std::string& msg, int pct) {
        if (progress) {
            std::wstring w; for(char c:msg) w+=(wchar_t)c;
            progress(w, pct);
        }
    };

    prog("Locating GWorld, GObjects, GNames...", 5);
    for (auto& p : patterns) {
        if (p.label == "GWorld" && !result.gWorldAddr) result.gWorldAddr = p.address;
        if (p.label == "GObjects" && !result.gObjectsAddr) result.gObjectsAddr = p.address;
        if (p.label == "GNames" && !result.gNamesAddr) result.gNamesAddr = p.address;
    }

    if (result.gObjectsAddr) {
        prog("Finding UObject::ProcessEvent...", 20);
        result.processEventAddr = FindProcessEvent(hProcess, result.gObjectsAddr, version);
    }

    prog("Decoding GNames entry pool...", 35);
    if (result.gNamesAddr) {
        for (uint32_t i = 1; i <= 1000; i++) {
            std::string str = DecodeFName(hProcess, result.gNamesAddr, i, version);
            if (!str.empty()) {
                result.names.push_back({ i, str });
            }
        }
    }

    prog("Walking FUObjectArray...", 60);
    if (result.gObjectsAddr) {
        uintptr_t objArray = RPtr(hProcess, result.gObjectsAddr);
        if (objArray) {
            for (uint32_t i = 1; i <= 500; i++) {
                uintptr_t obj = RPtr(hProcess, objArray + i * 0x18);
                if (!obj) continue;

                UEObject uo;
                uo.address   = obj;
                uo.index     = i;
                uo.classAddr = RPtr(hProcess, obj + 0x10);

                uint32_t nameId = RU32(hProcess, obj + 0x18);
                uo.name = DecodeFName(hProcess, result.gNamesAddr, nameId, version);
                if (uo.name.empty()) uo.name = "Object_" + std::to_string(i);

                if (uo.classAddr) {
                    uint32_t classNameId = RU32(hProcess, uo.classAddr + 0x18);
                    uo.className = DecodeFName(hProcess, result.gNamesAddr, classNameId, version);
                }
                if (uo.className.empty()) uo.className = "UObject";

                result.objects.push_back(std::move(uo));
            }
        }
    }

    prog("Formatting Unreal Engine dump...", 90);
    std::ostringstream out;
    out << "================================================================\r\n";
    out << "  [UNREAL ENGINE DEEP DUMP]\r\n";
    out << "================================================================\r\n";
    out << "  GWorld       : 0x" << std::hex << std::uppercase << result.gWorldAddr << "\r\n";
    out << "  GObjects     : 0x" << result.gObjectsAddr << "\r\n";
    out << "  GNames       : 0x" << result.gNamesAddr << "\r\n";
    out << "  ProcessEvent : 0x" << result.processEventAddr << "\r\n";
    out << "  Objects Found: " << std::dec << result.objects.size() << "\r\n";
    out << "  Names Decoded: " << result.names.size() << "\r\n\r\n";

    if (!result.objects.empty()) {
        out << "  [UOBJECT ARRAY SAMPLE]\r\n";
        out << "  " << std::left << std::setw(8) << "Index"
            << std::setw(25) << "Class"
            << std::setw(30) << "Name"
            << "Address\r\n";
        out << "  ----------------------------------------------------------------\r\n";
        for (auto& o : result.objects) {
            out << "  " << std::left << std::setw(8) << o.index
                << std::setw(25) << o.className
                << std::setw(30) << o.name
                << "0x" << std::hex << std::uppercase << o.address << std::dec << "\r\n";
        }
        out << "\r\n";
    }

    result.formattedText = out.str();
    prog("Unreal Engine dump complete.", 100);
    return true;
}
