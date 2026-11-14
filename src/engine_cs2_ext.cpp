// engine_cs2_ext.cpp -- Source Engine 2 ConVar Scanner + Vtable Extras
//
// Strategy overview:
//   Known convar name strings are searched inside the pre-read client.dll buffer.
//   For each found string offset we compute the absolute VA (clientBase + offset).
//   We then walk backwards from the string VA to find a ConVar object that has:
//     +0x08  char* m_pszName  -> points to our string
//     +0x00  vtable           -> points into .text (executable page)
//   Once the ConVar base is confirmed we read float/int/defaultValue fields.
//
// ConVar layout (Source 2 / CS2, approximate -- reversing from client.dll):
//   +0x00  void*   vtable
//   +0x08  char*   m_pszName
//   +0x10  char*   m_pszHelpText
//   +0x18  uint64  m_nFlags           (FCVAR_* bitmask)
//   +0x20  char*   m_pszDefaultValue
//   +0x28  int64   pad / callback
//   +0x30  float   m_flValue
//   +0x34  int32   m_nValue
//   +0x38  char*   m_pszString        (current value as string)
//
// Note: offsets may shift by +/-0x08 in different CS2 builds.
//       We scan a window and validate by cross-checking name ptr.
//
#include "dumper.h"
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>

// -----------------------------------------------------------------------
// RPM helpers (local, isolated from other translation units)
// -----------------------------------------------------------------------
static bool CS2_RPM(HANDLE hProc, uintptr_t addr, void* buf, size_t sz) {
    SIZE_T got = 0;
    return ReadProcessMemory(hProc, (LPCVOID)addr, buf, sz, &got) && got == sz;
}
static uintptr_t CS2_Ptr(HANDLE hProc, uintptr_t addr) {
    uintptr_t v = 0; CS2_RPM(hProc, addr, &v, 8); return v;
}
static float CS2_Float(HANDLE hProc, uintptr_t addr) {
    float v = 0.f; CS2_RPM(hProc, addr, &v, 4); return v;
}
static int32_t CS2_Int(HANDLE hProc, uintptr_t addr) {
    int32_t v = 0; CS2_RPM(hProc, addr, &v, 4); return v;
}
static std::string CS2_Str(HANDLE hProc, uintptr_t addr, size_t cap = 256) {
    if (!addr) return "";
    std::string s(cap, '\0');
    SIZE_T got = 0;
    ReadProcessMemory(hProc, (LPCVOID)addr, &s[0], cap, &got);
    s.resize(strnlen(s.c_str(), got));
    return s;
}

// -----------------------------------------------------------------------
// ConVarEntry struct (defined in header comment above, reproduced here)
// -----------------------------------------------------------------------
struct ConVarEntry {
    std::string name;
    std::string defaultValue;
    float       floatValue;
    int         intValue;
    uintptr_t   address;      // VA of the ConVar object
};

// -----------------------------------------------------------------------
// Check if a VA resides in an executable memory region
// -----------------------------------------------------------------------
static bool IsExecPage(HANDLE hProc, uintptr_t addr) {
    if (!addr || addr < 0x10000) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// -----------------------------------------------------------------------
// Validate that a candidate ConVar pointer makes structural sense
// Returns true + fills entry on success
// -----------------------------------------------------------------------
static bool ValidateConVar(HANDLE hProc,
                            uintptr_t candidateBase,
                            uintptr_t expectedNameVA,
                            ConVarEntry& out) {
    // Read vtable (first qword)
    uintptr_t vtable = CS2_Ptr(hProc, candidateBase + 0x00);
    if (!IsExecPage(hProc, vtable)) return false;

    // Check name ptr at +0x08 points to our known string VA
    uintptr_t namePtr = CS2_Ptr(hProc, candidateBase + 0x08);
    if (namePtr != expectedNameVA) return false;

    // Read string at namePtr
    std::string name = CS2_Str(hProc, namePtr, 128);
    if (name.empty() || name.size() > 64) return false;

    // Read defaultValue at +0x20
    uintptr_t defPtr    = CS2_Ptr  (hProc, candidateBase + 0x20);
    std::string defVal  = CS2_Str  (hProc, defPtr, 64);

    // Read float at +0x30, int at +0x34
    float   fval = CS2_Float(hProc, candidateBase + 0x30);
    int32_t ival = CS2_Int  (hProc, candidateBase + 0x34);

    out.name         = name;
    out.defaultValue = defVal;
    out.floatValue   = fval;
    out.intValue     = ival;
    out.address      = candidateBase;
    return true;
}

// =======================================================================
//  ScanConVars -- main scanner
// =======================================================================
//
//  clientBuf = full raw bytes of client.dll read from process
//  clientBase = base VA of client.dll in process
//
// =======================================================================

// Known ConVar names to search for (common Source 2 / CS2 convars)
static const char* KNOWN_CVAR_NAMES[] = {
    "sv_cheats",
    "sensitivity",
    "cl_fov",
    "mp_roundtime",
    "sv_gravity",
    "cl_interp",
    "r_drawothermodels",
    "net_graph",
    "voice_enable",
    "sv_infinite_ammo",
    // Extended list for broader coverage
    "sv_airaccelerate",
    "sv_accelerate",
    "sv_friction",
    "sv_maxvelocity",
    "sv_staminajumpcost",
    "cl_showpos",
    "cl_sidespeed",
    "cl_forwardspeed",
    "mat_wireframe",
    "r_drawtracers_firstperson",
    nullptr
};

// ConVar struct size upper bound -- how far back from the name string we search
// ConVar objects are typically 0x48 - 0x80 bytes in Source2
static constexpr int SCAN_BACK_MAX  = 0x80;
static constexpr int SCAN_BACK_STEP = 0x08;  // ptr-aligned

std::vector<ConVarEntry> ScanConVars(HANDLE hProcess,
                                      const std::vector<ModuleEntry>& modules,
                                      const std::vector<BYTE>& clientBuf,
                                      uintptr_t clientBase) {
    std::vector<ConVarEntry> results;

    if (clientBuf.empty() || !clientBase) return results;

    size_t bufSize = clientBuf.size();

    for (int ni = 0; KNOWN_CVAR_NAMES[ni] != nullptr; ni++) {
        const char* target  = KNOWN_CVAR_NAMES[ni];
        size_t      targLen = strlen(target);

        // Search for target string in clientBuf
        // We need it null-terminated and preceded by at least 1 null (or start of section)
        size_t found = std::string::npos;
        const uint8_t* data = clientBuf.data();

        for (size_t i = 0; i + targLen + 1 < bufSize; i++) {
            if (data[i] == (uint8_t)target[0] &&
                memcmp(data + i, target, targLen) == 0 &&
                data[i + targLen] == 0) {
                // Verify it's at a "proper" boundary -- previous byte null or i==0
                if (i == 0 || data[i - 1] == 0) {
                    found = i;
                    break;
                }
            }
        }

        if (found == std::string::npos) continue;

        uintptr_t nameVA = clientBase + (uintptr_t)found;

        // Walk backwards in pointer-aligned steps looking for a ConVar object
        // whose +0x08 namePtr == nameVA and +0x00 vtable is executable
        bool hitAny = false;
        for (int back = SCAN_BACK_STEP; back <= SCAN_BACK_MAX; back += SCAN_BACK_STEP) {
            uintptr_t candidateVA = nameVA - (uintptr_t)back;

            // Bounds check: must still be inside client.dll
            if (candidateVA < clientBase) break;
            size_t candidateOff = candidateVA - clientBase;
            if (candidateOff + 0x40 > bufSize) continue;

            // Read vtable from local buffer first (fast check)
            uintptr_t vtableLoc = *(uintptr_t*)(data + candidateOff);
            if (!vtableLoc || vtableLoc < 0x100000) continue;

            // Read name ptr from local buffer at +0x08
            uintptr_t namePtrLoc = *(uintptr_t*)(data + candidateOff + 0x08);
            if (namePtrLoc != nameVA) continue;

            // Full live-memory validation
            ConVarEntry entry{};
            if (ValidateConVar(hProcess, candidateVA, nameVA, entry)) {
                results.push_back(std::move(entry));
                hitAny = true;
                break;
            }
        }

        // If backwards walk failed, try forward from string - name might be at a different offset
        // Try: ConVar starts just before the string block (different layout builds)
        if (!hitAny) {
            // Alternative: scan for any ptr in clientBuf that == nameVA
            // then check if object at ptr-0x08 is valid ConVar
            for (size_t si = 0; si + 8 <= bufSize; si += 8) {
                uintptr_t candidate = *(uintptr_t*)(data + si);
                if (candidate == nameVA) {
                    // This si offset in buf is a field pointing to our name string
                    // If it's at +0x08 of ConVar, then ConVar starts at si-0x08
                    if (si < 0x08) continue;
                    uintptr_t objOffset = si - 0x08;
                    uintptr_t objVA     = clientBase + objOffset;
                    ConVarEntry entry{};
                    if (ValidateConVar(hProcess, objVA, nameVA, entry)) {
                        results.push_back(std::move(entry));
                        break;
                    }
                }
            }
        }
    }

    // Deduplicate by address
    std::sort(results.begin(), results.end(),
              [](const ConVarEntry& a, const ConVarEntry& b){
                  return a.address < b.address;
              });
    results.erase(std::unique(results.begin(), results.end(),
                              [](const ConVarEntry& a, const ConVarEntry& b){
                                  return a.address == b.address;
                              }),
                  results.end());

    return results;
}

// =======================================================================
//  Formatter
// =======================================================================
std::string FormatConVars(const std::vector<ConVarEntry>& cvars) {
    std::ostringstream ss;
    ss << "========================================\n";
    ss << " CS2 / SOURCE 2 CONVAR DUMP\n";
    ss << "========================================\n\n";
    ss << "Found " << cvars.size() << " ConVar(s)\n\n";

    ss << std::left
       << std::setw(28) << "Name"
       << " | " << std::setw(12) << "Default"
       << " | " << std::setw(10) << "Float"
       << " | " << std::setw(10) << "Int"
       << " | " << "Address\n";
    ss << std::string(28, '-') << "-+-"
       << std::string(12, '-') << "-+-"
       << std::string(10, '-') << "-+-"
       << std::string(10, '-') << "-+-"
       << std::string(18, '-') << "\n";

    for (const auto& cv : cvars) {
        ss << std::left  << std::setw(28) << cv.name.substr(0, 27)
           << " | " << std::setw(12) << cv.defaultValue.substr(0, 11)
           << " | " << std::setw(10) << cv.floatValue
           << " | " << std::setw(10) << cv.intValue
           << " | 0x" << std::hex << std::uppercase << cv.address << "\n";
    }
    return ss.str();
}
