// cs2_autoregen.cpp
// CS2 Signature Auto-Regenerator
//
// After a CS2 build update, RIP-relative displacements change because
// functions and globals move. This module re-discovers them by:
//
//   1. Parsing client.dll PE sections (.text, .data, .bss) from a buffer.
//   2. Scanning ALL 7-byte RIP-relative MOV instructions in .text:
//        opcode bytes 0..1 (or 0..2), then 4-byte little-endian disp32.
//      Covered encodings:
//        48 8B 05 dd dd dd dd   MOV RAX, [RIP+disp32]
//        48 8B 0D dd dd dd dd   MOV RCX, [RIP+disp32]
//        48 8B 15 dd dd dd dd   MOV RDX, [RIP+disp32]
//        48 8B 1D dd dd dd dd   MOV RBX, [RIP+disp32]
//        48 8B 2D dd dd dd dd   MOV RBP, [RIP+disp32]
//        48 8B 35 dd dd dd dd   MOV RSI, [RIP+disp32]
//        48 8B 3D dd dd dd dd   MOV RDI, [RIP+disp32]
//        4C 8B 05 dd dd dd dd   MOV R8,  [RIP+disp32]
//        4C 8B 0D dd dd dd dd   MOV R9,  [RIP+disp32]
//        4C 8B 15 dd dd dd dd   MOV R10, [RIP+disp32]
//        4C 8B 1D dd dd dd dd   MOV R11, [RIP+disp32]
//        48 8D 05 dd dd dd dd   LEA RAX, [RIP+disp32]
//        48 8D 0D dd dd dd dd   LEA RCX, [RIP+disp32]
//        48 89 05 dd dd dd dd   MOV [RIP+disp32], RAX  (stores)
//        48 89 0D dd dd dd dd   MOV [RIP+disp32], RCX
//
//   3. Resolves: target_va = instruction_end_va + sign_extend(disp32)
//                          = (clientBase + instrOff + 7) + (int32_t)disp32
//
//   4. Checks if target_va lands in .data or .bss (global variable pointer).
//
//   5. Builds a wildcard pattern:
//        bytes 0..1 (prefix + opcode) = literal
//        byte  2    (ModRM)           = literal
//        bytes 3..6 (disp32)          = "??"
//        bytes 7..10 (4 following)    = literal context (for uniqueness)
//      e.g. "48 8B 05 ?? ?? ?? ?? 48 83 C4 08"
//
// Known label table is defined in this file -- edit as patterns evolve.
// Output is written to C:\Users\HZLoxi\Desktop\dumper\regen_patterns.txt.
//
#include "cs2_autoregen.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <cstdio>

// ---------------------------------------------------------------------------
// Internal section info (same as vtable_scan but self-contained here)
// ---------------------------------------------------------------------------
struct CS2Section {
    uintptr_t vaBase;
    uint32_t  fileOff;
    uint32_t  size;
    uint32_t  chars;
};

// ---------------------------------------------------------------------------
// RIP-relative MOV/LEA instruction descriptor
// ---------------------------------------------------------------------------
struct RIPInstr {
    size_t    bufOff;       // offset of the first opcode byte in clientBuf
    uintptr_t instrVA;      // VA of first byte
    uintptr_t targetVA;     // resolved RIP+disp32 target
    uint8_t   bytes[7];     // the 7 instruction bytes
    uint8_t   context[4];   // 4 bytes following the instruction
};

// ---------------------------------------------------------------------------
// KnownLabel -- one entry from the built-in pattern table
// ---------------------------------------------------------------------------
struct KnownLabel {
    const char* label;
    const char* oldPattern;  // original pattern string (may fail after update)
};

// Known CS2 global-variable access patterns (commonly hunted offsets).
// These are the labels we try to regenerate when they fail to match.
static const KnownLabel s_knownLabels[] = {
    { "dwLocalPlayerController", "48 8B 05 ?? ?? ?? ?? 48 85 C0 74" },
    { "dwLocalPlayerPawn",        "48 8B 05 ?? ?? ?? ?? 48 85 C0 75" },
    { "dwEntityList",             "4C 8B 05 ?? ?? ?? ?? 49 63" },
    { "dwViewAngles",             "48 8B 0D ?? ?? ?? ?? 48 85 C9 74" },
    { "dwViewMatrix",             "48 8D 05 ?? ?? ?? ?? 48 89" },
    { "dwGameRules",              "48 8B 05 ?? ?? ?? ?? 48 85 C0 0F" },
    { "dwGlobalVars",             "48 8B 0D ?? ?? ?? ?? 8B 81" },
    { "dwPlantedC4",              "4C 8B 05 ?? ?? ?? ?? 4D 85 C0 74" },
    { "dwBombSite",               "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? FF 50" },
    { "dwSensitivity",            "F3 0F 10 05 ?? ?? ?? ?? F3 0F 59" },
    { "dwSensitivityScale",       "F3 0F 10 0D ?? ?? ?? ?? F3 0F 59" },
    { "dwCSGOInput",              "48 8B 0D ?? ?? ?? ?? 48 8B 01 FF" },
    { "m_pGameSceneNode",         "48 8B 05 ?? ?? ?? ?? 48 8B 48" },
    { "m_iHealth",                "8B 83 ?? ?? ?? ?? 85 C0 0F" },
    { "m_iTeamNum",               "8B 8B ?? ?? ?? ?? 83 F9 02" },
    { "m_bDormant",               "80 BB ?? ?? ?? ?? 00 75" },
    { "m_iszPlayerName",          "48 8D 95 ?? ?? ?? ?? 48 8B 0D" },
    { "m_vecOrigin",              "F3 0F 58 88 ?? ?? ?? ?? F3 0F" },
    { "m_fFlags",                 "8B 83 ?? ?? ?? ?? A8 01 75" },
    { "m_hActiveWeapon",          "8B 83 ?? ?? ?? ?? 89 85" },
};

// ---------------------------------------------------------------------------
// ParseCS2Sections
// ---------------------------------------------------------------------------
static bool ParseCS2Sections(const std::vector<BYTE>& buf,
                              uintptr_t                 base,
                              std::vector<CS2Section>&  sections)
{
    if (buf.size() < sizeof(IMAGE_DOS_HEADER))
        return false;
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    LONG lfanew = dos->e_lfanew;
    if (lfanew < 0 || static_cast<size_t>(lfanew) + sizeof(IMAGE_NT_HEADERS64) > buf.size())
        return false;
    const IMAGE_NT_HEADERS64* nt =
        reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    uint16_t n = nt->FileHeader.NumberOfSections;
    size_t secOff = lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
                    + nt->FileHeader.SizeOfOptionalHeader;
    for (uint16_t i = 0; i < n; i++) {
        size_t sa = secOff + i * sizeof(IMAGE_SECTION_HEADER);
        if (sa + sizeof(IMAGE_SECTION_HEADER) > buf.size()) break;
        const IMAGE_SECTION_HEADER* sec =
            reinterpret_cast<const IMAGE_SECTION_HEADER*>(buf.data() + sa);
        CS2Section s = {};
        s.vaBase  = base + sec->VirtualAddress;
        s.fileOff = sec->PointerToRawData;
        s.size    = std::min(sec->SizeOfRawData, sec->Misc.VirtualSize);
        s.chars   = sec->Characteristics;
        sections.push_back(s);
    }
    return !sections.empty();
}

// ---------------------------------------------------------------------------
// BytesToHex -- format a byte array as "AA BB CC ..."
// ---------------------------------------------------------------------------
static std::string BytesToHex(const uint8_t* data, size_t len)
{
    std::ostringstream ss;
    for (size_t i = 0; i < len; i++) {
        if (i) ss << " ";
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
           << static_cast<int>(data[i]);
    }
    return ss.str();
}

// ---------------------------------------------------------------------------
// BuildWildcardPattern
//   Takes a RIPInstr and builds the pattern with bytes 3-6 wildcarded:
//   "<byte0> <byte1> <byte2> ?? ?? ?? ?? <ctx0> <ctx1> <ctx2> <ctx3>"
// ---------------------------------------------------------------------------
static std::string BuildWildcardPattern(const RIPInstr& r)
{
    std::ostringstream ss;
    // First 3 bytes (prefix + opcode + ModRM) -- literal
    ss << std::hex << std::uppercase << std::setfill('0')
       << std::setw(2) << static_cast<int>(r.bytes[0]) << " "
       << std::setw(2) << static_cast<int>(r.bytes[1]) << " "
       << std::setw(2) << static_cast<int>(r.bytes[2]) << " ";
    // Bytes 3-6 (disp32) -- wildcarded
    ss << "?? ?? ?? ?? ";
    // 4-byte context after the instruction -- literal
    ss << std::setw(2) << static_cast<int>(r.context[0]) << " "
       << std::setw(2) << static_cast<int>(r.context[1]) << " "
       << std::setw(2) << static_cast<int>(r.context[2]) << " "
       << std::setw(2) << static_cast<int>(r.context[3]);
    return ss.str();
}

// ---------------------------------------------------------------------------
// IsRIPRelativeMOV -- checks if a 7-byte sequence is one of the covered opcodes.
// Returns true and fills outModRM.
// ---------------------------------------------------------------------------
static bool IsRIPRelativeMOV(const uint8_t* p, uint8_t& outRex, uint8_t& outOp, uint8_t& outModRM)
{
    // REX.W prefixes: 48 (W=1, no ext), 4C (W=1, R=1 -> extends reg field)
    // Opcodes: 8B (MOV reg,r/m), 8D (LEA reg,r/m), 89 (MOV r/m,reg)
    // ModRM must have mod=00, rm=101 (RIP-relative): 0b00???101 = 0x05 mask
    if (p[0] != 0x48 && p[0] != 0x4C && p[0] != 0x49 && p[0] != 0x4D)
        return false;
    if (p[1] != 0x8B && p[1] != 0x8D && p[1] != 0x89)
        return false;
    // ModRM: mod=00 (bits 7:6 = 00), rm=101 (bits 2:0 = 101) -> byte & 0xC7 == 0x05
    if ((p[2] & 0xC7) != 0x05)
        return false;
    outRex   = p[0];
    outOp    = p[1];
    outModRM = p[2];
    return true;
}

// ---------------------------------------------------------------------------
// CollectRIPInstrs
//   Walks .text, collects all RIP-relative MOV/LEA instructions that
//   resolve into the .data or .bss range.
// ---------------------------------------------------------------------------
static std::vector<RIPInstr> CollectRIPInstrs(const std::vector<BYTE>& buf,
                                               uintptr_t                 clientBase,
                                               const CS2Section&         textSec,
                                               uintptr_t                 dataMin,
                                               uintptr_t                 dataMax)
{
    std::vector<RIPInstr> results;
    results.reserve(4096);

    const BYTE* text    = buf.data() + textSec.fileOff;
    size_t      textLen = textSec.size;

    for (size_t i = 0; i + 11 <= textLen; i++) {
        uint8_t rex = 0, op = 0, modrm = 0;
        if (!IsRIPRelativeMOV(text + i, rex, op, modrm))
            continue;

        // Read disp32 (signed)
        int32_t disp32 = 0;
        std::memcpy(&disp32, text + i + 3, 4);

        // instruction end VA = base + fileOffset + i + 7
        uintptr_t instrEndVA = clientBase + textSec.vaBase - clientBase + i + 7;
        // Actually: vaBase is already the VA, fileOff is the file offset.
        // instrVA   = textSec.vaBase + i
        // instrEnd  = instrVA + 7
        uintptr_t instrVA  = textSec.vaBase + static_cast<uintptr_t>(i);
        uintptr_t instrEnd = instrVA + 7;
        uintptr_t targetVA = static_cast<uintptr_t>(
            static_cast<int64_t>(instrEnd) + static_cast<int64_t>(disp32));

        // Only care about instructions that target .data or .bss
        if (targetVA < dataMin || targetVA >= dataMax)
            continue;

        // Skip if not enough context bytes
        if (i + 11 > textLen)
            continue;

        RIPInstr r = {};
        r.bufOff   = textSec.fileOff + i;
        r.instrVA  = instrVA;
        r.targetVA = targetVA;
        std::memcpy(r.bytes,   text + i,     7);
        std::memcpy(r.context, text + i + 7, 4);
        results.push_back(r);
    }

    return results;
}

// ---------------------------------------------------------------------------
// PatternAlreadyExists -- check if label is in existingResults
// ---------------------------------------------------------------------------
static bool PatternAlreadyExists(const std::string&               label,
                                  const std::vector<PatternResult>& existing)
{
    for (const auto& pr : existing) {
        if (pr.label == label && pr.address != 0)
            return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// RegenerateCS2Patterns -- public entry point
// ---------------------------------------------------------------------------
std::vector<RegenResult> RegenerateCS2Patterns(
    HANDLE                            /*hProcess*/,
    const std::vector<BYTE>&          clientBuf,
    uintptr_t                         clientBase,
    const std::vector<PatternResult>& existingResults)
{
    std::vector<RegenResult> results;

    // Parse PE sections
    std::vector<CS2Section> sections;
    if (!ParseCS2Sections(clientBuf, clientBase, sections))
        return results;

    // Identify .text, .data, .bss sections
    CS2Section textSec  = {}, dataSec = {}, bssSec = {};
    bool haveText = false, haveData = false, haveBss = false;

    const uint32_t EXEC_FLAGS  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
    const uint32_t DATA_FLAGS  = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    const uint32_t BSS_FLAGS   = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    for (const auto& s : sections) {
        if (!haveText && (s.chars & EXEC_FLAGS) == EXEC_FLAGS) {
            textSec = s; haveText = true;
        }
        if (!haveData && (s.chars & DATA_FLAGS) == DATA_FLAGS &&
            !(s.chars & IMAGE_SCN_MEM_EXECUTE)) {
            dataSec = s; haveData = true;
        }
        if (!haveBss && (s.chars & BSS_FLAGS) == BSS_FLAGS) {
            bssSec = s; haveBss = true;
        }
    }

    if (!haveText)
        return results;

    // Build .data range for target resolution
    uintptr_t dataMin = 0xFFFFFFFFFFFFFFFFULL;
    uintptr_t dataMax = 0;
    if (haveData) {
        dataMin = std::min(dataMin, dataSec.vaBase);
        dataMax = std::max(dataMax, dataSec.vaBase + dataSec.size);
    }
    if (haveBss) {
        dataMin = std::min(dataMin, bssSec.vaBase);
        dataMax = std::max(dataMax, bssSec.vaBase + bssSec.size);
    }
    if (dataMin >= dataMax) {
        // Fallback: any non-text VA
        dataMin = clientBase;
        dataMax = clientBase + clientBuf.size();
    }

    // Validate text section buffer bounds
    if (textSec.fileOff + textSec.size > clientBuf.size())
        return results;

    // Collect all RIP-relative MOV/LEA targeting .data/.bss
    std::vector<RIPInstr> rips = CollectRIPInstrs(clientBuf, clientBase,
                                                   textSec, dataMin, dataMax);

    // For each known label that FAILED to match, generate candidates
    for (const auto& kl : s_knownLabels) {
        std::string labelStr(kl.label);

        if (PatternAlreadyExists(labelStr, existingResults))
            continue;  // already matched, skip

        // Group candidates by target VA (same global = same RVA across minor updates)
        // Since we don't know which RIP instr was the original, emit all of them
        // (capped at 10 per label to avoid noise).
        std::vector<RegenResult> candidates;

        for (const auto& r : rips) {
            if (candidates.size() >= 10)
                break;

            std::string pat = BuildWildcardPattern(r);

            RegenResult rr = {};
            rr.label      = "AutoRegen_" + labelStr + "_candidate_"
                             + std::to_string(candidates.size());
            rr.newPattern = pat;
            rr.oldPattern = kl.oldPattern;
            rr.foundAt    = r.instrVA;
            rr.success    = true;
            rr.notes      = "target=0x" + [&]() {
                std::ostringstream s;
                s << std::hex << std::uppercase << r.targetVA;
                return s.str();
            }() + "  raw=" + BytesToHex(r.bytes, 7);

            candidates.push_back(rr);
        }

        if (candidates.empty()) {
            // No candidates found -- report failure
            RegenResult rr = {};
            rr.label      = "AutoRegen_" + labelStr;
            rr.oldPattern = kl.oldPattern;
            rr.success    = false;
            rr.notes      = "No RIP-relative MOV targeting .data/.bss found for this label";
            results.push_back(rr);
        } else {
            for (auto& c : candidates)
                results.push_back(c);
        }
    }

// Auto-regen patterns stored in results

    return results;
}

// ---------------------------------------------------------------------------
// FormatRegenResults
// ---------------------------------------------------------------------------
std::string FormatRegenResults(const std::vector<RegenResult>& results)
{
    std::ostringstream ss;
    ss << "=== CS2 Pattern Regen Results ===\n";
    ss << "Total candidates: " << results.size() << "\n\n";

    for (const auto& r : results) {
        if (r.success) {
            ss << "[OK]  " << r.label << "\n"
               << "      pattern : " << r.newPattern << "\n"
               << "      old     : " << r.oldPattern << "\n"
               << "      foundAt : 0x" << std::hex << std::uppercase << r.foundAt << "\n"
               << "      notes   : " << r.notes << "\n\n";
        } else {
            ss << "[FAIL] " << r.label << " -- " << r.notes << "\n\n";
        }
    }

    ss << "Full output -> C:\\Users\\HZLoxi\\Desktop\\dumper\\regen_patterns.txt\n";
    return ss.str();
}

