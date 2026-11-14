// chain_verifier.cpp -- Confidence Scoring Implementation
// *separates live signals from dead noise with surgical precision*
#include "chain_verifier.h"
#include <sstream>
#include <iomanip>
#include <cstring>

const char* ConfStr(ConfidenceLevel c) {
    switch(c) {
        case CONF_HIGH:   return "HIGH  ";
        case CONF_MEDIUM: return "MEDIUM";
        case CONF_LOW:    return "LOW   ";
        default:          return "DEAD  ";
    }
}

static bool IsValidUserAddress(uintptr_t addr) {
    return addr >= 0x10000ULL && addr < 0x7FFFFFFFF000ULL && (addr & 3) == 0;
}

static bool IsReadable(HANDLE hProcess, uintptr_t addr, void* buf, size_t sz) {
    SIZE_T got = 0;
    return ReadProcessMemory(hProcess, (LPCVOID)addr, buf, sz, &got) && got > 0;
}

std::string HexDump16(HANDLE hProcess, uintptr_t address) {
    if (!IsValidUserAddress(address)) return "(invalid address)";
    BYTE buf[16] = {};
    SIZE_T got = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)address, buf, 16, &got) || got == 0)
        return "(unreadable)";

    std::ostringstream hex, asc;
    for (size_t i = 0; i < 16; i++) {
        hex << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << (int)buf[i] << " ";
        asc << (char)((buf[i] >= 0x20 && buf[i] < 0x7F) ? buf[i] : '.');
    }
    return hex.str() + " | " + asc.str();
}

std::vector<VerifiedOffset> VerifyOffsets(
    HANDLE hProcess,
    const std::vector<PatternResult>& patterns,
    const std::vector<PointerChainResult>& chainResults)
{
    std::vector<VerifiedOffset> results;

    for (auto& pr : patterns) {
        VerifiedOffset v;
        v.label   = pr.label;
        v.address = pr.address;
        v.offset  = pr.offset;
        v.notes   = pr.notes;
        v.liveValue = 0;
        v.confidence = CONF_DEAD;

        if (!IsValidUserAddress(pr.address)) {
            v.confidence = CONF_DEAD;
            v.confStr    = ConfStr(CONF_DEAD);
            results.push_back(v);
            continue;
        }

        // Try to read the address
        uintptr_t ptrValue = 0;
        BYTE raw[16] = {};
        bool readable = IsReadable(hProcess, pr.address, raw, 16);

        if (!readable) {
            v.confidence = CONF_LOW;  // pattern matched but memory unreadable (may be paged)
            v.confStr = ConfStr(CONF_LOW);
            v.hexDump = "(paged out)";
            results.push_back(v);
            continue;
        }

        memcpy(&ptrValue, raw, sizeof(ptrValue));
        v.liveValue = ptrValue;
        v.hexDump   = HexDump16(hProcess, pr.address);

        // If it's a pointer-type offset: check if the value reads as a valid ptr
        bool isStringXref = pr.label.find("xref_") == 0 || pr.label.find("str_") == 0;
        bool isFloatOffset = pr.label.find("_float") != std::string::npos
                          || pr.label.find("Time") != std::string::npos
                          || pr.label.find("FOV") != std::string::npos;

        if (isStringXref) {
            // String xrefs: address points to ASCII string — check printable chars
            bool printable = true;
            for (int i = 0; i < 8 && i < (int)sizeof(raw); i++) {
                if (raw[i] == 0) break;
                if (raw[i] < 0x20 || raw[i] > 0x7E) { printable = false; break; }
            }
            v.confidence = printable ? CONF_MEDIUM : CONF_LOW;
        } else if (isFloatOffset) {
            // Float sanity: value should be between -100000 and 100000
            float fval = 0.0f;
            memcpy(&fval, raw, 4);
            bool sane = (fval > -100000.0f && fval < 100000.0f && fval == fval); // NaN check
            v.confidence = sane ? CONF_MEDIUM : CONF_LOW;
        } else {
            // Pointer type: value should be a valid user-space pointer
            if (IsValidUserAddress(ptrValue)) {
                // Try one more hop: can we read FROM the pointed-to address?
                BYTE deref[8] = {};
                if (IsReadable(hProcess, ptrValue, deref, 8)) {
                    v.confidence = CONF_HIGH;
                } else {
                    v.confidence = CONF_MEDIUM;
                }
            } else if (ptrValue != 0) {
                // Non-zero, non-pointer: maybe a float, int, or struct offset
                v.confidence = CONF_MEDIUM;
            } else {
                // Zero value: might be valid (early in game load) or dead
                v.confidence = CONF_LOW;
            }
        }

        v.confStr = ConfStr(v.confidence);
        results.push_back(v);
    }

    return results;
}
