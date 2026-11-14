// chain_verifier.h -- Pointer Chain Verifier + Confidence Scorer
// *each hop examined like a detective turning evidence under a lamp*
#pragma once
#include "dumper.h"
#include "ptr_chain.h"
#include <cstdint>
#include <string>
#include <vector>

enum ConfidenceLevel {
    CONF_DEAD   = 0,  // address invalid or zero
    CONF_LOW    = 1,  // pattern matched but unverified
    CONF_MEDIUM = 2,  // RIP resolved, pointer reads non-zero
    CONF_HIGH   = 3,  // full chain valid + value is in sane range
};

struct VerifiedOffset {
    std::string    label;
    uintptr_t      address;
    uintptr_t      offset;
    ConfidenceLevel confidence;
    std::string    confStr;    // "HIGH" / "MEDIUM" / "LOW" / "DEAD"
    std::string    notes;
    uintptr_t      liveValue;  // what's at the address right now
    std::string    hexDump;    // 16-byte hex dump at address
};

// Verify all pattern results against live process memory
// Reads each resolved address, checks if it's valid, readable, non-null
std::vector<VerifiedOffset> VerifyOffsets(
    HANDLE hProcess,
    const std::vector<PatternResult>& patterns,
    const std::vector<PointerChainResult>& chainResults);

// Generate hex dump of N bytes at address
std::string HexDump16(HANDLE hProcess, uintptr_t address);

const char* ConfStr(ConfidenceLevel c);
