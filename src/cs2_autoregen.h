// cs2_autoregen.h
#pragma once
#include "dumper.h"
#include <cstdint>
#include <string>
#include <vector>

struct RegenResult {
    std::string label;
    std::string newPattern;
    std::string oldPattern;
    uintptr_t   foundAt;
    bool        success;
    std::string notes;
};

std::vector<RegenResult> RegenerateCS2Patterns(
    HANDLE hProcess,
    const std::vector<BYTE>& clientBuf,
    uintptr_t clientBase,
    const std::vector<PatternResult>& existingResults);

std::string FormatRegenResults(const std::vector<RegenResult>& results);
