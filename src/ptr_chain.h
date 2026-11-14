#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
// ptr_chain.h -- Multi-Level Pointer Chain Walker
// *follows the rabbit hole of pointers, each dereference a step deeper into memory*
#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <functional>

struct PointerChainResult {
    bool        valid;
    uintptr_t   finalAddress;
    uintptr_t   finalValue;
    std::string label;
    std::vector<uintptr_t> resolvedAddrs; // each hop address
    std::vector<uintptr_t> resolvedValues; // each hop dereferenced value
};

struct PointerChain {
    std::string           label;
    uintptr_t             baseAddr;   // starting absolute address (already resolved module base + offset)
    std::vector<uint32_t> offsets;    // chain of offsets to add at each level
    std::string           notes;
};

// Walk a pointer chain in target process
// Returns true if all hops succeed and final address is valid readable memory
PointerChainResult WalkChain(HANDLE hProcess, const PointerChain& chain);

// Build common pointer chains for known game engines (given pattern scan results)
// CS2 examples: EntityList + entity[i] offset + m_iHealth
std::vector<PointerChain> BuildCS2Chains(uintptr_t entityListBase,
                                          uintptr_t localPlayerBase);

std::vector<PointerChain> BuildUEChains(uintptr_t gWorldAddr,
                                         uintptr_t gObjectsAddr);

