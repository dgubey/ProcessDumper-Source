// ptr_chain.cpp -- Multi-Level Pointer Chain Walker
// *each RPM call peels back one layer of indirection*
#include "ptr_chain.h"
#include <cstdint>
#include <algorithm>

static bool SafeRead(HANDLE hProcess, uintptr_t addr, void* buf, size_t sz) {
    SIZE_T got = 0;
    return ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(addr), buf, sz, &got) && got == sz;
}

static uintptr_t ReadPtr64(HANDLE hProcess, uintptr_t addr) {
    uintptr_t val = 0;
    SafeRead(hProcess, addr, &val, sizeof(val));
    return val;
}

static bool IsValidPtr(uintptr_t ptr) {
    return ptr != 0 && ptr < 0x7FFFFFFFFFFFULL && (ptr & 0x3) == 0;
}

PointerChainResult WalkChain(HANDLE hProcess, const PointerChain& chain) {
    PointerChainResult result = {};
    result.valid = false;
    result.label = chain.label;

    uintptr_t current = chain.baseAddr;
    if (!IsValidPtr(current)) return result;

    size_t totalHops = chain.offsets.size();
    for (size_t i = 0; i < totalHops; i++) {
        result.resolvedAddrs.push_back(current);
        uintptr_t deref = ReadPtr64(hProcess, current);
        result.resolvedValues.push_back(deref);
        if (!IsValidPtr(deref)) return result;
        if (i + 1 < totalHops)
            current = deref + chain.offsets[i + 1];
        else
            current = deref + chain.offsets[i];
    }

    if (chain.offsets.empty()) {
        result.finalAddress = current;
    } else {
        result.finalAddress = current;
        uintptr_t val = 0;
        SafeRead(hProcess, result.finalAddress, &val, sizeof(val));
        result.finalValue = val;
    }
    result.valid = IsValidPtr(result.finalAddress);
    return result;
}

static PointerChain MakeChain(const char* lbl, uintptr_t base,
                               std::initializer_list<uint32_t> offs,
                               const char* notes) {
    PointerChain pc;
    pc.label   = lbl;
    pc.baseAddr= base;
    pc.offsets = std::vector<uint32_t>(offs);
    pc.notes   = notes;
    return pc;
}

std::vector<PointerChain> BuildCS2Chains(uintptr_t entityListBase,
                                          uintptr_t localPlayerBase) {
    std::vector<PointerChain> chains;
    if (entityListBase) {
        chains.push_back(MakeChain("Entity[0]_base",   entityListBase, {0x0, 0x10},        "entityList->entity[0]"));
        chains.push_back(MakeChain("Entity[0]_Health", entityListBase, {0x0, 0x10, 0x344}, "entity[0].m_iHealth"));
        chains.push_back(MakeChain("Entity[1]_base",   entityListBase, {0x0, 0x88},        "entityList->entity[1]"));
    }
    if (localPlayerBase) {
        chains.push_back(MakeChain("LocalPlayer_Health", localPlayerBase, {0x0, 0x344},        "localPlayer->m_iHealth"));
        chains.push_back(MakeChain("LocalPlayer_Team",   localPlayerBase, {0x0, 0x3C4},        "localPlayer->m_iTeamNum"));
        chains.push_back(MakeChain("LocalPlayer_Origin", localPlayerBase, {0x0, 0x328, 0xC8},  "localPlayer->GameSceneNode->pos"));
        chains.push_back(MakeChain("LocalPlayer_Ammo",   localPlayerBase, {0x0, 0xDF4, 0xC70}, "localPlayer->activeWeapon->m_iClip1"));
    }
    return chains;
}

std::vector<PointerChain> BuildUEChains(uintptr_t gWorldAddr,
                                         uintptr_t gObjectsAddr) {
    std::vector<PointerChain> chains;
    (void)gObjectsAddr;
    if (gWorldAddr) {
        chains.push_back(MakeChain("UWorld_PersistentLevel", gWorldAddr, {0x0, 0x30},       "GWorld->PersistentLevel"));
        chains.push_back(MakeChain("UWorld_GameState",       gWorldAddr, {0x0, 0x140},      "GWorld->GameState"));
        chains.push_back(MakeChain("UWorld_GameMode",        gWorldAddr, {0x0, 0x148},      "GWorld->AuthorityGameMode"));
        chains.push_back(MakeChain("UWorld_GameInstance",    gWorldAddr, {0x0, 0x188},      "GWorld->OwningGameInstance"));
        chains.push_back(MakeChain("UWorld_Actors",          gWorldAddr, {0x0, 0x30, 0xA0}, "GWorld->PersistentLevel->Actors"));
    }
    return chains;
}
