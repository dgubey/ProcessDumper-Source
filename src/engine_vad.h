// engine_vad.h
// VAD (Virtual Address Descriptor) module scanner
// Bypasses PEB module-list manipulation by using VirtualQueryEx
// to walk the full virtual address space and find hidden PE images.
//
// Context: Windows x64, targets a remote process via HANDLE.
// Privilege required: PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
//
// Anti-cheat evasion note:
//   Hooks on LdrLoadDll, LdrpHashTable poisoning, PEB.Ldr unlinking --
//   all invisible here. VirtualQueryEx speaks directly to the kernel
//   VAD tree (nt!MiQueryVirtualMemory), which the user-mode loader
//   cannot tamper with.
//
#pragma once
#include "dumper.h"
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// VADRegion -- one MEMORY_BASIC_INFORMATION record, enriched
// ---------------------------------------------------------------------------
struct VADRegion {
    uintptr_t    base;          // BaseAddress (page-aligned)
    size_t       size;          // RegionSize in bytes
    DWORD        protect;       // current page protection (PAGE_*)
    DWORD        type;          // MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE
    std::wstring mappedFile;    // path from GetMappedFileNameW (empty if not MEM_IMAGE)
    bool         hasPEHeader;   // true if we confirmed IMAGE_DOS_SIGNATURE + IMAGE_NT_SIGNATURE
    bool         isModule;      // also present in the supplied knownModules list
};

// ---------------------------------------------------------------------------
// VADDumpResult -- aggregated output of a full VAD walk
// ---------------------------------------------------------------------------
struct VADDumpResult {
    std::vector<VADRegion>    regions;        // every committed region found
    std::vector<ModuleEntry>  hiddenModules;  // PE images NOT in PEB module list
    std::string               formattedText;  // human-readable dump ready to print / save
};

// ---------------------------------------------------------------------------
// DumpVAD
//   hProcess      -- open handle to target process
//   knownModules  -- list already obtained via Toolhelp / PEB walk
//   result        -- populated on success
//   progress      -- optional callback(current, total, label)
//
// Returns true if the walk completed without fatal errors.
// Partial results are still written to `result` on false.
// ---------------------------------------------------------------------------
bool DumpVAD(HANDLE                          hProcess,
             const std::vector<ModuleEntry>& knownModules,
             VADDumpResult&                  result,
             ProgressCallback                progress = nullptr);
