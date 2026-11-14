// vtable_scan.h
// Vtable + RTTI scanner for MSVC x64 binaries.
//
// Strategy:
//   1. Load module bytes from remote process.
//   2. Locate .rdata (non-exec, init data) and .text (exec, code) sections.
//   3. Scan .rdata for consecutive 8-byte aligned values all pointing into .text
//      -- these are virtual function pointer tables.
//   4. Check the 8 bytes immediately BEFORE each candidate vtable pointer:
//      if they point to an RTTICompleteObjectLocator (COL), extract class name.
//   5. MSVC x64 RTTI layout (COL):
//        [vtable - 0x08]  -> ptr to COL
//        COL + 0x00       -> uint32 signature (must be 1 for x64)
//        COL + 0x0C       -> int32  typeDescriptor RVA (relative to image base)
//        typeDescriptor + 0x00 -> ptr to type_info vtable
//        typeDescriptor + 0x10 -> mangled name ".?AVFoo@@" (null-terminated)
//        Demangle: strip leading ".?AV" and trailing "@@"
//
// Context: Windows x64, MSVC ABI.
// Privilege required: PROCESS_VM_READ on hProcess.
//
#pragma once
#include "dumper.h"
#include <cstdint>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// VtableEntry -- one discovered virtual dispatch table
// ---------------------------------------------------------------------------
struct VtableEntry {
    uintptr_t              vtableAddr;    // VA of the vtable in .rdata
    uintptr_t              classInfoAddr; // VA of RTTICompleteObjectLocator (0 if absent)
    std::string            className;     // demangled class name ("" if RTTI absent)
    uint32_t               slotCount;     // number of consecutive valid function slots
    std::vector<uintptr_t> slots;         // the raw function pointer values
};

// ---------------------------------------------------------------------------
// VtableScanResult -- full output of a module scan
// ---------------------------------------------------------------------------
struct VtableScanResult {
    std::vector<VtableEntry> vtables;
    std::string              formattedText;
};

// ---------------------------------------------------------------------------
// ScanVtables
//   hProcess         -- open handle to target process
//   modules          -- full module list (to locate targetModuleName)
//   targetModuleName -- e.g. "client.dll"; matched case-insensitively
//   result           -- populated on success
//   progress         -- optional callback
//
// Returns true on success.
// ---------------------------------------------------------------------------
bool ScanVtables(HANDLE                          hProcess,
                 const std::vector<ModuleEntry>& modules,
                 const std::string&              targetModuleName,
                 VtableScanResult&               result,
                 ProgressCallback                progress = nullptr);
