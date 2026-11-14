// engine_vad.cpp -- VAD Region Scanner (FULL UNLIMITED DUMP)
#include "engine_vad.h"
#include <sstream>
#include <iomanip>
#include <set>
#include <psapi.h>
#include <fstream>

bool DumpVAD(HANDLE hProcess,
             const std::vector<ModuleEntry>& knownModules,
             VADDumpResult& result,
             ProgressCallback progress)
{
    result = {};
    auto prog = [&](const std::string& m, int p) {
        if (progress) {
            std::wstring w; for (char c : m) w += (wchar_t)c;
            progress(w, p);
        }
    };
    prog("Mapping ALL VAD regions (unlimited)...", 5);

    std::set<uintptr_t> knownBases;
    for (auto& m : knownModules) knownBases.insert(m.base);

    uintptr_t addr = 0x10000;
    const uintptr_t MAX_ADDR = 0x7FFFFFFFFFFF;
    MEMORY_BASIC_INFORMATION mbi = {};
    int regIdx = 0;

    while (addr < MAX_ADDR) {
        if (!VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) break;
        if (mbi.RegionSize == 0) break;

        if (mbi.State == MEM_COMMIT) {
            VADRegion vr;
            vr.base        = (uintptr_t)mbi.BaseAddress;
            vr.size        = mbi.RegionSize;
            vr.protect     = mbi.Protect;
            vr.type        = mbi.Type;
            vr.hasPEHeader = false;
            vr.isModule    = knownBases.count(vr.base) > 0;

            if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) {
                WCHAR fn[MAX_PATH] = {};
                if (GetMappedFileNameW(hProcess, (LPVOID)vr.base, fn, MAX_PATH)) {
                    vr.mappedFile = fn;
                }
            }

            if (mbi.Type == MEM_IMAGE && mbi.RegionSize >= 0x1000) {
                WORD magic = 0; SIZE_T g = 0;
                ReadProcessMemory(hProcess, (LPCVOID)vr.base, &magic, 2, &g);
                if (magic == IMAGE_DOS_SIGNATURE) {
                    uint32_t ntOff = 0;
                    ReadProcessMemory(hProcess, (LPCVOID)(vr.base + 0x3C), &ntOff, 4, &g);
                    if (ntOff < 0x1000) {
                        uint32_t ntsig = 0;
                        ReadProcessMemory(hProcess, (LPCVOID)(vr.base + ntOff), &ntsig, 4, &g);
                        vr.hasPEHeader = (ntsig == IMAGE_NT_SIGNATURE);
                    }
                }
            }

            if (vr.hasPEHeader && !vr.isModule) {
                ModuleEntry hidden;
                hidden.base = vr.base;
                hidden.size = vr.size;
                hidden.name = vr.mappedFile.empty() ? L"(anonymous)" :
                    vr.mappedFile.substr(vr.mappedFile.find_last_of(L"\\/") + 1);
                hidden.path = vr.mappedFile;
                result.hiddenModules.push_back(hidden);
            }

            result.regions.push_back(std::move(vr));
            regIdx++;
        }

        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        int pct = 5 + (int)(((double)(addr) / (double)MAX_ADDR) * 80.0);
        if (regIdx % 500 == 0) prog("Mapped " + std::to_string(regIdx) + " VAD regions...", pct);
    }

    prog("Formatting ALL VAD results...", 90);
    std::ostringstream out;
    out << "================================================================\r\n";
    out << "  [VAD VIRTUAL ADDRESS DESCRIPTOR MAP - FULL UNLIMITED DUMP]\r\n";
    out << "================================================================\r\n";
    out << "  Committed regions : " << result.regions.size() << "\r\n";
    out << "  Hidden PE modules : " << result.hiddenModules.size() << "\r\n\r\n";

    if (!result.hiddenModules.empty()) {
        out << "  *** HIDDEN/UNLISTED MODULES ***\r\n";
        for (auto& m : result.hiddenModules) {
            std::string n(m.name.begin(), m.name.end());
            out << "  [HIDDEN] 0x" << std::hex << std::uppercase << m.base
                << "  size=0x" << m.size << "  " << n << "\r\n";
        }
        out << "\r\n";
    }

    out << "  Base               Size           Type      Protect   Mapped File\r\n";
    out << "  ----------------------------------------------------------------\r\n";

    // NO LIMIT CAP HERE: DUMP ALL REGIONS
    for (size_t i = 0; i < result.regions.size(); i++) {
        auto& r = result.regions[i];
        std::string typeStr = (r.type == MEM_IMAGE ? "IMAGE" : (r.type == MEM_MAPPED ? "MAPPED" : "PRIVATE"));
        std::string mf(r.mappedFile.begin(), r.mappedFile.end());
        if (mf.size() > 40) mf = "..." + mf.substr(mf.size() - 37);
        out << "  0x" << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << r.base
            << "  0x" << std::setw(10) << r.size << "  "
            << std::left << std::setw(8) << typeStr
            << "  0x" << std::setw(8) << r.protect << "  " << mf << "\r\n";
    }

    result.formattedText = out.str();

// VAD map text stored in result.formattedText

    prog("VAD full dump done.", 100);
    return true;
}

