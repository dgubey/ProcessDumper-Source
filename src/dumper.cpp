// dumper.cpp -- Multi-Engine Dumper v4.0 Master Orchestrator
#include "dumper.h"
#include "pattern_db.h"
#include "engine_il2cpp.h"
#include "engine_ue.h"
#include "engine_mono.h"
#include "engine_vad.h"
#include "vtable_scan.h"
#include "cs2_autoregen.h"
#include "meta_parser.h"
#include "ptr_chain.h"
#include "chain_verifier.h"
#include "export_gen.h"
#include "km_read.h"

#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>

// Forward declaration from engine_cs2_ext.cpp
struct ConVarEntry {
    std::string name;
    std::string defaultValue;
    float       floatValue;
    int         intValue;
    uintptr_t   address;
};
std::vector<ConVarEntry> ScanConVars(HANDLE hProcess,
                                      const std::vector<ModuleEntry>& modules,
                                      const std::vector<BYTE>& clientBuf,
                                      uintptr_t clientBase);
std::string FormatConVars(const std::vector<ConVarEntry>& cvars);

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------
static DWORD g_currentPID = 0;

bool IsBattEyeRunning() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring n = pe.szExeFile;
            for (auto& c : n) c = towlower(c);
            if (n.find(L"beservice") != std::wstring::npos || n.find(L"battleye") != std::wstring::npos || n.find(L"bedaisy") != std::wstring::npos) {
                found = true; break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

bool SafeReadMemory(HANDLE hProcess, uintptr_t address, void* buffer, size_t size) {
    if (KernelReader::Get().IsLoaded() && g_currentPID != 0) {
        if (KernelReader::Get().ReadMemory(g_currentPID, address, buffer, size))
            return true;
    }
    if (hProcess) {
        SIZE_T got = 0;
        return ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address), buffer, size, &got) && got == size;
    }
    return false;
}

BOOL IsProcess64Bit(HANDLE hProcess) {
    BOOL isWow64 = FALSE; IsWow64Process(hProcess, &isWow64);
    SYSTEM_INFO si = {}; GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) return !isWow64;
    return FALSE;
}

static std::string WStrToStr(const std::wstring& w) {
    if (w.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(sz - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], sz, nullptr, nullptr);
    return s;
}

static std::string HexStr(uintptr_t val, int width = 16) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << std::setw(width) << std::setfill('0') << val;
    return ss.str();
}

static std::string CharFlagsStr(DWORD ch) {
    std::string s;
    if (ch & IMAGE_SCN_CNT_CODE)       s += "CODE ";
    if (ch & IMAGE_SCN_MEM_EXECUTE)    s += "EXEC ";
    if (ch & IMAGE_SCN_MEM_READ)       s += "READ ";
    if (ch & IMAGE_SCN_MEM_WRITE)      s += "WRITE ";
    if (!s.empty() && s.back() == ' ') s.pop_back();
    return s;
}

// ---------------------------------------------------------------------------
// Process + Module Enumeration
// ---------------------------------------------------------------------------
std::vector<ProcessEntry> EnumerateProcesses() {
    std::vector<ProcessEntry> res;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return res;
    PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) { CloseHandle(snap); return res; }
    do {
        ProcessEntry e = {};
        e.pid = pe.th32ProcessID; e.name = pe.szExeFile; e.threadCount = pe.cntThreads;
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, e.pid);
        if (h) {
            wchar_t b[MAX_PATH] = {};
            if (GetModuleFileNameExW(h, nullptr, b, MAX_PATH)) e.exePath = b;
            e.is64bit = IsProcess64Bit(h); CloseHandle(h);
        }
        res.push_back(std::move(e));
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    std::sort(res.begin(), res.end(), [](const ProcessEntry& a, const ProcessEntry& b){
        return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0; });
    return res;
}

bool EnableDebugPrivilege() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp = {};
    LUID luid = {};
    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    }
    CloseHandle(hToken);
    return true;
}

static std::vector<ModuleEntry> EnumerateModules(HANDLE hProcess, DWORD pid) {
    std::vector<ModuleEntry> mods;

    // Method 1: EnumProcessModulesEx
    HMODULE hm[2048] = {}; DWORD cb = 0;
    if (EnumProcessModulesEx(hProcess, hm, sizeof(hm), &cb, LIST_MODULES_ALL)) {
        DWORD cnt = cb / sizeof(HMODULE);
        for (DWORD i = 0; i < cnt; i++) {
            ModuleEntry m = {}; m.base = (uintptr_t)hm[i];
            wchar_t nb[MAX_PATH]={}, pb[MAX_PATH]={};
            GetModuleBaseNameW(hProcess, hm[i], nb, MAX_PATH);
            GetModuleFileNameExW(hProcess, hm[i], pb, MAX_PATH);
            m.name = nb; m.path = pb;
            MODULEINFO mi = {};
            if (GetModuleInformation(hProcess, hm[i], &mi, sizeof(mi))) m.size = mi.SizeOfImage;
            mods.push_back(std::move(m));
        }
    }

    // Method 2: Toolhelp32 Snapshot fallback
    if (mods.empty() && pid != 0) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me = {}; me.dwSize = sizeof(me);
            if (Module32FirstW(snap, &me)) {
                do {
                    ModuleEntry m = {};
                    m.base = (uintptr_t)me.modBaseAddr;
                    m.size = me.modBaseSize;
                    m.name = me.szModule;
                    m.path = me.szExePath;
                    mods.push_back(std::move(m));
                } while (Module32NextW(snap, &me));
            }
            CloseHandle(snap);
        }
    }

    // Method 3: VirtualQueryEx fallback for main exe
    if (mods.empty()) {
        wchar_t exePath[MAX_PATH] = {};
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, exePath, &sz)) {
            ModuleEntry m = {};
            m.path = exePath;
            std::wstring p(exePath);
            size_t slash = p.find_last_of(L"\\/");
            m.name = (slash != std::wstring::npos) ? p.substr(slash + 1) : p;

            MEMORY_BASIC_INFORMATION mbi = {};
            uintptr_t addr = 0x10000;
            while (addr < 0x7FFFFFFFFFFF) {
                if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
                    if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE) {
                        WORD magic = 0; SIZE_T got = 0;
                        ReadProcessMemory(hProcess, mbi.BaseAddress, &magic, 2, &got);
                        if (magic == IMAGE_DOS_SIGNATURE) {
                            m.base = (uintptr_t)mbi.BaseAddress;
                            m.size = mbi.RegionSize;
                            mods.push_back(std::move(m));
                            break;
                        }
                    }
                    addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
                } else break;
            }
        }
    }

    return mods;
}

// ---------------------------------------------------------------------------
// Engine + UE Version Detection
// ---------------------------------------------------------------------------
EngineType DetectEngine(const std::vector<ModuleEntry>& mods, const std::wstring& pn) {
    std::wstring pl = pn; for (auto& c : pl) c = towlower(c);

    // Pass 1: Unambiguous IL2CPP, Mono, Source2 indicators
    for (auto& m : mods) {
        std::wstring nl = m.name; for (auto& c : nl) c = towlower(c);
        if (nl == L"gameassembly.dll" || nl == L"il2cpp.dll") return ENGINE_UNITY_IL2CPP;
        if (nl == L"mono.dll" || nl.find(L"mono-2.0") != std::wstring::npos || nl.find(L"mono.2") != std::wstring::npos) return ENGINE_UNITY_MONO;
        if (nl == L"client.dll" && (pl.find(L"cs2") != std::wstring::npos || pl.find(L"dota") != std::wstring::npos || pl.find(L"deadlock") != std::wstring::npos)) return ENGINE_SOURCE2;
        if (nl.find(L"-win64-shipping") != std::wstring::npos) return ENGINE_UNREAL;
    }

    // Pass 2: Secondary / generic indicators
    for (auto& m : mods) {
        std::wstring nl = m.name; for (auto& c : nl) c = towlower(c);
        if (nl == L"unityplayer.dll") return ENGINE_UNITY_MONO;
        if (nl == L"client.dll" || nl == L"engine.dll") return ENGINE_SOURCE1;
    }

    if (pl.find(L"cs2") != std::wstring::npos) return ENGINE_SOURCE2;
    if (pl.find(L"csgo") != std::wstring::npos) return ENGINE_SOURCE1;
    return ENGINE_UNKNOWN;
}

const char* EngineTypeName(EngineType e) {
    switch(e) {
        case ENGINE_SOURCE1:      return "Source Engine 1 (CSGO)";
        case ENGINE_SOURCE2:      return "Source Engine 2 (CS2/Dota2/Deadlock)";
        case ENGINE_UNREAL:       return "Unreal Engine 4/5";
        case ENGINE_UNITY_IL2CPP: return "Unity IL2CPP";
        case ENGINE_UNITY_MONO:   return "Unity Mono/.NET";
        default:                  return "Unknown / Generic";
    }
}

const char* UEVersionName(UEVersion v) {
    switch(v) {
        case UE_425: return "4.25"; case UE_426: return "4.26";
        case UE_427: return "4.27"; case UE_50:  return "5.0";
        case UE_51:  return "5.1";  case UE_52:  return "5.2";
        case UE_53:  return "5.3";  case UE_54:  return "5.4";
        default: return "unknown";
    }
}

UEVersion DetectUEVersion(HANDLE hProcess, const std::vector<ModuleEntry>& mods) {
    for (auto& m : mods) {
        if (m.size > 200*1024*1024 || m.size == 0) continue;
        std::wstring nl = m.name; for (auto& c : nl) c = towlower(c);
        if (nl.find(L".exe") == std::wstring::npos && nl.find(L"game") == std::wstring::npos && nl.find(L"shipping") == std::wstring::npos) continue;

        size_t scanSize = std::min(m.size, (size_t)(32*1024*1024));
        std::vector<BYTE> buf(scanSize, 0);
        SIZE_T got = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)m.base, buf.data(), scanSize, &got)) continue;

        static const struct { const char* str; UEVersion ver; } VERS[] = {
            { "5.4.", UE_54 }, { "5.3.", UE_53 }, { "5.2.", UE_52 }, { "5.1.", UE_51 }, { "5.0.", UE_50 },
            { "4.27", UE_427 }, { "4.26", UE_426 }, { "4.25", UE_425 },
        };
        for (auto& vv : VERS) {
            size_t vLen = strlen(vv.str);
            for (size_t i = 0; i + vLen < buf.size(); i++) {
                if (memcmp(buf.data() + i, vv.str, vLen) == 0) {
                    if (i == 0 || !isdigit(buf[i-1])) return vv.ver;
                }
            }
        }
    }
    return UE_UNKNOWN;
}

// ---------------------------------------------------------------------------
// Pattern Scanner Helpers
// ---------------------------------------------------------------------------
static bool MatchPat(const BYTE* data, const BYTE* pattern, const uint8_t* mask, size_t len) {
    for (size_t i = 0; i < len; i++) if (mask[i] && data[i] != pattern[i]) return false;
    return true;
}

static bool ParsePat(const std::string& s, std::vector<BYTE>& bytes, std::vector<uint8_t>& mask) {
    bytes.clear(); mask.clear();
    size_t i = 0;
    while (i < s.size()) {
        if (s[i] == ' ') { i++; continue; }
        if (s[i] == '?') {
            bytes.push_back(0); mask.push_back(0);
            i++; if (i < s.size() && s[i] == '?') i++;
        } else {
            if (i + 1 >= s.size()) return false;
            char hx[3] = { s[i], s[i+1], 0 };
            bytes.push_back((BYTE)strtoul(hx, nullptr, 16));
            mask.push_back(1); i += 2;
        }
    }
    return !bytes.empty();
}

static bool ReadModBuf(HANDLE hProcess, uintptr_t base, size_t size, std::vector<BYTE>& buf) {
    if (!base || !size || size > 300*1024*1024) return false;
    buf.resize(size, 0);
    size_t off = 0;
    while (off < size) {
        size_t chunk = std::min((size_t)(4*1024*1024), size - off);
        SIZE_T r = 0;
        ReadProcessMemory(hProcess, (LPCVOID)(base + off), buf.data() + off, chunk, &r);
        off += chunk;
    }
    return true;
}

static uintptr_t ResolveRIP(uintptr_t base, size_t off, const std::vector<BYTE>& buf, int dOff, int iLen) {
    size_t dp = off + dOff;
    if (dp + 4 > buf.size()) return 0;
    int32_t disp = 0; memcpy(&disp, buf.data() + dp, 4);
    uintptr_t rip = base + off + iLen;
    return (uintptr_t)((int64_t)rip + disp);
}

static std::vector<size_t> FindPattern(const std::vector<BYTE>& buf, const std::vector<BYTE>& pat, const std::vector<uint8_t>& mask) {
    std::vector<size_t> hits;
    size_t pLen = pat.size();
    if (!pLen || buf.size() < pLen) return hits;
    for (size_t i = 0; i + pLen <= buf.size(); i++)
        if (MatchPat(buf.data()+i, pat.data(), mask.data(), pLen)) hits.push_back(i);
    return hits;
}

static void ScanBank(const PatDef* defs, size_t count, const std::vector<BYTE>& buf, uintptr_t base, const std::string& mod, std::vector<PatternResult>& out) {
    for (size_t pi = 0; pi < count; pi++) {
        const PatDef& pd = defs[pi];
        std::vector<BYTE> pb; std::vector<uint8_t> pm;
        if (!ParsePat(pd.pat, pb, pm)) continue;
        auto hits = FindPattern(buf, pb, pm);
        if (hits.empty()) continue;
        size_t mOff = hits[0];
        PatternResult pr;
        pr.label = pd.label; pr.moduleName = mod;
        pr.notes = pd.notes ? pd.notes : "";
        pr.engineVer = pd.engineVer ? pd.engineVer : "*";
        pr.rawMatchAddr = base + mOff; pr.rawMatchOffset = mOff;
        if (pd.dispOff >= 0) {
            uintptr_t res = ResolveRIP(base, mOff, buf, pd.dispOff, pd.instrLen);
            pr.address = res; pr.offset = (res > base) ? (res - base) : res;
        } else {
            pr.address = base + mOff; pr.offset = mOff;
        }
        out.push_back(pr);
    }
}

static const struct { const char* label; const char* str; } S_REFS[] = {
    { "xref_EntityList", "EntityList" }, { "xref_LocalPlayer", "LocalPlayer" },
    { "xref_PlayerCtrl", "PlayerController" }, { "xref_GameInstance", "GameInstance" },
    { "xref_HealthComp", "HealthComponent" }, { "xref_CameraManager", "CameraManager" },
    { "xref_ViewMatrix", "ViewMatrix" }, { "xref_GWorld", "GWorld" },
    { "xref_WeaponData", "WeaponData" }, { "xref_il2cpp", "il2cpp" },
    { "xref_GameAssembly", "GameAssembly" }, { "xref_Health", "Health" },
};

static void ScanStringXrefs(const std::vector<BYTE>& buf, uintptr_t base, const std::string& mod, std::vector<PatternResult>& out) {
    for (auto& sr : S_REFS) {
        size_t sLen = strlen(sr.str);
        for (size_t i = 0; i + sLen <= buf.size(); i++) {
            if (memcmp(buf.data()+i, sr.str, sLen) == 0 &&
                (i+sLen >= buf.size() || !isalnum(buf[i+sLen])) &&
                (i == 0 || !isalnum(buf[i-1]))) {
                PatternResult pr;
                pr.label = sr.label; pr.moduleName = mod;
                pr.address = base + i; pr.offset = i;
                pr.rawMatchAddr = base + i; pr.rawMatchOffset = i;
                pr.notes = "String reference";
                out.push_back(pr); break;
            }
        }
    }
}

static std::vector<ExportEntry> DumpExports(HANDLE hProcess, uintptr_t base, size_t imgSz) {
    std::vector<ExportEntry> exps;
    if (!base || !imgSz || imgSz > 500*1024*1024) return exps;
    std::vector<BYTE> img(imgSz, 0); SIZE_T got = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)base, img.data(), imgSz, &got)) return exps;
    auto* dos = (IMAGE_DOS_HEADER*)img.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return exps;
    auto* nt32 = (IMAGE_NT_HEADERS32*)(img.data() + dos->e_lfanew);
    if (nt32->Signature != IMAGE_NT_SIGNATURE) return exps;
    DWORD expRVA=0, expSz=0;
    if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto* h = (IMAGE_NT_HEADERS64*)(img.data()+dos->e_lfanew);
        expRVA = h->OptionalHeader.DataDirectory[0].VirtualAddress;
        expSz  = h->OptionalHeader.DataDirectory[0].Size;
    } else { expRVA = nt32->OptionalHeader.DataDirectory[0].VirtualAddress; expSz = nt32->OptionalHeader.DataDirectory[0].Size; }
    if (!expRVA || expRVA >= imgSz) return exps;
    auto* ed = (IMAGE_EXPORT_DIRECTORY*)(img.data()+expRVA);
    auto* funcs = (DWORD*)(img.data()+ed->AddressOfFunctions);
    auto* names = (DWORD*)(img.data()+ed->AddressOfNames);
    auto* ords = (WORD*)(img.data()+ed->AddressOfNameOrdinals);
    std::vector<std::string> nm(ed->NumberOfFunctions);
    for (DWORD i=0;i<ed->NumberOfNames;i++) if (names[i]<imgSz) { WORD o=ords[i]; if(o<ed->NumberOfFunctions) nm[o]=(char*)(img.data()+names[i]); }
    for (DWORD i=0;i<ed->NumberOfFunctions;i++) {
        if (!funcs[i]||(funcs[i]>=expRVA&&funcs[i]<expRVA+expSz)) continue;
        ExportEntry e = {}; e.rva=funcs[i]; e.va=base+funcs[i];
        e.ordinal=(WORD)(ed->Base+i); e.name=nm[i].empty()?("#"+std::to_string(e.ordinal)):nm[i];
        exps.push_back(std::move(e));
    }
    return exps;
}

static std::vector<SectionEntry> DumpSections(HANDLE hProcess, uintptr_t base) {
    std::vector<SectionEntry> secs;
    IMAGE_DOS_HEADER dos = {};
    if (!SafeReadMemory(hProcess, base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) return secs;
    WORD magic = 0; uintptr_t ntBase = base + dos.e_lfanew;
    if (!SafeReadMemory(hProcess, ntBase + offsetof(IMAGE_NT_HEADERS32, OptionalHeader.Magic), &magic, sizeof(magic))) return secs;
    DWORD numSec=0; uintptr_t secBase=0;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64 nt={}; if(!SafeReadMemory(hProcess,ntBase,&nt,sizeof(nt))) return secs;
        numSec=nt.FileHeader.NumberOfSections; secBase=ntBase+sizeof(nt);
    } else { IMAGE_NT_HEADERS32 nt={}; if(!SafeReadMemory(hProcess,ntBase,&nt,sizeof(nt))) return secs;
        numSec=nt.FileHeader.NumberOfSections; secBase=ntBase+sizeof(nt); }
    for (DWORD i=0;i<numSec&&i<64;i++) {
        IMAGE_SECTION_HEADER sh={}; if(!SafeReadMemory(hProcess,secBase+i*sizeof(sh),&sh,sizeof(sh))) break;
        SectionEntry se={}; memcpy(se.name,sh.Name,8); se.name[8]=0;
        se.rva=sh.VirtualAddress; se.virtualSize=sh.Misc.VirtualSize;
        se.rawSize=sh.SizeOfRawData; se.characteristics=sh.Characteristics;
        secs.push_back(se);
    }
    return secs;
}

static std::vector<ExportEntry> FilterIL2CPPExports(const std::vector<ExportEntry>& exps) {
    static const char* KEY[] = {
        "il2cpp_domain_get","il2cpp_domain_get_assemblies","il2cpp_class_from_name","il2cpp_field_get_offset", nullptr
    };
    std::vector<ExportEntry> res;
    for (auto& e : exps) for (int i=0;KEY[i];i++) if (e.name==KEY[i]) { res.push_back(e); break; }
    return res;
}

// ---------------------------------------------------------------------------
// DumpProcess -- Master Orchestrator v4.0
// ---------------------------------------------------------------------------
bool DumpProcess(DWORD pid, DumpResult& result, ProgressCallback progress) {
    result = {};
    g_currentPID = pid;
    auto prog = [&](const std::wstring& msg, int pct) { if (progress) progress(msg, pct); };

    bool isBE = IsBattEyeRunning();
    if (isBE) {
        prog(L"⚡ BattEye Anti-Cheat detected! Activating Ring-0 Kernel Driver Bypass...", 1);
    }

    prog(L"Opening target process with SeDebugPrivilege...", 2);
    EnableDebugPrivilege();

    // Auto-load Kernel Driver for BattEye bypass if ProcDumperKM.sys exists
    if (!KernelReader::Get().IsLoaded()) {
        wchar_t exeDir[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exeDir, MAX_PATH);
        for (int i = (int)wcslen(exeDir) - 1; i >= 0; i--) {
            if (exeDir[i] == L'\\' || exeDir[i] == L'/') { exeDir[i] = 0; break; }
        }
        std::wstring driverPath = std::wstring(exeDir) + L"\\ProcDumperKM.sys";
        if (GetFileAttributesW(driverPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            prog(L"Loading ProcDumperKM Ring-0 Kernel Driver for BattEye Bypass...", 3);
            if (KernelReader::Get().Load(driverPath)) {
                result.usedKernelDriver = true;
                prog(L"✓ Ring-0 Kernel Driver ACTIVE -- BattEye ObRegisterCallbacks Bypassed!", 4);
            }
        }
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (!hProcess && !KernelReader::Get().IsLoaded()) {
        return false;
    }

    { HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
      PROCESSENTRY32W pe={}; pe.dwSize=sizeof(pe);
      if (snap!=INVALID_HANDLE_VALUE&&Process32FirstW(snap,&pe)) {
        do { if (pe.th32ProcessID==pid) { result.processName=pe.szExeFile; break; } }
        while (Process32NextW(snap,&pe)); }
      if (snap!=INVALID_HANDLE_VALUE) CloseHandle(snap); }
    result.pid = pid;

    prog(L"Enumerating modules & VAD regions...", 5);
    result.modules = EnumerateModules(hProcess, pid);
    if (result.modules.empty()) { CloseHandle(hProcess); return false; }

    // v4: VAD Region Dump (Bypasses anti-cheat module hiding)
    VADDumpResult vadRes;
    if (DumpVAD(hProcess, result.modules, vadRes, [&](const std::wstring& m, int p){ prog(m, 5 + p/10); })) {
        result.vadDumpText = vadRes.formattedText;
        if (!vadRes.hiddenModules.empty()) result.hasHiddenModules = true;
    }

    result.engine    = DetectEngine(result.modules, result.processName);
    result.ueVersion = (result.engine == ENGINE_UNREAL) ? DetectUEVersion(hProcess, result.modules) : UE_UNKNOWN;

    {
        std::string en = std::string(EngineTypeName(result.engine));
        if (result.engine == ENGINE_UNREAL && result.ueVersion != UE_UNKNOWN)
            en += " " + std::string(UEVersionName(result.ueVersion));
        prog(std::wstring(L"Engine Detected: ") + std::wstring(en.begin(),en.end()), 15);
    }

    prog(L"Parsing PE headers & sections...", 18);
    result.sections = DumpSections(hProcess, result.modules[0].base);

    prog(L"Dumping export tables...", 22);
    for (auto& m : result.modules) {
        std::wstring nl=m.name; for(auto&c:nl) c=towlower(c);
        bool dump = false;
        switch (result.engine) {
            case ENGINE_UNITY_IL2CPP: dump=(nl==L"gameassembly.dll"||nl==L"il2cpp.dll"); break;
            case ENGINE_SOURCE1: case ENGINE_SOURCE2: dump=(nl==L"client.dll"||nl.find(L"engine")!=std::wstring::npos); break;
            default: dump=(&m==&result.modules[0]); break;
        }
        if (!dump) continue;
        auto exps = DumpExports(hProcess, m.base, m.size);
        for (auto& e : exps) { e.moduleName=WStrToStr(m.name); result.exports.push_back(e); }
    }
    if (result.engine==ENGINE_UNITY_IL2CPP) result.il2cppKeyExports = FilterIL2CPPExports(result.exports);

    // Scan Patterns
    prog(L"Executing multi-engine pattern banks...", 30);
    std::vector<BYTE> mainModBuf;
    ReadModBuf(hProcess, result.modules[0].base, result.modules[0].size, mainModBuf);

    // Target ALL modules for CS2/Source2 (especially client.dll and engine2.dll)
    for (size_t mi = 0; mi < result.modules.size(); mi++) {
        auto& m = result.modules[mi];
        std::wstring nl = m.name; for (auto& c : nl) c = towlower(c);
        std::string sn = WStrToStr(m.name);

        // Scan client.dll, engine2.dll, GameAssembly.dll, or main exe
        bool isTarget = (nl == L"client.dll" || nl == L"engine2.dll" || nl == L"gameassembly.dll" || nl == L"il2cpp.dll" || &m == &result.modules[0]);
        if (!isTarget && result.engine != ENGINE_SOURCE2) continue;

        std::vector<BYTE> buf;
        if (!ReadModBuf(hProcess, m.base, m.size, buf)) continue;

        if (result.engine == ENGINE_SOURCE2 || result.engine == ENGINE_SOURCE1) {
            if (nl == L"client.dll" || nl == L"engine2.dll" || &m == &result.modules[0]) {
                ScanBank(PATS_CS2, sizeof(PATS_CS2)/sizeof(*PATS_CS2), buf, m.base, sn, result.patterns);
            }
        } else if (result.engine == ENGINE_UNREAL) {
            ScanBank(PATS_UE50, sizeof(PATS_UE50)/sizeof(*PATS_UE50), buf, m.base, sn, result.patterns);
        } else if (result.engine == ENGINE_UNITY_IL2CPP) {
            ScanBank(PATS_IL2CPP, sizeof(PATS_IL2CPP)/sizeof(*PATS_IL2CPP), buf, m.base, sn, result.patterns);
        }

        if (&m == &result.modules[0]) {
            ScanBank(PATS_GENERIC, sizeof(PATS_GENERIC)/sizeof(*PATS_GENERIC), buf, m.base, sn, result.patterns);
        }
        if (nl == L"client.dll" || &m == &result.modules[0]) {
            ScanStringXrefs(buf, m.base, sn, result.patterns);
        }
    }

    // Engine-Specific Deep Walks (v4 Features)
    if (result.engine == ENGINE_UNREAL) {
        prog(L"Walking Unreal Engine GObjects & GNames...", 50);
        UEDumpResult ueRes;
        if (DumpUnrealEngine(hProcess, result.modules, result.patterns, result.ueVersion, ueRes, [&](const std::wstring& m, int p){ prog(m, 50 + p/5); })) {
            result.ueObjectsText = ueRes.formattedText;
            result.processEventAddr = ueRes.processEventAddr;
        }
    } else if (result.engine == ENGINE_UNITY_IL2CPP) {
        prog(L"Walking IL2CPP Runtime & Parsing global-metadata.dat...", 55);
        IL2CppDumpResult il2Res;
        if (DumpIL2CPP(hProcess, result.modules, result.exports, il2Res, [&](const std::wstring& m, int p){ prog(m, 55 + p/10); })) {
            result.il2cppMetadataText = il2Res.formattedText;
        }
        // Disk metadata parse
        std::wstring exePath = result.modules[0].path;
        std::wstring metaPath = FindMetadataFile(exePath);
        if (!metaPath.empty()) {
            MetaDumpResult metaRes;
            if (ParseMetadataDat(metaPath, metaRes)) {
                result.il2cppFileMetaText = metaRes.formattedText;
            }
        }
    } else if (result.engine == ENGINE_UNITY_MONO) {
        prog(L"Walking Unity Mono Assembly Tree...", 60);
        MonoDumpResult monoRes;
        if (DumpMonoRuntime(hProcess, result.modules, result.exports, monoRes, [&](const std::wstring& m, int p){ prog(m, 60 + p/10); })) {
            result.monoMetaText = monoRes.formattedText;
        }
    } else if (result.engine == ENGINE_SOURCE2) {
        prog(L"Scanning Source2 ConVars & Regenerating CS2 patterns...", 65);
        auto cvars = ScanConVars(hProcess, result.modules, mainModBuf, result.modules[0].base);
        if (!cvars.empty()) result.conVarText = FormatConVars(cvars);

        // Auto-Regen missing patterns
        auto regens = RegenerateCS2Patterns(hProcess, mainModBuf, result.modules[0].base, result.patterns);
        if (!regens.empty()) result.regenPatternsText = FormatRegenResults(regens);
    }

    // v4: Vtable & RTTI Scanning
    prog(L"Scanning Vtables & RTTI Class Info...", 75);
    VtableScanResult vtRes;
    if (ScanVtables(hProcess, result.modules, WStrToStr(result.modules[0].name), vtRes, [&](const std::wstring& m, int p){ prog(m, 75 + p/10); })) {
        result.vtableText = vtRes.formattedText;
    }

    // Pointer Chains Walk
    prog(L"Walking multi-level pointer chains...", 85);
    {
        uintptr_t elBase = 0, lpBase = 0, gwBase = 0, goBase = 0;
        for (auto& pr : result.patterns) {
            if (pr.label == "dwEntityList" && !elBase) elBase = pr.address;
            if (pr.label == "dwLocalPlayerPawn" && !lpBase) lpBase = pr.address;
            if (pr.label == "GWorld" && !gwBase) gwBase = pr.address;
            if (pr.label == "GObjects" && !goBase) goBase = pr.address;
        }
        std::vector<PointerChain> chains;
        if (result.engine == ENGINE_SOURCE2 || result.engine == ENGINE_SOURCE1) {
            auto cs = BuildCS2Chains(elBase, lpBase); chains.insert(chains.end(), cs.begin(), cs.end());
        }
        if (result.engine == ENGINE_UNREAL) {
            auto uc = BuildUEChains(gwBase, goBase); chains.insert(chains.end(), uc.begin(), uc.end());
        }
        for (auto& c : chains) {
            auto res = WalkChain(hProcess, c);
            PointerChainDump pcd; pcd.label = c.label; pcd.valid = res.valid;
            pcd.finalAddress = res.finalAddress; pcd.finalValue = res.finalValue;
            std::ostringstream chain; chain << HexStr(c.baseAddr);
            for (auto off : c.offsets) chain << "->[+" << HexStr(off,4) << "]";
            pcd.chain = chain.str();
            result.chains.push_back(pcd);
        }
    }

    // v4: Confidence Verification
    prog(L"Verifying offsets & calculating confidence scores...", 90);
    {
        std::vector<PointerChainResult> chainPCRs;
        auto verified = VerifyOffsets(hProcess, result.patterns, chainPCRs);
        for (size_t vi = 0; vi < verified.size() && vi < result.patterns.size(); vi++) {
            result.patterns[vi].confidence = (int)verified[vi].confidence;
            result.patterns[vi].liveValue  = verified[vi].liveValue;
            result.patterns[vi].hexDump    = verified[vi].hexDump;
        }
        std::ostringstream verOut;
        verOut << "================================================================\r\n";
        verOut << "  [CONFIDENCE VERIFICATION]\r\n";
        verOut << "================================================================\r\n";
        verOut << "  " << std::left << std::setw(35) << "Label" << std::setw(8) << "Conf" << std::setw(22) << "Live Value" << "Hex Dump\r\n";
        verOut << "----------------------------------------------------------------\r\n";
        for (auto& v : verified) {
            verOut << "  " << std::left << std::setw(35) << v.label << std::setw(8) << v.confStr << std::setw(22) << HexStr(v.liveValue) << v.hexDump << "\r\n";
        }
        result.verificationText = verOut.str();
    }

    CloseHandle(hProcess);

    // Format final full text
    prog(L"Building final output report...", 95);
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    char tb[64]={}; ctime_s(tb, sizeof(tb), &t);
    std::string ts = tb; if (!ts.empty()&&ts.back()=='\n') ts.pop_back();

    std::ostringstream out;
    std::string pn = WStrToStr(result.processName);
    std::string en = std::string(EngineTypeName(result.engine));
    if (result.engine==ENGINE_UNREAL && result.ueVersion!=UE_UNKNOWN) en += " (v" + std::string(UEVersionName(result.ueVersion)) + ")";

    #define S  "================================================================\r\n"
    #define S2 "----------------------------------------------------------------\r\n"

    out << S << "  PROCESS MEMORY OFFSET DUMP v4.2 -- CATEGORIZED REPORT\r\n" << S;
    out << "  Game       : " << pn << "\r\n";
    out << "  PID        : " << pid << " (0x" << std::hex << std::uppercase << pid << std::dec << ")\r\n";
    out << "  Engine     : " << en << "\r\n";
    out << "  Time       : " << ts << "\r\n";
    out << "  Total Offsets Found : " << result.patterns.size() << "\r\n";
    out << "\r\n";

    // -----------------------------------------------------------------------
    // Helper to determine offset priority: 1 = ÖNEMLİ, 2 = DAHA AZ, 3 = ÖNEMSİZ
    // -----------------------------------------------------------------------
    auto GetPriority = [](const PatternResult& p) -> int {
        std::string l = p.label;
        for (auto& c : l) c = tolower(c);

        // 1. ÖNEMLİLER (High value for cheats / core offsets)
        if (l.find("entitylist") != std::string::npos ||
            l.find("localplayer") != std::string::npos ||
            l.find("viewmatrix") != std::string::npos ||
            l.find("gworld") != std::string::npos ||
            l.find("gobjects") != std::string::npos ||
            l.find("gnames") != std::string::npos ||
            l.find("health") != std::string::npos ||
            l.find("origin") != std::string::npos ||
            l.find("team") != std::string::npos ||
            l.find("forceattack") != std::string::npos ||
            l.find("forcejump") != std::string::npos) {
            return 1;
        }

        // 3. ÖNEMSİZLER (String references, generic symbols)
        if (l.find("xref_") == 0 || l.find("str_") == 0) {
            return 3;
        }

        // 2. DAHA AZ ÖNEMLİLER (Everything else)
        return 2;
    };

    std::vector<const PatternResult*> prio1, prio2, prio3;
    for (auto& p : result.patterns) {
        int pr = GetPriority(p);
        if (pr == 1) prio1.push_back(&p);
        else if (pr == 2) prio2.push_back(&p);
        else prio3.push_back(&p);
    }

    // -----------------------------------------------------------------------
    // 1. ÖNEMLİ OFFSETS
    // -----------------------------------------------------------------------
    out << S << "  [1. ONEMLI OFFSETS (CRITICAL / CORE GAME POINTERS)]\r\n" << S;
    if (prio1.empty()) {
        out << "  (Henuz kritik pattern eslesmedi)\r\n\r\n";
    } else {
        out << "  " << std::left << std::setw(35) << "Label"
            << std::setw(22) << "Resolved VA"
            << std::setw(16) << "Offset"
            << "Module\r\n" << S2;
        for (auto* p : prio1) {
            out << "  " << std::left << std::setw(35) << p->label
                << std::setw(22) << HexStr(p->address)
                << std::setw(16) << HexStr(p->offset, 8)
                << p->moduleName << (p->notes.empty() ? "" : "  // " + p->notes) << "\r\n";
        }
        out << "\r\n";
    }

    // -----------------------------------------------------------------------
    // 2. DAHA AZ ONEMLI OFFSETS
    // -----------------------------------------------------------------------
    out << S << "  [2. DAHA AZ ONEMLI OFFSETS (SECONDARY POINTERS & VARS)]\r\n" << S;
    if (prio2.empty()) {
        out << "  (Ikincil offset bulunamadi)\r\n\r\n";
    } else {
        out << "  " << std::left << std::setw(35) << "Label"
            << std::setw(22) << "Resolved VA"
            << std::setw(16) << "Offset"
            << "Module\r\n" << S2;
        for (auto* p : prio2) {
            out << "  " << std::left << std::setw(35) << p->label
                << std::setw(22) << HexStr(p->address)
                << std::setw(16) << HexStr(p->offset, 8)
                << p->moduleName << (p->notes.empty() ? "" : "  // " + p->notes) << "\r\n";
        }
        out << "\r\n";
    }

    // -----------------------------------------------------------------------
    // 3. ONEMSIZ OFFSETS
    // -----------------------------------------------------------------------
    out << S << "  [3. ONEMSIZ OFFSETS (STRING XREFS & HELPER SYMBOLS)]\r\n" << S;
    if (prio3.empty()) {
        out << "  (String xref / yardımcı offset yok)\r\n\r\n";
    } else {
        out << "  " << std::left << std::setw(35) << "Label"
            << std::setw(22) << "Address"
            << std::setw(16) << "Offset"
            << "Module\r\n" << S2;
        for (auto* p : prio3) {
            out << "  " << std::left << std::setw(35) << p->label
                << std::setw(22) << HexStr(p->address)
                << std::setw(16) << HexStr(p->offset, 8)
                << p->moduleName << "\r\n";
        }
        out << "\r\n";
    }

    // Extended modules output
    if (!result.verificationText.empty()) out << result.verificationText << "\r\n";
    if (!result.ueObjectsText.empty()) out << result.ueObjectsText << "\r\n";
    if (!result.il2cppMetadataText.empty()) out << result.il2cppMetadataText << "\r\n";
    if (!result.il2cppFileMetaText.empty()) out << result.il2cppFileMetaText << "\r\n";
    if (!result.monoMetaText.empty()) out << result.monoMetaText << "\r\n";
    if (!result.conVarText.empty()) out << result.conVarText << "\r\n";
    if (!result.vtableText.empty()) out << result.vtableText << "\r\n";
    if (!result.vadDumpText.empty()) out << result.vadDumpText << "\r\n";
    if (!result.regenPatternsText.empty()) out << result.regenPatternsText << "\r\n";

    out << S << "  [END OF CATEGORIZED DUMP - " << pn << "]\r\n" << S;
    #undef S
    #undef S2

    result.rawText = out.str();
    prog(L"Done.", 100);
    return true;
}

bool WriteOffsets(const DumpResult& result, const std::wstring& outputPath) {
    FILE* fp = nullptr;
    _wfopen_s(&fp, outputPath.c_str(), L"wb");
    if (!fp) return false;
    fwrite(result.rawText.c_str(), 1, result.rawText.size(), fp);
    fclose(fp);

    std::wstring jsonPath = outputPath;
    size_t dotPos = jsonPath.rfind(L'.');
    if (dotPos != std::wstring::npos) jsonPath = jsonPath.substr(0, dotPos) + L".json";
    else jsonPath += L".json";
    WriteJSON(result, jsonPath);

    std::wstring hPath = outputPath;
    dotPos = hPath.rfind(L'.');
    if (dotPos != std::wstring::npos) hPath = hPath.substr(0, dotPos) + L".h";
    else hPath += L".h";
    WriteCppHeader(result, hPath);

    // Extract folder path from outputPath
    std::wstring dirPath = outputPath;
    size_t slashPos = dirPath.rfind(L'\\');
    if (slashPos != std::wstring::npos) dirPath = dirPath.substr(0, slashPos + 1);
    else dirPath = L".\\";

    // Save vad_map.txt in game directory
    if (!result.vadDumpText.empty()) {
        std::wstring vadPath = dirPath + L"vad_map.txt";
        FILE* vfp = nullptr;
        _wfopen_s(&vfp, vadPath.c_str(), L"wb");
        if (vfp) {
            fwrite(result.vadDumpText.c_str(), 1, result.vadDumpText.size(), vfp);
            fclose(vfp);
        }
    }

    // Save CS2 auto-regen patterns in game directory
    if (!result.regenPatternsText.empty()) {
        std::wstring regenPath = dirPath + L"regen_patterns.txt";
        FILE* rfp = nullptr;
        _wfopen_s(&rfp, regenPath.c_str(), L"wb");
        if (rfp) {
            fwrite(result.regenPatternsText.c_str(), 1, result.regenPatternsText.size(), rfp);
            fclose(rfp);
        }
    }

    return true;
}






