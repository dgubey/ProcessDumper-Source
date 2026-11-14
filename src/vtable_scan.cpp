// vtable_scan.cpp -- Vtable + RTTI Scanner
// *combs .rdata for pointer arrays that point into .text, then peeks at RTTI above them*
#include "vtable_scan.h"
#include <sstream>
#include <iomanip>

static bool GetSectionRange(const std::vector<BYTE>& buf, DWORD targetFlags, DWORD notFlags,
                              size_t& rStart, size_t& rEnd) {
    if(buf.size()<0x40) return false;
    auto* dos=(IMAGE_DOS_HEADER*)buf.data();
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE) return false;
    auto* nt=(IMAGE_NT_HEADERS64*)(buf.data()+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE) return false;
    auto* sec=(IMAGE_SECTION_HEADER*)((BYTE*)nt+sizeof(IMAGE_NT_HEADERS64));
    WORD cnt=nt->FileHeader.NumberOfSections;
    for(WORD i=0;i<cnt;i++) {
        DWORD ch=sec[i].Characteristics;
        if((ch&targetFlags)==targetFlags&&(ch&notFlags)==0&&sec[i].Misc.VirtualSize>0) {
            rStart=sec[i].VirtualAddress;
            rEnd=rStart+sec[i].Misc.VirtualSize;
            if(rEnd>buf.size()) rEnd=buf.size();
            return true;
        }
    }
    return false;
}

static bool IsInRange(size_t v, size_t s, size_t e) { return v>=s&&v<e; }

// Try to demangle MSVC RTTI mangled name like ".?AVPlayerController@@"
static std::string DemangleRTTI(const char* mangled) {
    std::string s=mangled;
    // Strip leading ".?AV" or ".?AU" (struct) or ".?AW" (enum)
    if(s.size()>4&&s[0]=='.'&&s[1]=='?') {
        if(s[2]=='A'&&(s[3]=='V'||s[3]=='U'||s[3]=='W')) s=s.substr(4);
        else if(s[2]=='A'&&s[3]=='X') s=s.substr(4);
    }
    // Strip trailing "@@"
    if(s.size()>=2&&s[s.size()-1]=='@'&&s[s.size()-2]=='@') s=s.substr(0,s.size()-2);
    // Replace remaining "@" with "::"
    std::string res;
    for(size_t i=0;i<s.size();i++) {
        if(s[i]=='@'&&i+1<s.size()&&s[i+1]=='@') { res+="::"; i++; }
        else if(s[i]=='@') res+="::";
        else res+=s[i];
    }
    return res.empty()?mangled:res;
}

bool ScanVtables(HANDLE hProcess,
                 const std::vector<ModuleEntry>& modules,
                 const std::string& targetModuleName,
                 VtableScanResult& result,
                 ProgressCallback progress)
{
    result={};
    auto prog=[&](const std::string& m,int p){ if(progress){ std::wstring w; for(char c:m) w+=(wchar_t)c; progress(w,p); }};

    // Find target module
    const ModuleEntry* targetMod=nullptr;
    for(auto& m:modules) {
        std::wstring nl=m.name; for(auto&c:nl) c=towlower(c);
        std::string ns(nl.begin(),nl.end());
        if(ns==targetModuleName||m.name.find(std::wstring(targetModuleName.begin(),targetModuleName.end()))!=std::wstring::npos) {
            targetMod=&m; break;
        }
    }
    if(!targetMod&&!modules.empty()) targetMod=&modules[0];
    if(!targetMod) return false;

    prog("Reading module buffer for vtable scan...",10);
    size_t modSize=std::min(targetMod->size,(size_t)(64*1024*1024));
    std::vector<BYTE> buf(modSize,0);
    SIZE_T got=0;
    ReadProcessMemory(hProcess,(LPCVOID)targetMod->base,buf.data(),modSize,&got);
    if(got<0x1000) return false;

    size_t textS=0,textE=0,rdataS=0,rdataE=0;
    const DWORD CODE_FLAGS=IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE;
    const DWORD RDATA_FLAGS=IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ;
    GetSectionRange(buf,CODE_FLAGS,0,textS,textE);
    GetSectionRange(buf,RDATA_FLAGS,IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE,rdataS,rdataE);

    if(!textE||!rdataE) return false;

    uintptr_t modBase=targetMod->base;
    prog("Scanning .rdata for vtable patterns...",20);

    size_t vtFound=0;
    // Scan .rdata at 8-byte alignment looking for runs of .text pointers
    for(size_t roff=rdataS;roff+8<=rdataE&&roff+8<=buf.size();roff+=8) {
        uintptr_t val=0; memcpy(&val,buf.data()+roff,8);
        uintptr_t rva=(val>=modBase)?(val-modBase):0;

        if(!IsInRange(rva,textS,textE)) continue;

        // Count consecutive .text pointers (vtable slots)
        size_t slotCount=0;
        std::vector<uintptr_t> slots;
        for(size_t si=roff;si+8<=rdataE&&si+8<=buf.size()&&slotCount<256;si+=8) {
            uintptr_t sv=0; memcpy(&sv,buf.data()+si,8);
            uintptr_t srva=(sv>=modBase)?(sv-modBase):0;
            if(!IsInRange(srva,textS,textE)) break;
            slots.push_back(modBase+si); // address of the slot
            slotCount++;
        }
        if(slotCount<3) continue; // not a vtable

        VtableEntry ve;
        ve.vtableAddr   = modBase+roff;
        ve.slotCount    = (uint32_t)slotCount;
        ve.slots        = slots;
        ve.classInfoAddr= 0;
        ve.className    = "";

        // Check for RTTI: 8 bytes before vtable = ptr to RTTICompleteObjectLocator (COL)
        if(roff>=8+rdataS) {
            uintptr_t colPtrVal=0; memcpy(&colPtrVal,buf.data()+roff-8,8);
            uintptr_t colRVA=(colPtrVal>=modBase)?(colPtrVal-modBase):0;
            // COL should be in .rdata
            if(IsInRange(colRVA,rdataS,rdataE)&&colRVA+0x20<=buf.size()) {
                uint32_t sig=0; memcpy(&sig,buf.data()+colRVA,4);
                if(sig==1) { // x64 RTTI signature
                    // COL+0x0C = RVA of typeDescriptor (relative to image base)
                    int32_t tdRVA=0; memcpy(&tdRVA,buf.data()+colRVA+0x0C,4);
                    if(tdRVA>0&&(size_t)tdRVA+0x20<buf.size()) {
                        // TypeDescriptor+0x10 = mangled name
                        const char* mangled=(const char*)buf.data()+(size_t)tdRVA+0x10;
                        size_t maxLen=std::min((size_t)128,buf.size()-(size_t)tdRVA-0x10);
                        std::string nm(mangled,strnlen(mangled,maxLen));
                        if(!nm.empty()&&nm[0]=='.') {
                            ve.classInfoAddr=modBase+colRVA;
                            ve.className=DemangleRTTI(nm.c_str());
                        }
                    }
                }
            }
        }

        result.vtables.push_back(std::move(ve));
        vtFound++;
        roff += slotCount*8-8; // skip to end of this vtable

        if(vtFound>=200) break; // cap at 200
    }

    prog("Formatting vtable output...",90);
    std::ostringstream out;
    out<<"================================================================\r\n"
       <<"  [VTABLE + RTTI SCAN - "<<targetModuleName<<"]\r\n"
       <<"================================================================\r\n"
       <<"  Vtables found: "<<result.vtables.size()<<"\r\n\r\n";
    for(auto& vt:result.vtables) {
        out<<"  VTable @ 0x"<<std::hex<<std::uppercase<<vt.vtableAddr
           <<"  slots="<<std::dec<<vt.slotCount;
        if(!vt.className.empty()) out<<"  class="<<vt.className;
        out<<"\r\n";
        // Show first 8 slots
        size_t showN=std::min(vt.slots.size(),(size_t)8);
        for(size_t si=0;si<showN;si++) {
            uintptr_t fnPtr=0; memcpy(&fnPtr,buf.data()+(vt.slots[si]-modBase),8);
            out<<"    ["<<si<<"] 0x"<<std::hex<<std::uppercase<<fnPtr<<"\r\n";
        }
        out<<"\r\n";
    }
    result.formattedText=out.str();
    prog("Vtable scan done.",100);
    return !result.vtables.empty();
}

