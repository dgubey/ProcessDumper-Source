// engine_mono.cpp -- Mono Runtime Metadata Walker
#include "engine_mono.h"
#include <sstream>
#include <iomanip>

static bool RPM(HANDLE h, uintptr_t a, void* b, size_t s) {
    SIZE_T g=0; return ReadProcessMemory(h,(LPCVOID)a,b,s,&g)&&g==s;
}
static uintptr_t RPtr(HANDLE h, uintptr_t a){ uintptr_t v=0; RPM(h,a,&v,8); return v; }
static uint32_t  RU32(HANDLE h, uintptr_t a){ uint32_t  v=0; RPM(h,a,&v,4); return v; }
static uint16_t  RU16(HANDLE h, uintptr_t a){ uint16_t  v=0; RPM(h,a,&v,2); return v; }
static int32_t   RI32(HANDLE h, uintptr_t a){ int32_t   v=0; RPM(h,a,&v,4); return v; }

static std::string RStr(HANDLE h, uintptr_t a, size_t mx=256) {
    if(!a) return "";
    char buf[257]={}; SIZE_T g=0;
    ReadProcessMemory(h,(LPCVOID)a,buf,std::min(mx,(size_t)256),&g);
    buf[g]=0;
    for(size_t i=0;i<g;i++) if((unsigned char)buf[i]<0x20||(unsigned char)buf[i]>0x7E) buf[i]='?';
    return buf;
}

static const char* MonoTypeStr(uint8_t t) {
    static const char* n[]={"END","void","bool","char","int8","uint8","int16","uint16",
        "int32","uint32","int64","uint64","float","double","string","ptr","byref",
        "valuetype","class","var","array","genericinst","typedbyref","I","U","fnptr",
        "object","szarray","mvar","cmod_reqd","cmod_opt","internal"};
    return t<32?n[t]:"unknown";
}

#define MC_IMAGE       0x00
#define MC_PARENT      0x08
#define MC_NAME        0x10
#define MC_NAMESPACE   0x18
#define MC_INST_SIZE   0x28
#define MC_FIELDS      0x60
#define MC_FIELD_COUNT 0x68
#define MCF_TYPE       0x00
#define MCF_NAME       0x08
#define MCF_PARENT     0x10
#define MCF_OFFSET     0x18
#define MT_TYPE        0x0A
#define MI_NAME        0x00
#define MI_TYPECOUNT   0x1C
#define MI_TYPEDEFS    0x20
#define GS_DATA        0x00
#define GS_NEXT        0x08

static std::vector<MonoField> ReadMonoFields(HANDLE h, uintptr_t classPtr) {
    std::vector<MonoField> fields;
    uint16_t count = RU16(h, classPtr + MC_FIELD_COUNT);
    uintptr_t fArr = RPtr(h, classPtr + MC_FIELDS);
    if(!fArr || count==0 || count>1024) return fields;
    const size_t STRIDE = 0x20;
    for(uint16_t i=0;i<count;i++) {
        uintptr_t fb = fArr + i*STRIDE;
        MonoField f;
        uintptr_t nptr = RPtr(h, fb+MCF_NAME);
        f.name = RStr(h, nptr);
        if(f.name.empty()) f.name = "(field_"+std::to_string(i)+")";
        f.offset = (uint32_t)RI32(h, fb+MCF_OFFSET);
        f.isStatic = (RI32(h,fb+MCF_OFFSET) < 0);
        uintptr_t tp = RPtr(h, fb+MCF_TYPE);
        if(tp){ uint8_t te=0; RPM(h,tp+MT_TYPE,&te,1); f.typeName=MonoTypeStr(te); }
        else f.typeName="?";
        fields.push_back(std::move(f));
    }
    return fields;
}

bool DumpMonoRuntime(HANDLE hProcess,
                     const std::vector<ModuleEntry>& modules,
                     const std::vector<ExportEntry>& exports,
                     MonoDumpResult& result,
                     ProgressCallback progress) {
    result={};
    auto prog=[&](const std::string& m, int p){
        if(progress){
            std::wstring w; for(char c:m) w+=(wchar_t)c;
            progress(w,p);
        }
    };

    prog("Finding mono_get_root_domain...",5);

    uintptr_t monoBase=0;
    for(auto& m:modules) {
        std::wstring nl=m.name; for(auto&c:nl) c=towlower(c);
        if(nl==L"mono.dll"||nl.find(L"mono-2.0")!=std::wstring::npos||nl==L"unityplayer.dll") {
            monoBase=m.base; break;
        }
    }
    if(!monoBase) return false;

    uintptr_t domainGetAddr=0;
    for(auto& e:exports) {
        if(e.name=="mono_get_root_domain"||e.name=="mono_domain_get") { domainGetAddr=e.va; break; }
    }
    if(!domainGetAddr) return false;

    BYTE instr[16]={};
    if(!RPM(hProcess,domainGetAddr,instr,16)) return false;
    uintptr_t domainPtrAddr=0;
    if(instr[0]==0x48&&instr[1]==0x8B&&(instr[2]==0x05||instr[2]==0x0D)) {
        int32_t disp=0; memcpy(&disp,instr+3,4);
        domainPtrAddr=domainGetAddr+7+disp;
    } else return false;

    uintptr_t domainAddr=RPtr(hProcess,domainPtrAddr);
    if(!domainAddr) return false;
    result.domainAddr=domainAddr;

    prog("Walking Mono assemblies...",15);
    uintptr_t assembliesListPtr=RPtr(hProcess,domainAddr+0x08);
    if(!assembliesListPtr) return false;

    int classCount=0;
    uintptr_t node=assembliesListPtr;
    int asmIdx=0;
    while(node&&asmIdx<64) {
        uintptr_t asmPtr=RPtr(hProcess,node+GS_DATA);
        node=RPtr(hProcess,node+GS_NEXT);
        if(!asmPtr){asmIdx++;continue;}

        uintptr_t imgPtr=RPtr(hProcess,asmPtr);
        if(!imgPtr){asmIdx++;continue;}

        uintptr_t namePtr=RPtr(hProcess,imgPtr+MI_NAME);
        std::string asmName=RStr(hProcess,namePtr);
        if(asmName.empty()) asmName="asm_"+std::to_string(asmIdx);

        prog("Mono: "+asmName, 15+asmIdx*50/64);

        uint32_t typeCount=RU32(hProcess,imgPtr+MI_TYPECOUNT);
        uintptr_t typeArr=RPtr(hProcess,imgPtr+MI_TYPEDEFS);
        if(!typeArr||typeCount==0||typeCount>5000){asmIdx++;continue;}

        uint32_t limit=std::min(typeCount,(uint32_t)200);
        for(uint32_t ci=0;ci<limit&&classCount<500;ci++) {
            uintptr_t cp=RPtr(hProcess,typeArr+ci*8);
            if(!cp) continue;
            MonoClass mc;
            mc.classPtr=cp; mc.assemblyName=asmName;
            mc.instanceSize=RU32(hProcess,cp+MC_INST_SIZE);
            uintptr_t np=RPtr(hProcess,cp+MC_NAME), nsp=RPtr(hProcess,cp+MC_NAMESPACE);
            mc.name=RStr(hProcess,np); mc.namespaceName=RStr(hProcess,nsp);
            if(mc.name.empty()) continue;
            mc.fields=ReadMonoFields(hProcess,cp);
            result.classes.push_back(std::move(mc));
            classCount++;
        }
        asmIdx++;
    }

    prog("Formatting Mono output...",85);
    std::ostringstream out;
    out<<"================================================================\r\n"
       <<"  [MONO RUNTIME METADATA DUMP]\r\n"
       <<"================================================================\r\n"
       <<"  Domain  : 0x"<<std::hex<<std::uppercase<<result.domainAddr<<"\r\n"
       <<"  Classes : "<<std::dec<<result.classes.size()<<"\r\n\r\n";
    for(auto& cls:result.classes) {
        std::string fn=cls.namespaceName.empty()?cls.name:cls.namespaceName+"."+cls.name;
        out<<"  class "<<fn<<" ["<<cls.assemblyName<<"] size=0x"
           <<std::hex<<cls.instanceSize<<std::dec
           <<" ptr=0x"<<std::hex<<cls.classPtr<<std::dec<<"\r\n  {\r\n";
        if(cls.fields.empty()) out<<"    // (no fields)\r\n";
        for(auto& f:cls.fields) {
            out<<"    "<<(f.isStatic?"static ":"")
               <<std::left<<std::setw(12)<<f.typeName<<" "
               <<std::left<<std::setw(40)<<f.name
               <<(f.isStatic?" // static":"  // offset=0x"+([&]()->std::string{
                   std::ostringstream s; s<<std::hex<<f.offset; return s.str();})())
               <<"\r\n";
        }
        out<<"  }\r\n\r\n";
    }
    result.formattedText=out.str();
    prog("Mono dump done.",100);
    return !result.classes.empty();
}
