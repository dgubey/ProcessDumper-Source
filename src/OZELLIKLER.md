# 🚀 ProcessDumper v4.2 Pro -- Gelişmiş Oyun Bellek & Offset Dökücü

**ProcessDumper v4.2 Pro**, modern oyun motorları (Source 2, Unreal Engine 4/5, Unity IL2CPP, Unity Mono), anti-cheat korumaları ve karmaşık bellek yapılarından anlık olarak pointer, vtable, pattern ve offset dökümü almak üzere sıfırdan C++17 ile geliştirilmiş **Ring-0 Kernel Sürücü Destekli** yüksek performanslı döküm arayüzüdür.

---

## 🌟 ÖNE ÇIKAN BAŞLICA ÖZELLİKLER

### 🎯 1. Çoklu Oyun Motoru Desteği (Multi-Engine Scanner)
- **Source 2 Engine (CS2, Dota 2, Deadlock):**
  - `client.dll` & `engine2.dll` otomatik tespiti ve modül ayrıştırması.
  - CS2 ConVar (`sv_cheats`, `sensitivity`, `cl_fov` vb.) bellek içi otomatik taraması.
  - Değişen güncellemelerde otomatik kırılan pattern'leri yeniden üreten **CS2 Auto-Regenerator Engine**.
- **Unreal Engine 4 & 5 (UE4 / UE5):**
  - **GObjects Walk:** Bellekteki binlerce `UObject` örneğini ve adreslerini canlı dökme.
  - **GNames Pool Decoder:** TNameEntryArray (UE4) ve FNamePool (UE5) şifre çözme.
  - **ProcessEvent VTable Locator:** UE4 (Slot 61) ve UE5 (Slot 62) vtable adreslerini otomatik bulma.
- **Unity IL2CPP Engine:**
  - `GameAssembly.dll` runtime domain walk & class offset çözümleme.
  - `global-metadata.dat` (v24..v29) dosyasından statik sınıf, alan ve metod isimlerini dökme.
- **Unity Mono Engine:**
  - `mono.dll` domain, assembly tree ve `Assembly-CSharp.dll` sınıf yapısı taraması.

---

### 🛡️ 2. Anti-Cheat Bypass & Privilege Escalation (Ring-0 / Kernel Level)
- **SeDebugPrivilege Otomatik Yükseltme:** Windows işletim sisteminde `AdjustTokenPrivileges` kullanarak en yüksek bellek okuma yetkisine otomatik erişim.
- **4 Aşamalı Adaptive `OpenProcess` Merdiveni:**
  1. `PROCESS_ALL_ACCESS`
  2. `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION`
  3. `PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`
  4. `PROCESS_QUERY_LIMITED_INFORMATION`
- **BattEye & Easy Anti-Cheat Kernel Bypass (`ProcDumperKM.sys`):**
  - `BEDaisy.sys` veya `BEService.exe` tespit edildiğinde otomatik devreye girer.
  - `ObRegisterCallbacks` engellerini aşarak Ring-0 `MmCopyVirtualMemory` IOCTL arabirimi üzerinden bellek okur.

---

### 🔍 3. Gelişmiş Bellek & Yapı Taramaları
- **VAD (Virtual Address Descriptor) Sınırsız Haritalama:**
  - PEB manipülasyonunu atlatmak için `VirtualQueryEx` ile tüm `MEM_COMMIT` bellek bölgelerini tarar.
  - PEB modül listesinde gizlenen **Hidden PE Module**'leri anında tespit eder.
  - `vad_map.txt` dosyasına sınırsız döküm yazar.
- **VTable & RTTI Class Info Scanner:**
  - `.rdata` ve `.text` kesimlerinde sanal fonksiyon tablolarını (VTable) arar.
  - MSVC x64 RTTI (`RTTICompleteObjectLocator`) mangled class isimlerini çözümler (`class PlayerController` vb.).
- **Multi-Level Pointer Chain Walker & Verifier:**
  - Çok seviyeli pointer zincirlerini canlı bellek değerleri ve hex dump'ları ile doğrular (`HIGH`, `MEDIUM`, `LOW`, `DEAD` güven skoru).

---

### 📁 4. Modüler & Oyuna Özel Dosya Mimarisi
- **Per-Game Output Folder:** Her dökümde oyun adına özel klasör otomatik oluşturulur (Örn: `dumper/cs2/`, `dumper/TaskBarHero/`).
- **3-Katmanlı Öncelikli Raporlama:**
  1. **[1. ONEMLI OFFSETS]:** EntityList, LocalPlayer, ViewMatrix, GWorld, GObjects gibi kritik hile pointer'ları.
  2. **[2. DAHA AZ ONEMLI OFFSETS]:** İkincil semboller ve değişkenler.
  3. **[3. ONEMSIZ OFFSETS]:** String xref ve yardımcı semboller.
- **Çoklu Çıktı Formatları:**
  - `offsets.txt`: İnsan tarafından okunabilir kategorize edilmiş metin raporu.
  - `offsets.json`: Otomasyon ve script entegrasyonu için JSON verisi.
  - `offsets.h`: C/C++ projelerine doğrudan `#include` edilebilen makro/enum başlık dosyası.
  - `vad_map.txt`: Oyun bellek haritası.
  - `regen_patterns.txt`: Otomatik türetilen yeni CS2 pattern'leri.

---

## 🛠️ PROJE DOSYA YAPISI (`src/`)

```
dumper/
├── ProcessDumper.exe           # Derlenmiş 3.10 MB Çalıştırılabilir Dosya
├── OZELLIKLER.md              # Teknik Özellikler ve Kullanım Kılavuzu
├── build.bat                  # Derleme Komut Dosyası
└── src/                        # Tüm C++ Kaynak Kodları
    ├── main.cpp                # GUI WinMain, Dosya Yolları ve Buton Mantığı
    ├── dumper.cpp / dumper.h   # Master Dumper Orkestratörü & Engine Router
    ├── pattern_db.h            # CS2, UE, IL2CPP Pattern Veritabanı
    ├── engine_il2cpp.cpp / .h  # IL2CPP Runtime Walker
    ├── meta_parser.cpp / .h    # global-metadata.dat Static Parser
    ├── engine_ue.cpp / .h      # UE4/UE5 GObjects & GNames Scanner
    ├── engine_mono.cpp / .h    # Unity Mono Domain Walker
    ├── engine_cs2_ext.cpp      # Source 2 ConVar Scanner
    ├── cs2_autoregen.cpp / .h  # CS2 Auto Pattern Regenerator
    ├── engine_vad.cpp / .h     # VAD & Hidden PE Scanner
    ├── vtable_scan.cpp / .h    # Vtable & RTTI Class Info Scanner
    ├── chain_verifier.cpp / .h # Pointer Chain Verification Engine
    ├── km_read.cpp / km_read.h # Ring-0 Kernel Driver User-Mode Interface
    ├── app.manifest            # SeDebugPrivilege & Admin UAC Manifest
    └── km_driver/              # WDM Kernel Driver C Kodları (ProcDumperKM.sys)
        ├── driver.c
        ├── km_interface.h
        └── build_driver.bat
```

---

## ⚙️ KODDAN DERLEME (COMPILATION)

Proje MinGW (g++ 64-bit) ile bağımsız olarak derlenebilir:

```bash
cd C:\Users\HZLoxi\Desktop\dumper\src
build.bat
```

Derleme sonucunda üretilen `ProcessDumper.exe` kök dizine kopyalanır.
