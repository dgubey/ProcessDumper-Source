/*
 * km_read.h  --  User-mode interface to ProcDumperKM kernel driver
 *
 * Purpose   : Singleton KernelReader class that installs, starts, and
 *             communicates with the ProcDumperKM WDM driver via IOCTLs.
 *             Falls back to ReadProcessMemory when driver is unavailable.
 *
 * Usage     :
 *   KernelReader& kr = KernelReader::Get();
 *   if (kr.Load(L"C:\\path\\to\\ProcDumperKM.sys")) {
 *       uint64_t base = kr.GetModuleBase(pid, L"GameAssembly.dll");
 *       kr.ReadMemory(pid, base + 0x10, &val, sizeof(val));
 *   }
 *
 * Privileges: SeLoadDriverPrivilege required for Load().
 *             ReadMemory fallback requires PROCESS_VM_READ on target.
 *
 * Thread    : Not thread-safe -- external synchronization required for
 *             concurrent Load/Unload calls. ReadMemory/GetModuleBase are
 *             safe to call from multiple threads once loaded.
 */

#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <cstdint>
#include "km_driver/km_interface.h"

/*
 * KernelReader
 *
 * Singleton.  One device handle.  One service registration.
 * Install once, hammer IOCTLs from any thread.
 */
class KernelReader {
public:
    // Returns the global instance.  No dynamic allocation, no lifetime ambiguity.
    static KernelReader& Get();

    /*
     * Load
     * ----
     * Registers the .sys file as a kernel service, starts it, and opens
     * a handle to \\\\.\\ProcDumperKM.
     *
     * driverPath : absolute path to ProcDumperKM.sys
     * Returns    : true on success; call GetLastError() on failure.
     *
     * Side-fx    : Calls OpenSCManager (requires admin), CreateService,
     *              StartService, CreateFile.  Test signing must be enabled.
     */
    bool Load(const std::wstring& driverPath);

    /*
     * Unload
     * ------
     * Closes the device handle, stops the service, deletes the service
     * registration.  Safe to call even if Load() failed partially.
     */
    void Unload();

    // True after a successful Load().
    bool IsLoaded() const { return m_loaded; }

    /*
     * ReadMemory
     * ----------
     * Reads `size` bytes from `address` in process `pid` into `buf`.
     *
     * pid     : target process ID
     * address : virtual address in target''s address space
     * buf     : local destination buffer (must be >= size bytes)
     * size    : byte count
     *
     * Returns : true on success.
     *
     * When driver is loaded : IOCTL_KM_READ_MEMORY  (ring-0 copy)
     * When driver is absent : ReadProcessMemory      (ring-3 fallback, needs handle rights)
     */
    bool ReadMemory(DWORD pid, uintptr_t address, void* buf, size_t size);

    /*
     * GetModuleBase
     * -------------
     * Walks the target process PEB InLoadOrderModuleList to find the
     * module whose BaseDllName matches modName (case-insensitive).
     *
     * pid     : target process ID
     * modName : e.g. L"GameAssembly.dll"
     *
     * Returns : module base address, or 0 on failure.
     *
     * Requires driver to be loaded (no fallback implemented here).
     */
    uintptr_t GetModuleBase(DWORD pid, const std::wstring& modName);

private:
    KernelReader()  = default;
    ~KernelReader() = default;

    KernelReader(const KernelReader&)            = delete;
    KernelReader& operator=(const KernelReader&) = delete;

    HANDLE    m_hDevice  = INVALID_HANDLE_VALUE;
    SC_HANDLE m_hSCM     = nullptr;
    SC_HANDLE m_hService = nullptr;
    bool      m_loaded   = false;

    static constexpr const wchar_t* SERVICE_NAME   = L"ProcDumperKM";
    static constexpr const wchar_t* DEVICE_PATH    = L"\\\\.\\ProcDumperKM";
};
