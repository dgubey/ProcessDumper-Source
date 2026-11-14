// km_read.cpp -- Kernel Driver User-Mode Interface v2 (with camouflage suffix support)
// *queries registry for the random device name written by the driver at load time*
#include "km_read.h"
#include <string>
#include <sstream>

#pragma comment(lib, "advapi32.lib")

KernelReader& KernelReader::Get() {
    static KernelReader instance;
    return instance;
}

// Read the random suffix the driver wrote to registry
static std::wstring ReadDriverSuffix() {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ProcDumperKM",
                      0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return L"";
    WCHAR buf[64] = {};
    DWORD sz = sizeof(buf);
    DWORD type = 0;
    RegQueryValueExW(hKey, L"Suffix", nullptr, &type, (LPBYTE)buf, &sz);
    RegCloseKey(hKey);
    return std::wstring(buf);
}

bool KernelReader::Load(const std::wstring& driverPath) {
    m_hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!m_hSCM) return false;

    static const LPCWSTR SERVICE_NAME = L"ProcDumperKM";

    // Try to open existing service first
    m_hService = OpenServiceW(m_hSCM, SERVICE_NAME,
                              SERVICE_START | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!m_hService) {
        // Create the service
        m_hService = CreateServiceW(
            m_hSCM, SERVICE_NAME, L"Process Dumper KM Driver",
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            driverPath.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!m_hService) return false;
    }

    // Start service
    if (!StartServiceW(m_hService, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) return false;
    }

    // Wait a moment for driver to write registry key
    Sleep(200);

    // Read the random suffix from registry
    std::wstring suffix = ReadDriverSuffix();
    std::wstring devPath = L"\\\\.\\PD_" + suffix;

    // Open device handle using randomized name
    m_hDevice = CreateFileW(
        devPath.c_str(),
        GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (m_hDevice == INVALID_HANDLE_VALUE) {
        // Fallback to static name (backward compat)
        m_hDevice = CreateFileW(L"\\\\.\\ProcDumperKM",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    m_loaded = (m_hDevice != INVALID_HANDLE_VALUE);
    return m_loaded;
}

void KernelReader::Unload() {
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
    }
    if (m_hService) {
        SERVICE_STATUS ss = {};
        ControlService(m_hService, SERVICE_CONTROL_STOP, &ss);
        DeleteService(m_hService);
        CloseServiceHandle(m_hService);
        m_hService = nullptr;
    }
    if (m_hSCM) {
        CloseServiceHandle(m_hSCM);
        m_hSCM = nullptr;
    }
    // Remove registry key
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ProcDumperKM");
    m_loaded = false;
}

bool KernelReader::ReadMemory(DWORD pid, uintptr_t address, void* buf, size_t size) {
    if (!IsLoaded()) {
        // Fallback to ReadProcessMemory
        HANDLE hProc = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if (!hProc) return false;
        SIZE_T got = 0;
        bool ok = ReadProcessMemory(hProc, (LPCVOID)address, buf, size, &got) && got > 0;
        CloseHandle(hProc);
        return ok;
    }

    // Use kernel driver
    KM_READ_REQUEST req = {};
    req.ProcessId    = pid;
    req.Address      = (ULONG64)address;
    req.Size         = (ULONG64)size;
    req.OutputBuffer = 0; // not used in METHOD_BUFFERED

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        m_hDevice,
        IOCTL_KM_READ_MEMORY,
        &req, sizeof(req),
        buf, (DWORD)size,
        &bytesReturned,
        nullptr);

    return ok && bytesReturned > 0;
}

uintptr_t KernelReader::GetModuleBase(DWORD pid, const std::wstring& modName) {
    if (!IsLoaded()) return 0;

    KM_MODULE_REQUEST req = {};
    req.ProcessId = pid;
    wcsncpy_s(req.ModuleName, 260, modName.c_str(), _TRUNCATE);

    DWORD bytesReturned = 0;
    DeviceIoControl(
        m_hDevice,
        IOCTL_KM_GET_MODULE_BASE,
        &req, sizeof(req),
        &req, sizeof(req),
        &bytesReturned,
        nullptr);

    return (uintptr_t)req.BaseAddress;
}
