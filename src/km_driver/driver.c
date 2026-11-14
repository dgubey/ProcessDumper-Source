// km_driver/driver.c -- Ring-0 WDM Kernel Driver with Anti-Detect Camouflage
// *the driver wears a mask, its device name changes with every boot like a ghost*
#include <ntddk.h>
#include "km_interface.h"

// ---------------------------------------------------------------------------
// Undocumented exports we need
// ---------------------------------------------------------------------------
NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess, PVOID SourceAddress,
    PEPROCESS TargetProcess, PVOID TargetAddress,
    SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
    PSIZE_T NumberOfBytesCopied);

PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);

// PEB structure minimal (for module walk)
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB64 {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[21];
    PPEB_LDR_DATA Ldr;
} PEB64, *PPEB64;

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static PDEVICE_OBJECT g_DeviceObject = NULL;
static UNICODE_STRING g_DeviceName;
static UNICODE_STRING g_SymLink;
static WCHAR g_DeviceNameBuf[64];
static WCHAR g_SymLinkBuf[64];

// ---------------------------------------------------------------------------
// Generate pseudo-random suffix from system time (ring-0 safe)
// ---------------------------------------------------------------------------
static VOID GenerateRandomSuffix(PWCHAR buf, ULONG len) {
    LARGE_INTEGER time;
    KeQuerySystemTime(&time);
    ULONGLONG v = (ULONGLONG)time.QuadPart;
    // Mix with KeQueryPerformanceCounter if available
    LARGE_INTEGER freq;
    LARGE_INTEGER perf = KeQueryPerformanceCounter(&freq);
    v ^= (ULONGLONG)perf.QuadPart;
    v ^= (v >> 33);
    v *= 0xFF51AFD7ED558CCDULL;
    v ^= (v >> 33);

    // Write as 8 hex chars
    static const WCHAR hex[] = L"0123456789ABCDEF";
    for (ULONG i = 0; i < 8 && i < len - 1; i++) {
        buf[i] = hex[(v >> (i * 4)) & 0xF];
    }
    buf[8] = L'\0';
}

// ---------------------------------------------------------------------------
// IOCTL Handlers
// ---------------------------------------------------------------------------
static NTSTATUS HandleReadMemory(PIRP Irp, PIO_STACK_LOCATION Stack) {
    ULONG inLen  = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inLen < sizeof(KM_READ_REQUEST) || outLen == 0)
        return STATUS_INVALID_PARAMETER;

    PKM_READ_REQUEST req = (PKM_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    if (!req) return STATUS_INVALID_PARAMETER;

    if (req->Size == 0 || req->Size > 0x10000000)
        return STATUS_INVALID_PARAMETER;

    // Lookup source process
    PEPROCESS srcProcess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &srcProcess);
    if (!NT_SUCCESS(status)) return status;

    // Allocate kernel buffer for the read
    PVOID kBuf = ExAllocatePoolWithTag(NonPagedPool, req->Size, 'DmpR');
    if (!kBuf) {
        ObDereferenceObject(srcProcess);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(kBuf, req->Size);

    SIZE_T copied = 0;
    status = MmCopyVirtualMemory(
        srcProcess,
        (PVOID)(ULONG_PTR)req->Address,
        PsGetCurrentProcess(),
        kBuf,
        req->Size,
        KernelMode,
        &copied);

    ObDereferenceObject(srcProcess);

    if (NT_SUCCESS(status) && copied > 0) {
        // The OutputBuffer is the caller's buffer (METHOD_BUFFERED)
        // But OutputBuffer is req->OutputBuffer (a user-space VA we should write to)
        // Actually with METHOD_BUFFERED the output is Irp->AssociatedIrp.SystemBuffer
        // We overlay input and output in the same buffer for METHOD_BUFFERED
        // Return data via the system buffer (output)
        if (outLen >= copied) {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, kBuf, copied);
            Irp->IoStatus.Information = copied;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }

    ExFreePoolWithTag(kBuf, 'DmpR');
    return status;
}

static NTSTATUS HandleQueryProcess(PIRP Irp, PIO_STACK_LOCATION Stack) {
    ULONG inLen  = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inLen < sizeof(ULONG64) || outLen < sizeof(KM_QUERY_RESPONSE))
        return STATUS_INVALID_PARAMETER;

    ULONG64 pid = *(PULONG64)Irp->AssociatedIrp.SystemBuffer;
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);

    PKM_QUERY_RESPONSE resp = (PKM_QUERY_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
    if (NT_SUCCESS(status)) {
        resp->EProcess  = (ULONG64)(ULONG_PTR)process;
        resp->IsWow64   = (PsGetProcessWow64Process(process) != NULL) ? 1 : 0;
        resp->Status    = STATUS_SUCCESS;
        ObDereferenceObject(process);
    } else {
        resp->EProcess  = 0;
        resp->IsWow64   = 0;
        resp->Status    = status;
        status          = STATUS_SUCCESS; // still return success at IOCTL level
    }
    Irp->IoStatus.Information = sizeof(KM_QUERY_RESPONSE);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleGetModuleBase(PIRP Irp, PIO_STACK_LOCATION Stack) {
    ULONG inLen  = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inLen < sizeof(KM_MODULE_REQUEST) || outLen < sizeof(KM_MODULE_REQUEST))
        return STATUS_INVALID_PARAMETER;

    PKM_MODULE_REQUEST req = (PKM_MODULE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    if (!req) return STATUS_INVALID_PARAMETER;

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    req->BaseAddress = 0;
    req->ModuleSize  = 0;

    // Attach to process to read PEB
    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    __try {
        PPEB64 peb = (PPEB64)PsGetProcessPeb(process);
        if (peb && MmIsAddressValid(peb) && peb->Ldr && MmIsAddressValid(peb->Ldr)) {
            PPEB_LDR_DATA ldr = peb->Ldr;
            PLIST_ENTRY listHead = &ldr->InLoadOrderModuleList;
            PLIST_ENTRY entry    = listHead->Flink;

            // Build target UNICODE_STRING for comparison
            UNICODE_STRING targetName;
            RtlInitUnicodeString(&targetName, req->ModuleName);

            while (entry != listHead && MmIsAddressValid(entry)) {
                PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(
                    entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                if (MmIsAddressValid(mod) &&
                    mod->BaseDllName.Buffer &&
                    MmIsAddressValid(mod->BaseDllName.Buffer)) {

                    if (RtlEqualUnicodeString(&mod->BaseDllName, &targetName, TRUE)) {
                        req->BaseAddress = (ULONG64)(ULONG_PTR)mod->DllBase;
                        req->ModuleSize  = (ULONG64)mod->SizeOfImage;
                        break;
                    }
                }
                entry = entry->Flink;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // Process memory may be unmapped during iteration — safe fallthrough
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    Irp->IoStatus.Information = sizeof(KM_MODULE_REQUEST);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// IRP Dispatch
// ---------------------------------------------------------------------------
static NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status;

    switch (code) {
        case IOCTL_KM_READ_MEMORY:    status = HandleReadMemory(Irp, stack);    break;
        case IOCTL_KM_QUERY_PROCESS:  status = HandleQueryProcess(Irp, stack);  break;
        case IOCTL_KM_GET_MODULE_BASE:status = HandleGetModuleBase(Irp, stack); break;
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            Irp->IoStatus.Information = 0;
            break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ---------------------------------------------------------------------------
// Driver Unload -- clean up device + symlink
// ---------------------------------------------------------------------------
static VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    IoDeleteSymbolicLink(&g_SymLink);
    if (g_DeviceObject)
        IoDeleteDevice(g_DeviceObject);
    DbgPrint("[ProcDumper] Driver unloaded\n");
}

// ---------------------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // Generate random device name suffix for camouflage
    WCHAR suffix[16] = {0};
    GenerateRandomSuffix(suffix, 16);

    // Build device name: \Device\PD_<random8hex>
    RtlZeroMemory(g_DeviceNameBuf, sizeof(g_DeviceNameBuf));
    RtlStringCbPrintfW(g_DeviceNameBuf, sizeof(g_DeviceNameBuf),
                       L"\\Device\\PD_%s", suffix);
    RtlInitUnicodeString(&g_DeviceName, g_DeviceNameBuf);

    // Build symlink: \DosDevices\PD_<random8hex>
    RtlZeroMemory(g_SymLinkBuf, sizeof(g_SymLinkBuf));
    RtlStringCbPrintfW(g_SymLinkBuf, sizeof(g_SymLinkBuf),
                       L"\\DosDevices\\PD_%s", suffix);
    RtlInitUnicodeString(&g_SymLink, g_SymLinkBuf);

    // Create device
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[ProcDumper] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    // Create symlink
    status = IoCreateSymbolicLink(&g_SymLink, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ProcDumper] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Set dispatch routines
    DriverObject->DriverUnload                         = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    // Write symlink suffix to registry for user-mode to read
    // Store in HKLM\Software\ProcDumper\DeviceSuffix
    UNICODE_STRING regPath;
    RtlInitUnicodeString(&regPath, L"\\Registry\\Machine\\SOFTWARE\\ProcDumperKM");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &regPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hKey = NULL;
    ULONG disposition = 0;
    if (NT_SUCCESS(ZwCreateKey(&hKey, KEY_SET_VALUE, &oa, 0, NULL, REG_OPTION_VOLATILE, &disposition))) {
        UNICODE_STRING valName;
        RtlInitUnicodeString(&valName, L"Suffix");
        ZwSetValueKey(hKey, &valName, 0, REG_SZ, suffix, (ULONG)((wcslen(suffix) + 1) * sizeof(WCHAR)));
        ZwClose(hKey);
    }

    DbgPrint("[ProcDumper] Driver loaded. Device: %wZ\n", &g_DeviceName);
    return STATUS_SUCCESS;
}
