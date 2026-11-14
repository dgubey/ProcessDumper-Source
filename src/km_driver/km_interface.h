#pragma once
#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#endif

#define KM_DEVICE_TYPE 0x8000
#define IOCTL_KM_READ_MEMORY     CTL_CODE(KM_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KM_QUERY_PROCESS   CTL_CODE(KM_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KM_GET_MODULE_BASE CTL_CODE(KM_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _KM_READ_REQUEST {
    ULONG64 ProcessId;
    ULONG64 Address;
    ULONG64 Size;
    ULONG64 OutputBuffer;
} KM_READ_REQUEST, *PKM_READ_REQUEST;

typedef struct _KM_QUERY_RESPONSE {
    ULONG64  EProcess;
    ULONG    IsWow64;
    NTSTATUS Status;
} KM_QUERY_RESPONSE, *PKM_QUERY_RESPONSE;

typedef struct _KM_MODULE_REQUEST {
    ULONG64 ProcessId;
    WCHAR   ModuleName[260];
    ULONG64 BaseAddress;
    ULONG64 ModuleSize;
} KM_MODULE_REQUEST, *PKM_MODULE_REQUEST;
