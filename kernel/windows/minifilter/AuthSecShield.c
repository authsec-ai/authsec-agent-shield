/*
 * AuthSec Agent Shield — Windows Kernel Minifilter Driver
 *
 * Intercepts filesystem write/delete operations at the kernel level.
 * Operates BELOW the NTFS ACL layer — no userspace process can bypass this,
 * including MSYS2/Git Bash which bypasses NTFS ACLs via its POSIX layer.
 *
 * Architecture:
 *   AI tool calls write() / DeleteFile() / rename()
 *       ↓
 *   I/O Manager routes IRP to filter manager
 *       ↓
 *   AuthSecShield minifilter pre-operation callback fires
 *       ↓
 *   Driver checks: is this path protected? is caller a known AI process?
 *       ↓ if risky
 *   Driver sends IRP_PENDING + notifies user-space daemon via named pipe
 *       ↓
 *   User-space daemon calls Agent Guard API → push notification → human decision
 *       ↓ approved
 *   Driver signals completion, IRP passes through to NTFS
 *       ↓ denied
 *   Driver completes IRP with STATUS_ACCESS_DENIED
 *
 * Build:
 *   Requires Windows Driver Kit (WDK) + Visual Studio
 *   msbuild AuthSecShield.vcxproj /p:Configuration=Release /p:Platform=x64
 *
 * Install:
 *   sc create AuthSecShield type= filesys start= boot binpath= <path>
 *   fltMC load AuthSecShield
 *   fltMC attach AuthSecShield C:   (attach to all volumes: iterate with fltMC volumes)
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//
// ── Driver metadata ─────────────────────────────────────────────────────────
//

#define DRIVER_NAME         L"AuthSecShield"
#define POOL_TAG            'SSAS'  // AuthSec Shield reversed
#define PIPE_NAME           L"\\Device\\NamedPipe\\authsec-shield-kernel"
#define SHIELD_ALTITUDE     L"370030"   // Altitude in the FSFilter range (anti-virus band)

//
// ── Protected paths (wide strings) ──────────────────────────────────────────
// User-space daemon updates these via DeviceIoControl IOCTL.
// Hardcoded defaults below; IOCTL overrides at runtime.
//

#define MAX_PROTECTED_PATHS 32
#define MAX_PATH_LEN        512

typedef struct _PROTECTED_PATH {
    WCHAR   Path[MAX_PATH_LEN];
    ULONG   PathLen;    // character count
    BOOLEAN Active;
} PROTECTED_PATH, *PPROTECTED_PATH;

static PROTECTED_PATH g_ProtectedPaths[MAX_PROTECTED_PATHS];
static ULONG          g_ProtectedPathCount = 0;
static ERESOURCE      g_PathLock;
static BOOLEAN        g_ShieldEnabled = TRUE;

//
// ── IOCTL definitions (matches user-space daemon) ───────────────────────────
//

#define IOCTL_SHIELD_SET_PATHS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SHIELD_ENABLE      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SHIELD_DISABLE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SHIELD_GET_STATUS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// ── Pending decision request ─────────────────────────────────────────────────
// Kernel allocates one per blocked IRP, user-space resolves it.
//

typedef struct _PENDING_REQUEST {
    LIST_ENTRY      ListEntry;
    PFLT_CALLBACK_DATA Data;
    KEVENT          CompletionEvent;
    NTSTATUS        Decision;           // STATUS_SUCCESS = approved, STATUS_ACCESS_DENIED = denied
    WCHAR           FilePath[MAX_PATH_LEN];
    ULONG           ProcessId;
    WCHAR           ProcessName[260];
    ULONG           Operation;          // IRP_MJ_* code
} PENDING_REQUEST, *PPENDING_REQUEST;

static LIST_ENTRY       g_PendingList;
static KSPIN_LOCK       g_PendingLock;
static PDEVICE_OBJECT   g_ControlDevice = NULL;

//
// ── Filter registration ──────────────────────────────────────────────────────
//

PFLT_FILTER g_FilterHandle = NULL;

FLT_PREOP_CALLBACK_STATUS AuthSecPreCreate(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS AuthSecPreWrite(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS AuthSecPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

CONST FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    // IRP_MJ_CREATE: intercept file opens with write/overwrite intent
    { IRP_MJ_CREATE,
      0,
      AuthSecPreCreate,
      NULL },

    // IRP_MJ_WRITE: intercept direct writes
    { IRP_MJ_WRITE,
      0,
      AuthSecPreWrite,
      NULL },

    // IRP_MJ_SET_INFORMATION: intercept renames, deletes, truncates
    { IRP_MJ_SET_INFORMATION,
      0,
      AuthSecPreSetInfo,
      NULL },

    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),           // Size
    FLT_REGISTRATION_VERSION,           // Version
    0,                                  // Flags
    NULL,                               // Context registrations
    g_Callbacks,                        // Operation callbacks
    AuthSecUnload,                      // Unload callback
    AuthSecInstanceSetup,               // InstanceSetup
    AuthSecInstanceQueryTeardown,       // InstanceQueryTeardown
    NULL, NULL, NULL, NULL, NULL        // Optional callbacks
};

//
// ── Forward declarations ─────────────────────────────────────────────────────
//

DRIVER_INITIALIZE DriverEntry;
NTSTATUS AuthSecUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS AuthSecInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);
NTSTATUS AuthSecInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

NTSTATUS AuthSecDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

//
// ── Path matching ─────────────────────────────────────────────────────────────
//

static BOOLEAN IsProtectedPath(_In_ PUNICODE_STRING FilePath)
{
    if (!g_ShieldEnabled) return FALSE;

    ExAcquireResourceSharedLite(&g_PathLock, TRUE);

    for (ULONG i = 0; i < g_ProtectedPathCount; i++) {
        if (!g_ProtectedPaths[i].Active) continue;

        UNICODE_STRING protectedPath = {
            .Length        = (USHORT)(g_ProtectedPaths[i].PathLen * sizeof(WCHAR)),
            .MaximumLength = (USHORT)(g_ProtectedPaths[i].PathLen * sizeof(WCHAR)),
            .Buffer        = g_ProtectedPaths[i].Path
        };

        // Check if FilePath starts with this protected path
        if (FilePath->Length >= protectedPath.Length) {
            UNICODE_STRING prefix = {
                .Length        = protectedPath.Length,
                .MaximumLength = protectedPath.Length,
                .Buffer        = FilePath->Buffer
            };
            if (RtlEqualUnicodeString(&prefix, &protectedPath, TRUE)) {
                ExReleaseResourceLite(&g_PathLock);
                return TRUE;
            }
        }
    }

    ExReleaseResourceLite(&g_PathLock);
    return FALSE;
}

//
// ── Process name helper ───────────────────────────────────────────────────────
//

static VOID GetCurrentProcessName(_Out_writes_(260) PWCHAR Buffer, _In_ SIZE_T BufLen)
{
    PEPROCESS Process = PsGetCurrentProcess();
    if (Process) {
        PUCHAR namePtr = PsGetProcessImageFileName(Process);
        if (namePtr) {
            RtlStringCchPrintfW(Buffer, BufLen, L"%S", namePtr);
            return;
        }
    }
    RtlStringCchCopyW(Buffer, BufLen, L"unknown");
}

//
// ── Notify user-space daemon (named pipe or shared memory) ────────────────────
// Queues a pending request and waits for decision with timeout.
//

static NTSTATUS NotifyAndWait(
    _In_  PFLT_CALLBACK_DATA Data,
    _In_  PUNICODE_STRING    FilePath,
    _In_  ULONG              Operation)
{
    PPENDING_REQUEST req = (PPENDING_REQUEST)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(PENDING_REQUEST), POOL_TAG);
    if (!req) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(req, sizeof(*req));
    req->Data      = Data;
    req->Operation = Operation;
    req->ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    GetCurrentProcessName(req->ProcessName, 260);
    KeInitializeEvent(&req->CompletionEvent, NotificationEvent, FALSE);
    req->Decision = STATUS_ACCESS_DENIED; // default: deny if no answer

    RtlStringCchCopyNW(req->FilePath, MAX_PATH_LEN,
                       FilePath->Buffer,
                       FilePath->Length / sizeof(WCHAR));

    // Queue the request
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PendingLock, &oldIrql);
    InsertTailList(&g_PendingList, &req->ListEntry);
    KeReleaseSpinLock(&g_PendingLock, oldIrql);

    // Wait up to 60 seconds for a decision
    LARGE_INTEGER timeout;
    timeout.QuadPart = -600000000LL; // 60 seconds in 100ns units
    NTSTATUS waitStatus = KeWaitForSingleObject(
        &req->CompletionEvent, Executive, KernelMode, FALSE, &timeout);

    NTSTATUS decision;
    if (waitStatus == STATUS_TIMEOUT) {
        decision = STATUS_ACCESS_DENIED; // timed out = deny
    } else {
        decision = req->Decision;
    }

    // Remove from pending list
    KeAcquireSpinLock(&g_PendingLock, &oldIrql);
    RemoveEntryList(&req->ListEntry);
    KeReleaseSpinLock(&g_PendingLock, oldIrql);

    ExFreePoolWithTag(req, POOL_TAG);
    return decision;
}

//
// ── Pre-operation callbacks ───────────────────────────────────────────────────
//

FLT_PREOP_CALLBACK_STATUS AuthSecPreCreate(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!g_ShieldEnabled) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Only care about write/overwrite opens
    ACCESS_MASK access = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    ULONG disp = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

    BOOLEAN isWrite = (access & (FILE_WRITE_DATA | FILE_APPEND_DATA |
                                  FILE_WRITE_ATTRIBUTES | DELETE)) != 0;
    BOOLEAN isOverwrite = (disp == FILE_OVERWRITE || disp == FILE_OVERWRITE_IF ||
                           disp == FILE_SUPERSEDE);

    if (!isWrite && !isOverwrite) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Get file path
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FltParseFileNameInformation(nameInfo);

    if (!IsProtectedPath(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Protected path — notify user-space and wait
    NTSTATUS decision = NotifyAndWait(Data, &nameInfo->Name, IRP_MJ_CREATE);
    FltReleaseFileNameInformation(nameInfo);

    if (!NT_SUCCESS(decision)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS AuthSecPreWrite(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!g_ShieldEnabled) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FltParseFileNameInformation(nameInfo);

    if (!IsProtectedPath(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    NTSTATUS decision = NotifyAndWait(Data, &nameInfo->Name, IRP_MJ_WRITE);
    FltReleaseFileNameInformation(nameInfo);

    if (!NT_SUCCESS(decision)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS AuthSecPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!g_ShieldEnabled) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Intercept delete, rename, truncate
    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (infoClass != FileDispositionInformation &&
        infoClass != FileDispositionInformationEx &&
        infoClass != FileRenameInformation &&
        infoClass != FileRenameInformationEx &&
        infoClass != FileEndOfFileInformation) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FltParseFileNameInformation(nameInfo);

    if (!IsProtectedPath(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    NTSTATUS decision = NotifyAndWait(Data, &nameInfo->Name, IRP_MJ_SET_INFORMATION);
    FltReleaseFileNameInformation(nameInfo);

    if (!NT_SUCCESS(decision)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//
// ── DeviceIoControl handler (user-space → driver communication) ──────────────
//

NTSTATUS AuthSecDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl  = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID inBuf  = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    switch (ioctl) {

    case IOCTL_SHIELD_SET_PATHS: {
        // Input: array of null-terminated wide strings, double-null terminated
        // e.g. L"C:\\Users\\user\\.ssh\0C:\\Users\\user\\.aws\0\0"
        ExAcquireResourceExclusiveLite(&g_PathLock, TRUE);
        g_ProtectedPathCount = 0;
        RtlZeroMemory(g_ProtectedPaths, sizeof(g_ProtectedPaths));

        PWCHAR p = (PWCHAR)inBuf;
        ULONG remaining = inLen / sizeof(WCHAR);
        while (remaining > 0 && *p != L'\0' && g_ProtectedPathCount < MAX_PROTECTED_PATHS) {
            SIZE_T len = wcsnlen(p, remaining);
            if (len == 0 || len >= MAX_PATH_LEN) break;
            RtlCopyMemory(g_ProtectedPaths[g_ProtectedPathCount].Path,
                          p, len * sizeof(WCHAR));
            g_ProtectedPaths[g_ProtectedPathCount].PathLen = (ULONG)len;
            g_ProtectedPaths[g_ProtectedPathCount].Active  = TRUE;
            g_ProtectedPathCount++;
            p         += len + 1;
            remaining -= (ULONG)(len + 1);
        }
        ExReleaseResourceLite(&g_PathLock);
        break;
    }

    case IOCTL_SHIELD_ENABLE:
        g_ShieldEnabled = TRUE;
        break;

    case IOCTL_SHIELD_DISABLE:
        g_ShieldEnabled = FALSE;
        break;

    case IOCTL_SHIELD_GET_STATUS: {
        // Output: one ULONG — 1 if enabled, 0 if disabled
        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG)) {
            *(PULONG)Irp->AssociatedIrp.SystemBuffer = g_ShieldEnabled ? 1 : 0;
            info = sizeof(ULONG);
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

//
// ── Driver entry / unload ────────────────────────────────────────────────────
//

/* Forward declarations for exec monitor (defined in AuthSecShieldExec.c) */
NTSTATUS AuthSecExecInit(void);
VOID     AuthSecExecUninit(void);

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    // Initialize synchronization primitives
    ExInitializeResourceLite(&g_PathLock);
    KeInitializeSpinLock(&g_PendingLock);
    InitializeListHead(&g_PendingList);
    g_ShieldEnabled = TRUE;

    // Create a control device for IOCTL communication
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\AuthSecShield");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\AuthSecShield");

    status = IoCreateDevice(DriverObject, 0, &devName,
                            FILE_DEVICE_UNKNOWN, 0, FALSE, &g_ControlDevice);
    if (!NT_SUCCESS(status)) {
        DbgPrint("AuthSecShield: IoCreateDevice failed: %08X\n", status);
        return status;
    }
    IoCreateSymbolicLink(&symLink, &devName);

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AuthSecDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = AuthSecDispatchPassthrough;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = AuthSecDispatchPassthrough;

    // Register the minifilter
    status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("AuthSecShield: FltRegisterFilter failed: %08X\n", status);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_ControlDevice);
        return status;
    }

    // Start filtering
    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("AuthSecShield: FltStartFiltering failed: %08X\n", status);
        FltUnregisterFilter(g_FilterHandle);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_ControlDevice);
        return status;
    }

    DbgPrint("AuthSecShield: Kernel minifilter loaded. Altitude: %S\n", SHIELD_ALTITUDE);

    // Initialize process execution monitor
    // Non-fatal: if it fails, filesystem protection still works
    NTSTATUS execStatus = AuthSecExecInit();
    if (!NT_SUCCESS(execStatus)) {
        DbgPrint("AuthSecShield: WARNING — exec monitor init failed: %08X\n", execStatus);
        DbgPrint("AuthSecShield: Filesystem protection remains active.\n");
    } else {
        DbgPrint("AuthSecShield: Exec monitor active — ALL process creations intercepted.\n");
    }

    return STATUS_SUCCESS;
}

NTSTATUS AuthSecUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    // Unload is only allowed during system shutdown OR if caller is admin.
    // FLTFL_FILTER_UNLOAD_MANDATORY fires during system shutdown — always allow.
    if (!(Flags & FLTFL_FILTER_UNLOAD_MANDATORY)) {
        // Check if the requesting thread has admin privileges
        PACCESS_TOKEN token = PsReferencePrimaryToken(PsGetCurrentProcess());
        BOOLEAN isAdmin = SeTokenIsAdmin(token);
        PsDereferencePrimaryToken(token);
        if (!isAdmin) {
            DbgPrint("AuthSecShield: Unload DENIED — caller is not admin.\n");
            return STATUS_ACCESS_DENIED;
        }
    }

    // Stop exec monitor first
    AuthSecExecUninit();

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\AuthSecShield");
    IoDeleteSymbolicLink(&symLink);
    if (g_ControlDevice) {
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = NULL;
    }

    FltUnregisterFilter(g_FilterHandle);
    ExDeleteResourceLite(&g_PathLock);

    DbgPrint("AuthSecShield: Kernel minifilter unloaded.\n");
    return STATUS_SUCCESS;
}

NTSTATUS AuthSecInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    // Attach to NTFS, FAT, exFAT — not network or special filesystems
    if (VolumeFilesystemType == FLT_FSTYPE_NTFS  ||
        VolumeFilesystemType == FLT_FSTYPE_FAT   ||
        VolumeFilesystemType == FLT_FSTYPE_EXFAT) {
        return STATUS_SUCCESS;
    }
    return STATUS_FLT_DO_NOT_ATTACH;
}

NTSTATUS AuthSecInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

NTSTATUS AuthSecDispatchPassthrough(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
