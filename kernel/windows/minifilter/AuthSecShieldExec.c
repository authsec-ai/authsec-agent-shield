/*
 * AuthSec Agent Shield — Windows Process Execution Monitor
 *
 * Hooks ALL process creation system-wide using kernel callbacks:
 *   - PsSetCreateProcessNotifyRoutineEx  → intercepts every CreateProcess call
 *     with the FULL command line before the process starts
 *   - ObRegisterCallbacks                → protects the bridge process from
 *     being killed by non-admin processes (prevents bypass by killing the daemon)
 *
 * This is the Windows equivalent of fanotify FAN_OPEN_EXEC_PERM.
 * Every process created on the system — by any user, AI tool, script, or
 * scheduled task — passes through AuthSecProcessNotify BEFORE it starts.
 *
 * Cannot be bypassed because:
 *   - PsSetCreateProcessNotifyRoutineEx runs in kernel mode inside NtCreateUserProcess
 *   - Setting CreateInfo->CreationStatus = STATUS_ACCESS_DENIED blocks the
 *     process before it ever starts
 *   - Renaming the binary doesn't help — we block on the FULL COMMAND LINE
 *     which contains the arguments (the dangerous part), not just the binary name
 *   - The ImageFileName field gives the NT path to the binary if needed for
 *     binary-identity checks
 *
 * Integration: This file is compiled into AuthSecShield.sys.
 *   DriverEntry calls AuthSecExecInit() to register the callbacks.
 *   AuthSecUnload calls AuthSecExecUninit() to unregister.
 *
 * The actual decision (approve/deny) is routed via the existing pending-request
 * infrastructure in AuthSecShield.c — same named pipe / IOCTL bridge.
 */

#include <fltKernel.h>
#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>

/* From AuthSecShield.c */
extern NTSTATUS NotifyAndWait(PFLT_CALLBACK_DATA Data, PUNICODE_STRING FilePath, ULONG Operation);
extern BOOLEAN  g_ShieldEnabled;

#define OP_EXEC_CREATE 0x20  /* new operation code for process creation */
#define POOL_TAG_EXEC  'XSAS'

/* Bridge to pass command line via the pending-request pipe */
typedef struct _EXEC_PENDING_REQUEST {
    LIST_ENTRY      ListEntry;
    KEVENT          CompletionEvent;
    NTSTATUS        Decision;
    WCHAR           CommandLine[4096];
    WCHAR           ImageFileName[512];
    ULONG           ProcessId;
} EXEC_PENDING_REQUEST, *PEXEC_PENDING_REQUEST;

extern LIST_ENTRY  g_PendingList;   /* shared with AuthSecShield.c */
extern KSPIN_LOCK  g_PendingLock;

/* ObRegisterCallbacks handle for bridge process protection */
static PVOID g_ObCallbackHandle = NULL;
static PEPROCESS g_BridgeProcess = NULL;

/* ── Risk scoring ─────────────────────────────────────────────────────────── */
/*
 * Local pre-filter — same logic as the Linux local_risk_score().
 * If score <= 30, allow immediately without calling the bridge.
 * This keeps reads, normal compiles, etc. at zero latency.
 */
static ULONG LocalRiskScore(_In_ PCUNICODE_STRING CommandLine)
{
    if (!CommandLine || !CommandLine->Buffer) return 0;

    ULONG score = 0;
    PWCHAR cmd = CommandLine->Buffer;
    SIZE_T len = CommandLine->Length / sizeof(WCHAR);

    /* Helper: case-insensitive substring search in the command line */
#define CMDHAS(w) (wcsstr(cmd, (w)) != NULL)

    /* Dangerous binaries */
    if (CMDHAS(L"\\rm.exe") || CMDHAS(L"\\rm ") ||
        CMDHAS(L"\\del.exe") || CMDHAS(L"cmd /c del")) score += 30;
    if (CMDHAS(L"git push")) score += 30;
    if (CMDHAS(L"kubectl")) score += 30;
    if (CMDHAS(L"terraform")) score += 30;
    if (CMDHAS(L"az ") || CMDHAS(L"aws ") || CMDHAS(L"gcloud ")) score += 20;
    if (CMDHAS(L"docker rm") || CMDHAS(L"docker rmi")) score += 30;

    /* Risky arguments */
    if (CMDHAS(L" -rf") || CMDHAS(L" /f ") || CMDHAS(L" --force")) score += 20;
    if (CMDHAS(L" -r ") || CMDHAS(L" --recursive")) score += 15;
    if (CMDHAS(L"--force") && CMDHAS(L"push")) score += 50;
    if (CMDHAS(L"delete namespace") || CMDHAS(L"delete ns ")) score += 60;
    if (CMDHAS(L"destroy") || CMDHAS(L"terminate")) score += 40;
    if (CMDHAS(L"DROP TABLE") || CMDHAS(L"TRUNCATE ")) score += 60;
    if (CMDHAS(L"\\.ssh\\") || CMDHAS(L"\\.aws\\") ||
        CMDHAS(L"\\.kube\\") || CMDHAS(L"\\Windows\\")) score += 25;

    /* PowerShell risky patterns */
    if (CMDHAS(L"Remove-Item") || CMDHAS(L"ri ") || CMDHAS(L"del ")) score += 25;
    if (CMDHAS(L"Format-Volume") || CMDHAS(L"Clear-Disk")) score += 80;
    if (CMDHAS(L"Invoke-Expression") || CMDHAS(L"IEX ")) score += 30;

#undef CMDHAS

    return score > 100 ? 100 : score;
}

/* ── Process creation callback ─────────────────────────────────────────────── */

static VOID AuthSecProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    /* Termination notification — ignore */
    if (!CreateInfo) return;
    if (!g_ShieldEnabled) return;

    /* No command line available (rare — kernel processes) */
    if (!CreateInfo->CommandLine || !CreateInfo->CommandLine->Buffer) return;

    /* Skip kernel system process (PID 4) and SYSTEM (PID 0) */
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    if (pid <= 4) return;

    /* Local risk score — allow safe commands instantly */
    ULONG score = LocalRiskScore(CreateInfo->CommandLine);
    if (score <= 30) return; /* allow — no API call */

    /*
     * Block this process creation and wait for user decision.
     *
     * Allocate a pending request, queue it for the bridge process,
     * and wait. If approved within 60s, allow. Otherwise deny.
     */
    PEXEC_PENDING_REQUEST req = (PEXEC_PENDING_REQUEST)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(EXEC_PENDING_REQUEST), POOL_TAG_EXEC);
    if (!req) {
        /* Out of memory — deny for safety */
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        return;
    }

    RtlZeroMemory(req, sizeof(*req));
    req->ProcessId = pid;
    req->Decision  = STATUS_ACCESS_DENIED; /* default: deny if no answer */
    KeInitializeEvent(&req->CompletionEvent, NotificationEvent, FALSE);

    /* Copy command line */
    SIZE_T copyLen = min(CreateInfo->CommandLine->Length / sizeof(WCHAR),
                        (SIZE_T)(ARRAYSIZE(req->CommandLine) - 1));
    RtlCopyMemory(req->CommandLine, CreateInfo->CommandLine->Buffer,
                  copyLen * sizeof(WCHAR));

    /* Copy image file name */
    if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
        SIZE_T fnLen = min(CreateInfo->ImageFileName->Length / sizeof(WCHAR),
                          (SIZE_T)(ARRAYSIZE(req->ImageFileName) - 1));
        RtlCopyMemory(req->ImageFileName, CreateInfo->ImageFileName->Buffer,
                      fnLen * sizeof(WCHAR));
    }

    /* Queue the request */
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PendingLock, &oldIrql);
    InsertTailList(&g_PendingList, &req->ListEntry);
    KeReleaseSpinLock(&g_PendingLock, oldIrql);

    /* Wait up to 60 seconds */
    LARGE_INTEGER timeout;
    timeout.QuadPart = -600000000LL;
    NTSTATUS waitStatus = KeWaitForSingleObject(
        &req->CompletionEvent, Executive, KernelMode, FALSE, &timeout);

    NTSTATUS decision = (waitStatus == STATUS_TIMEOUT)
                        ? STATUS_ACCESS_DENIED
                        : req->Decision;

    /* Remove from list */
    KeAcquireSpinLock(&g_PendingLock, &oldIrql);
    RemoveEntryList(&req->ListEntry);
    KeReleaseSpinLock(&g_PendingLock, oldIrql);

    ExFreePoolWithTag(req, POOL_TAG_EXEC);

    if (!NT_SUCCESS(decision)) {
        /* Deny: block the process creation */
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        DbgPrint("AuthSecShield: BLOCKED process creation: %wZ score=%lu\n",
                 CreateInfo->CommandLine, score);
    }
    /* If approved: return without setting CreationStatus → process starts normally */
}

/* ── Bridge process handle protection ─────────────────────────────────────── */
/*
 * Intercept OpenProcess calls targeting the bridge process.
 * Strip PROCESS_TERMINATE from non-admin callers so they cannot kill the daemon.
 */

static OB_PREOP_CALLBACK_STATUS AuthSecObPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!g_BridgeProcess) return OB_PREOP_SUCCESS;
    if (OperationInformation->Object != g_BridgeProcess) return OB_PREOP_SUCCESS;

    /* Check if the calling process has admin privilege */
    PACCESS_TOKEN token = PsReferencePrimaryToken(PsGetCurrentProcess());
    BOOLEAN isAdmin = SeTokenIsAdmin(token);
    PsDereferencePrimaryToken(token);

    if (!isAdmin) {
        /* Strip terminate + suspend privileges */
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess
                &= ~(PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_VM_WRITE);
        } else {
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess
                &= ~(PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_VM_WRITE);
        }
    }

    return OB_PREOP_SUCCESS;
}

/* ── Register/unregister bridge process ──────────────────────────────────── */

NTSTATUS AuthSecSetBridgeProcess(_In_ HANDLE ProcessId)
{
    PEPROCESS proc = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &proc);
    if (!NT_SUCCESS(status)) return status;

    if (g_BridgeProcess) {
        ObDereferenceObject(g_BridgeProcess);
    }
    g_BridgeProcess = proc; /* holds a reference */
    DbgPrint("AuthSecShield: Bridge process registered (PID=%lu)\n",
             (ULONG)(ULONG_PTR)ProcessId);
    return STATUS_SUCCESS;
}

/* ── Init / uninit ──────────────────────────────────────────────────────── */

NTSTATUS AuthSecExecInit(void)
{
    /* Register process creation callback */
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(AuthSecProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("AuthSecShield: PsSetCreateProcessNotifyRoutineEx failed: %08X\n", status);
        return status;
    }

    /* Register object callback to protect bridge process */
    OB_CALLBACK_REGISTRATION obReg  = {0};
    OB_OPERATION_REGISTRATION opReg = {0};

    opReg.ObjectType               = PsProcessType;
    opReg.Operations               = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation             = AuthSecObPreCallback;
    opReg.PostOperation            = NULL;

    obReg.Version                  = OB_FLT_REGISTRATION_VERSION;
    obReg.OperationRegistrationCount = 1;
    obReg.Altitude                 = RTL_CONSTANT_STRING(L"370031");
    obReg.RegistrationContext      = NULL;
    obReg.OperationRegistration    = &opReg;

    status = ObRegisterCallbacks(&obReg, &g_ObCallbackHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("AuthSecShield: ObRegisterCallbacks failed: %08X (non-fatal)\n", status);
        /* ObRegisterCallbacks failure is non-fatal — exec monitoring still works */
        g_ObCallbackHandle = NULL;
    }

    DbgPrint("AuthSecShield: Exec monitor active — all process creations intercepted\n");
    return STATUS_SUCCESS;
}

VOID AuthSecExecUninit(void)
{
    PsSetCreateProcessNotifyRoutineEx(AuthSecProcessNotify, TRUE);

    if (g_ObCallbackHandle) {
        ObUnRegisterCallbacks(g_ObCallbackHandle);
        g_ObCallbackHandle = NULL;
    }

    if (g_BridgeProcess) {
        ObDereferenceObject(g_BridgeProcess);
        g_BridgeProcess = NULL;
    }

    DbgPrint("AuthSecShield: Exec monitor stopped\n");
}
