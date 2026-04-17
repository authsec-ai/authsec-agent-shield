/*
 * AuthSec Agent Shield — Kernel-to-Userspace Bridge
 *
 * This is the user-space side of the kernel driver communication.
 * It runs as part of the authsec-shield daemon (via CGo or as a separate
 * helper process on Windows).
 *
 * Responsibilities:
 *   1. Open the driver's control device \\.\AuthSecShield
 *   2. Push the configured protected paths into the driver via IOCTL
 *   3. Listen on named pipe for pending decision requests from the driver
 *   4. For each request: call the Agent Guard API, get approve/deny, signal driver
 *
 * Named pipe protocol (driver → bridge):
 *   REQUEST: 4 bytes magic + SHIELD_REQUEST struct
 *   RESPONSE: 4 bytes magic + SHIELD_RESPONSE struct
 *
 * This file is compiled as a standalone Windows executable called by the Go
 * shield binary when the kernel driver is installed.
 *
 * Build:
 *   cl /W4 /WX /O2 AuthSecShieldBridge.c /link Kernel32.lib
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ── Shared with kernel driver ────────────────────────────────────────────────

#define DEVICE_NAME         L"\\\\.\\AuthSecShield"
#define PIPE_NAME           L"\\\\.\\pipe\\authsec-shield-kernel"
#define REQUEST_MAGIC       0x53484C44u   // 'SHLD'
#define RESPONSE_MAGIC      0x52455350u   // 'RESP'
#define MAX_PATH_LEN        512
#define MAX_PROTECTED_PATHS 32

#define IOCTL_SHIELD_SET_PATHS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SHIELD_ENABLE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SHIELD_DISABLE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SHIELD_GET_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct _SHIELD_REQUEST {
    DWORD   Magic;              // REQUEST_MAGIC
    DWORD   RequestId;          // unique ID for this request
    DWORD   ProcessId;
    WCHAR   ProcessName[260];
    WCHAR   FilePath[MAX_PATH_LEN];
    DWORD   Operation;          // IRP_MJ_* (2=create, 3=read, 4=write, 6=setinfo)
} SHIELD_REQUEST;

typedef struct _SHIELD_RESPONSE {
    DWORD   Magic;              // RESPONSE_MAGIC
    DWORD   RequestId;
    DWORD   Approved;           // 1 = approved, 0 = denied
} SHIELD_RESPONSE;
#pragma pack(pop)

// ── Forward declarations ─────────────────────────────────────────────────────
static BOOL SendPathsToDriver(HANDLE hDevice, const WCHAR** paths, DWORD count);
static BOOL SetDriverEnabled(HANDLE hDevice, BOOL enabled);
static DWORD WINAPI PipeListenerThread(LPVOID param);
static BOOL HandleRequest(HANDLE hPipe, const SHIELD_REQUEST* req);
static BOOL CallAgentGuardAPI(const WCHAR* filePath, const WCHAR* processName,
                               DWORD operation, BOOL* approved);
static void LogMessage(const char* level, const char* fmt, ...);

// ── Global state ─────────────────────────────────────────────────────────────
static HANDLE g_hDevice  = INVALID_HANDLE_VALUE;
static BOOL   g_Running  = TRUE;
static WCHAR  g_AgentGuardURL[1024] = {0};
static WCHAR  g_AccessToken[4096]   = {0};

// ── Entry point ──────────────────────────────────────────────────────────────
int wmain(int argc, WCHAR* argv[])
{
    // Args: bridge.exe <mode> [args...]
    // Modes:
    //   set-paths <path1> <path2> ...    — push paths to driver
    //   enable                           — enable driver filtering
    //   disable                          — disable (pause) driver filtering
    //   status                           — print driver status
    //   listen <api-url> <token>         — start pipe listener loop (daemon mode)

    if (argc < 2) {
        wprintf(L"Usage: AuthSecShieldBridge.exe <mode> [args]\n");
        wprintf(L"  set-paths <path1> ...   Push protected paths to kernel driver\n");
        wprintf(L"  enable                  Enable kernel interception\n");
        wprintf(L"  disable                 Disable kernel interception\n");
        wprintf(L"  status                  Print driver status\n");
        wprintf(L"  listen <url> <token>    Start decision listener loop\n");
        return 1;
    }

    const WCHAR* mode = argv[1];

    // Open driver control device
    g_hDevice = CreateFileW(DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (g_hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            LogMessage("ERROR", "Kernel driver not loaded. Install with: fltMC load AuthSecShield");
        } else {
            LogMessage("ERROR", "Cannot open driver device: %lu", err);
        }
        return 1;
    }

    int exitCode = 0;

    if (wcscmp(mode, L"set-paths") == 0) {
        const WCHAR** paths = (const WCHAR**)&argv[2];
        DWORD count = (DWORD)(argc - 2);
        if (!SendPathsToDriver(g_hDevice, paths, count)) {
            LogMessage("ERROR", "Failed to set protected paths");
            exitCode = 1;
        } else {
            LogMessage("OK", "Pushed %lu protected paths to kernel driver", count);
        }
    }
    else if (wcscmp(mode, L"enable") == 0) {
        SetDriverEnabled(g_hDevice, TRUE);
        LogMessage("OK", "Kernel driver enabled");
    }
    else if (wcscmp(mode, L"disable") == 0) {
        SetDriverEnabled(g_hDevice, FALSE);
        LogMessage("OK", "Kernel driver disabled");
    }
    else if (wcscmp(mode, L"status") == 0) {
        DWORD status = 0, returned = 0;
        if (DeviceIoControl(g_hDevice, IOCTL_SHIELD_GET_STATUS,
                            NULL, 0, &status, sizeof(status), &returned, NULL)) {
            LogMessage("STATUS", "Kernel driver: %s", status ? "ENABLED" : "DISABLED");
        } else {
            LogMessage("ERROR", "Failed to query driver status: %lu", GetLastError());
            exitCode = 1;
        }
    }
    else if (wcscmp(mode, L"listen") == 0) {
        if (argc < 4) {
            LogMessage("ERROR", "listen requires <api-url> <token>");
            exitCode = 1;
        } else {
            wcsncpy_s(g_AgentGuardURL, 1024, argv[2], _TRUNCATE);
            wcsncpy_s(g_AccessToken,   4096, argv[3], _TRUNCATE);
            LogMessage("INFO", "Starting kernel decision listener...");
            // Run in this thread — daemon mode
            PipeListenerThread(NULL);
        }
    }
    else {
        LogMessage("ERROR", "Unknown mode: %ls", mode);
        exitCode = 1;
    }

    CloseHandle(g_hDevice);
    return exitCode;
}

// ── Push protected paths into kernel driver ───────────────────────────────────
static BOOL SendPathsToDriver(HANDLE hDevice, const WCHAR** paths, DWORD count)
{
    // Build double-null-terminated wide string list
    // Format: L"path1\0path2\0\0"
    WCHAR buf[MAX_PROTECTED_PATHS * MAX_PATH_LEN] = {0};
    DWORD offset = 0;

    for (DWORD i = 0; i < count && i < MAX_PROTECTED_PATHS; i++) {
        size_t len = wcslen(paths[i]);
        if (offset + len + 1 >= sizeof(buf)/sizeof(WCHAR)) break;
        wcsncpy_s(buf + offset, sizeof(buf)/sizeof(WCHAR) - offset, paths[i], _TRUNCATE);
        offset += (DWORD)(len + 1);  // +1 for null terminator
    }
    // Double-null at end
    buf[offset] = L'\0';
    DWORD bufBytes = (offset + 1) * sizeof(WCHAR);

    DWORD returned = 0;
    return DeviceIoControl(hDevice, IOCTL_SHIELD_SET_PATHS,
                           buf, bufBytes, NULL, 0, &returned, NULL);
}

static BOOL SetDriverEnabled(HANDLE hDevice, BOOL enabled)
{
    DWORD code = enabled ? IOCTL_SHIELD_ENABLE : IOCTL_SHIELD_DISABLE;
    DWORD returned = 0;
    return DeviceIoControl(hDevice, code, NULL, 0, NULL, 0, &returned, NULL);
}

// ── Named pipe listener ───────────────────────────────────────────────────────
// The kernel driver writes SHIELD_REQUEST structs to the pipe when it needs a decision.
// We read them, call the API, write SHIELD_RESPONSE back.

static DWORD WINAPI PipeListenerThread(LPVOID param)
{
    (void)param;

    while (g_Running) {
        // Create the pipe server — kernel driver connects as client
        HANDLE hPipe = CreateNamedPipeW(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            sizeof(SHIELD_RESPONSE) * 16,
            sizeof(SHIELD_REQUEST)  * 16,
            5000,   // default timeout 5s
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            LogMessage("ERROR", "CreateNamedPipe failed: %lu", GetLastError());
            Sleep(1000);
            continue;
        }

        // Wait for a kernel connection
        if (!ConnectNamedPipe(hPipe, NULL)) {
            DWORD err = GetLastError();
            if (err != ERROR_PIPE_CONNECTED) {
                CloseHandle(hPipe);
                continue;
            }
        }

        // Read the request
        SHIELD_REQUEST req = {0};
        DWORD bytesRead = 0;
        if (!ReadFile(hPipe, &req, sizeof(req), &bytesRead, NULL) ||
            bytesRead != sizeof(req) ||
            req.Magic != REQUEST_MAGIC) {
            CloseHandle(hPipe);
            continue;
        }

        // Handle it
        HandleRequest(hPipe, &req);

        FlushFileBuffers(hPipe);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    return 0;
}

static BOOL HandleRequest(HANDLE hPipe, const SHIELD_REQUEST* req)
{
    LogMessage("PENDING", "PID=%lu process=%ls op=%lu path=%ls",
               req->ProcessId, req->ProcessName, req->Operation, req->FilePath);

    BOOL approved = FALSE;
    BOOL ok = CallAgentGuardAPI(req->FilePath, req->ProcessName, req->Operation, &approved);
    if (!ok) {
        // API error — default deny
        approved = FALSE;
        LogMessage("ERROR", "Agent Guard API call failed — defaulting to DENY");
    }

    LogMessage(approved ? "APPROVED" : "DENIED", "RequestId=%lu", req->RequestId);

    SHIELD_RESPONSE resp = {
        .Magic     = RESPONSE_MAGIC,
        .RequestId = req->RequestId,
        .Approved  = approved ? 1u : 0u
    };

    DWORD written = 0;
    return WriteFile(hPipe, &resp, sizeof(resp), &written, NULL) &&
           written == sizeof(resp);
}

// ── Agent Guard API call (WinHTTP) ────────────────────────────────────────────
// Calls POST /authsec/uflow/agent/actions/evaluate and polls /status
// Simplified synchronous implementation — in production use async I/O

#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

static BOOL CallAgentGuardAPI(const WCHAR* filePath, const WCHAR* processName,
                               DWORD operation, BOOL* approved)
{
    *approved = FALSE;

    if (wcslen(g_AgentGuardURL) == 0 || wcslen(g_AccessToken) == 0) {
        LogMessage("WARN", "No API URL or token configured — auto-denying");
        return TRUE; // known state, return success with deny
    }

    // Parse URL into host + path
    URL_COMPONENTS urlComp = {0};
    urlComp.dwStructSize      = sizeof(urlComp);
    WCHAR hostName[256] = {0};
    WCHAR urlPath[1024] = {0};
    urlComp.lpszHostName     = hostName;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath      = urlPath;
    urlComp.dwUrlPathLength  = 1024;

    if (!WinHttpCrackUrl(g_AgentGuardURL, 0, 0, &urlComp)) {
        LogMessage("ERROR", "Invalid API URL: %lu", GetLastError());
        return FALSE;
    }

    BOOL secure = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

    HINTERNET hSession = WinHttpOpen(
        L"AuthSecShieldBridge/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return FALSE;

    HINTERNET hConnect = WinHttpConnect(hSession, hostName, urlComp.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return FALSE; }

    // Build JSON body
    const char* opStr = "write";
    if (operation == 6) opStr = "delete";

    char jsonBody[4096];
    // Convert wide strings to UTF-8 for JSON
    char filePathA[MAX_PATH_LEN*2] = {0};
    char processA[520] = {0};
    WideCharToMultiByte(CP_UTF8, 0, filePath,    -1, filePathA, sizeof(filePathA)-1, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, processName, -1, processA,  sizeof(processA)-1,  NULL, NULL);

    int bodyLen = _snprintf_s(jsonBody, sizeof(jsonBody), _TRUNCATE,
        "{\"agent_id\":\"authsec-shield-kernel\","
        "\"agent_name\":\"AuthSec Agent Shield (Kernel)\","
        "\"agent_framework\":\"minifilter\","
        "\"action\":\"%s\","
        "\"resource\":\"%s\","
        "\"detail\":\"Kernel intercepted %s on %s\","
        "\"metadata\":{\"process\":\"%s\",\"pid\":%lu}}",
        opStr, filePathA, opStr, filePathA, processA, (unsigned long)GetCurrentProcessId());

    // POST to /authsec/uflow/agent/actions/evaluate
    WCHAR evalPath[1024];
    _snwprintf_s(evalPath, 1024, _TRUNCATE, L"%s/authsec/uflow/agent/actions/evaluate", urlPath);

    HINTERNET hReq = WinHttpOpenRequest(
        hConnect, L"POST", evalPath,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hReq) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return FALSE; }

    WCHAR authHeader[5000];
    _snwprintf_s(authHeader, 5000, _TRUNCATE, L"Authorization: Bearer %s", g_AccessToken);
    WinHttpAddRequestHeaders(hReq, authHeader, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
    WinHttpAddRequestHeaders(hReq, L"Content-Type: application/json",
                             (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    BOOL sent = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   jsonBody, bodyLen, bodyLen, 0);
    if (!sent || !WinHttpReceiveResponse(hReq, NULL)) {
        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Read response body to get action_req_id and status
    char respBuf[8192] = {0};
    DWORD totalRead = 0, bytesRead = 0;
    while (WinHttpReadData(hReq, respBuf + totalRead,
                           sizeof(respBuf) - totalRead - 1, &bytesRead) && bytesRead > 0) {
        totalRead += bytesRead;
        if (totalRead >= sizeof(respBuf) - 1) break;
    }

    WinHttpCloseHandle(hReq);

    // Parse status and action_req_id from JSON (minimal manual parsing)
    const char* statusPtr = strstr(respBuf, "\"status\":\"");
    if (statusPtr) {
        statusPtr += 10;
        if (strncmp(statusPtr, "auto_approved", 13) == 0) {
            *approved = TRUE;
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return TRUE;
        }
    }

    // Extract action_req_id for polling
    const char* reqIdPtr = strstr(respBuf, "\"action_req_id\":\"");
    if (!reqIdPtr) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }
    reqIdPtr += 17;
    char actionReqId[64] = {0};
    int i = 0;
    while (*reqIdPtr && *reqIdPtr != '"' && i < 63) {
        actionReqId[i++] = *reqIdPtr++;
    }

    // Poll /status every 5 seconds, up to 60 seconds
    LogMessage("INFO", "Waiting for approval (req_id=%s)...", actionReqId);

    WCHAR statusPath[1024];
    WCHAR actionReqIdW[64];
    MultiByteToWideChar(CP_UTF8, 0, actionReqId, -1, actionReqIdW, 64);
    _snwprintf_s(statusPath, 1024, _TRUNCATE,
                 L"%s/authsec/uflow/agent/actions/status?action_req_id=%s",
                 urlPath, actionReqIdW);

    for (int attempt = 0; attempt < 12; attempt++) {
        Sleep(5000);

        HINTERNET hPoll = WinHttpOpenRequest(
            hConnect, L"GET", statusPath, NULL,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            secure ? WINHTTP_FLAG_SECURE : 0);
        if (!hPoll) continue;

        WinHttpAddRequestHeaders(hPoll, authHeader, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
        if (!WinHttpSendRequest(hPoll, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) ||
            !WinHttpReceiveResponse(hPoll, NULL)) {
            WinHttpCloseHandle(hPoll);
            continue;
        }

        char pollBuf[2048] = {0};
        DWORD pRead = 0;
        WinHttpReadData(hPoll, pollBuf, sizeof(pollBuf)-1, &pRead);
        WinHttpCloseHandle(hPoll);

        const char* st = strstr(pollBuf, "\"status\":\"");
        if (!st) continue;
        st += 10;

        if (strncmp(st, "approved", 8) == 0 || strncmp(st, "auto_approved", 13) == 0) {
            *approved = TRUE;
            break;
        }
        if (strncmp(st, "denied", 6) == 0 ||
            strncmp(st, "expired", 7) == 0 ||
            strncmp(st, "timed_out", 9) == 0) {
            *approved = FALSE;
            break;
        }
        // Still pending — keep polling
    }

    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return TRUE;
}

// ── Logging ───────────────────────────────────────────────────────────────────
static void LogMessage(const char* level, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    printf("[shield-kernel] [%s] ", level);
    vprintf(fmt, args);
    printf("\n");
    fflush(stdout);
    va_end(args);
}
