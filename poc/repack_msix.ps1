$ErrorActionPreference='Continue'
$src='C:\squat_test\release_v3_ZeroAdmin_SYSTEM\src'
$mk='C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86\makeappx.exe'
$layout="$src\lay2"
if(Test-Path $layout){ Remove-Item $layout -Recurse -Force }
& $mk unpack /p "$src\codechost.msix" /d $layout /o /nv | Out-Null
Copy-Item "$src\proof.dll" "$layout\proof.dll" -Force
Copy-Item "$src\syslaunch.exe" "$layout\syslaunch.exe" -Force
Remove-Item -LiteralPath "$layout\AppxBlockMap.xml" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$layout\[Content_Types].xml" -Force -ErrorAction SilentlyContinue
& $mk pack /d $layout /p "$src\codechost.msix" /o /nv 2>&1 | Select-Object -Last 2
& $mk unpack /p "$src\codechost.msix" /d "$src\vlay" /o /nv | Out-Null
Write-Host "=== packaged files ==="
Get-ChildItem "$src\vlay" | Select-Object Name,Length | Format-Table -AutoSize | Out-String | Write-Host
Remove-Item "$src\vlay" -Recurse -Force
Remove-Item $layout -Recurse -Force
Write-Host ("final msix: " + [math]::Round((Get-Item "$src\codechost.msix").Length/1KB,1) + "KB")
