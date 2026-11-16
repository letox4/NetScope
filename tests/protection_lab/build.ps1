# Compila todos los ejecutables de laboratorio (x64 y x86) con MSVC.
#   powershell -ExecutionPolicy Bypass -File tests\protection_lab\build.ps1
# Requiere Visual Studio 2022/2019 (C++ build tools) + Windows SDK.
param([string[]]$Arch = @('x64', 'x86'))
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$candidates = @(
    'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build',
    'C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build',
    'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build',
    'C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build')
$vc = $candidates | Where-Object { Test-Path "$_\vcvars64.bat" } | Select-Object -First 1
if (-not $vc) { throw 'No se encontró vcvars64.bat (instala MSVC build tools)' }

$sources = Get-ChildItem "$here\src\lab_*.c" | ForEach-Object { $_.BaseName }
New-Item -ItemType Directory -Force "$here\bin" | Out-Null
$failed = 0
foreach ($a in $Arch) {
    $vcvars = if ($a -eq 'x64') { 'vcvars64.bat' } else { 'vcvars32.bat' }
    New-Item -ItemType Directory -Force "$here\obj\$a" | Out-Null
    foreach ($s in $sources) {
        $extra = ''
        if ($s -eq 'lab_mitigated') { $extra = '/guard:cf /link /CETCOMPAT /DYNAMICBASE' }
        $cmd = "call `"$vc\$vcvars`" >nul && cl /nologo /O2 /W3 /MT /GS /std:c11 /Fo`"$here\obj\$a\\`" " +
               "/Fe`"$here\bin\${s}_$a.exe`" `"$here\src\$s.c`" $extra"
        $out = & $env:ComSpec /c $cmd 2>&1
        if ($LASTEXITCODE -ne 0) { Write-Host "FALLO $s ($a)`n$($out -join "`n")"; $failed++ }
        else { Write-Host "ok    $s ($a)" }
    }
}
Remove-Item "$here\obj" -Recurse -Force -ErrorAction SilentlyContinue
if ($failed) { exit 1 }
