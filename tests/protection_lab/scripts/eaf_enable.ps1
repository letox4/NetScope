# Configura EAF (Export Address Filtering) REAL para los laboratorios mediante el
# mecanismo oficial de Windows (Exploit Protection). REQUIERE ELEVACIÓN: escribe en
# HKLM\...\Image File Execution Options.
#
#   Start-Process powershell -Verb RunAs -ArgumentList '-File', '<ruta>\eaf_enable.ps1'
#
# Después: py -3.11 tests\protection_lab\run_matrix.py --scenarios eaf_real
# Revertir: scripts\eaf_disable.ps1
$ErrorActionPreference = 'Stop'
$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Se necesita una consola elevada (Administrador): Set-ProcessMitigation escribe en IFEO (HKLM).'
}
foreach ($arch in 'x64', 'x86') {
    $img = "lab_guard_$arch.exe"
    Set-ProcessMitigation -Name $img -Enable EnableExportAddressFilter
    Write-Host "EAF activado para $img"
    (Get-ProcessMitigation -Name $img).Payload | Select-Object EnableExportAddressFilter, EnableExportAddressFilterPlus | Format-List
}
