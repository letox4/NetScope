# Revierte la configuración de EAF de eaf_enable.ps1 (requiere elevación).
$ErrorActionPreference = 'Stop'
$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Se necesita una consola elevada (Administrador).'
}
foreach ($arch in 'x64', 'x86') {
    $img = "lab_guard_$arch.exe"
    Set-ProcessMitigation -Name $img -Remove
    Write-Host "Configuración de Exploit Protection eliminada para $img"
}
