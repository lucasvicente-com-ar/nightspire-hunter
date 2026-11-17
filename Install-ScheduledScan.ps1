#requires -Version 2.0
<#
.SYNOPSIS
    Instala NightSpire-Hunter en el servidor y lo deja corriendo como tarea programada (SYSTEM).

.DESCRIPTION
    Compatible con PowerShell 2.0 en adelante (Windows Server 2008 con WMF 2.0, 2008 R2, 2016...).
    - Copia NightSpire-Hunter.ps1, iocs.psd1 e iocs.local.psd1 (si existe) a C:\ProgramData\NightSpireHunter
    - Restringe esa carpeta a SYSTEM y Administradores (la tarea corre como SYSTEM: nadie
      mas debe poder modificar el script)
    - Crea dos tareas (con schtasks.exe, presente en todas las versiones):
        NightSpireHunter-Quick : cada N horas (por defecto 4), modo Quick
        NightSpireHunter-Full  : semanal (domingo 03:00), modo Full
    - Opcionalmente crea archivos canario y hace una primera ejecucion.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-ScheduledScan.ps1
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-ScheduledScan.ps1 -IntervalHours 1 -Canary -ExtraPath "D:\Datos;E:\Compartido"
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-ScheduledScan.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 23)][int]$IntervalHours = 4,
    [int]$DaysBack = 60,
    [string]$ExtraPath,          # varias carpetas separadas por ';'
    [string]$CentralShare,
    [switch]$Canary,
    [switch]$NoFullWeekly,
    [switch]$RunNow,
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$InstallDir = Join-Path $env:ProgramData 'NightSpireHunter'
$TaskQuick = 'NightSpireHunter-Quick'
$TaskFull = 'NightSpireHunter-Full'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$PsExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'ERROR: ejecutar desde una consola de PowerShell como Administrador.'; exit 1 }

if ($Uninstall) {
    foreach ($t in @($TaskQuick, $TaskFull)) {
        & schtasks.exe /Delete /TN $t /F 2>&1 | Out-Null
        Write-Host "Tarea eliminada (si existia): $t"
    }
    Write-Host "Los informes y el script quedan en $InstallDir. Borrar esa carpeta a mano si ya no se necesitan."
    exit 0
}

foreach ($f in @('NightSpire-Hunter.ps1', 'iocs.psd1')) {
    if (-not (Test-Path -LiteralPath (Join-Path $Here $f))) { Write-Host "ERROR: falta $f junto a este instalador."; exit 1 }
}
if (-not (Test-Path -LiteralPath $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }

# Solo SYSTEM (S-1-5-18) y Administradores (S-1-5-32-544). Se aplica ANTES de copiar el script.
& icacls.exe $InstallDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "AVISO: no se pudieron restringir los permisos de $InstallDir (icacls devolvio $LASTEXITCODE). Revisarlos a mano." }

$sameDir = ($Here.TrimEnd('\') -ieq $InstallDir.TrimEnd('\'))
if (-not $sameDir) {
    Copy-Item -LiteralPath (Join-Path $Here 'NightSpire-Hunter.ps1') -Destination $InstallDir -Force
    # Antes de reemplazar los archivos de IOCs se guarda copia de los que ya estaban
    $stampIoc = Get-Date -Format 'yyyyMMdd_HHmmss'
    foreach ($iocName in @('iocs.psd1', 'iocs.local.psd1')) {
        $srcIoc = Join-Path $Here $iocName
        if (-not (Test-Path -LiteralPath $srcIoc)) { continue }   # iocs.local.psd1 es opcional
        $dstIoc = Join-Path $InstallDir $iocName
        if (Test-Path -LiteralPath $dstIoc) {
            $bak = Join-Path $InstallDir ("{0}.anterior_{1}.psd1" -f [System.IO.Path]::GetFileNameWithoutExtension($iocName), $stampIoc)
            Copy-Item -LiteralPath $dstIoc -Destination $bak -Force
        }
        Copy-Item -LiteralPath $srcIoc -Destination $dstIoc -Force
    }
}
if (Get-Command Unblock-File -ErrorAction SilentlyContinue) {   # PowerShell 3+
    Get-ChildItem -LiteralPath $InstallDir | Where-Object { -not $_.PSIsContainer } | Unblock-File -ErrorAction SilentlyContinue
}
Write-Host "Instalado en $InstallDir (acceso restringido a SYSTEM y Administradores)"

# Cada tarea llama a un .cmd propio: evita el limite de 261 caracteres de schtasks /TR
# y los problemas de comillas en Windows Server 2008.
$extra = "-Quiet -DaysBack $DaysBack"
if ($ExtraPath) { $extra += " -Path `"$ExtraPath`"" }
if ($CentralShare) { $extra += " -CentralShare `"$CentralShare`"" }
function New-Runner([string]$Mode) {
    $file = Join-Path $InstallDir ("run-{0}.cmd" -f $Mode.ToLower())
    $lines = @(
        '@echo off',
        ('"{0}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0NightSpire-Hunter.ps1" -Mode {1} {2}' -f $PsExe, $Mode, $extra),
        'exit /b %ERRORLEVEL%'
    )
    $lines | Set-Content -LiteralPath $file -Encoding ASCII
    return $file
}

$runQuick = New-Runner 'Quick'
& schtasks.exe /Create /TN $TaskQuick /TR $runQuick /SC HOURLY /MO $IntervalHours /RU SYSTEM /RL HIGHEST /F | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: no se pudo crear la tarea $TaskQuick"; exit 1 }
Write-Host "Tarea creada: $TaskQuick (cada $IntervalHours h, modo Quick)"

if (-not $NoFullWeekly) {
    $runFull = New-Runner 'Full'
    & schtasks.exe /Create /TN $TaskFull /TR $runFull /SC WEEKLY /D SUN /ST 03:00 /RU SYSTEM /RL HIGHEST /F | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: no se pudo crear la tarea $TaskFull"; exit 1 }
    Write-Host "Tarea creada: $TaskFull (domingos 03:00, modo Full)"
}

$script = Join-Path $InstallDir 'NightSpire-Hunter.ps1'
if ($Canary) {
    Write-Host 'Creando archivos canario y linea base (puede tardar unos minutos)...'
    & $PsExe -NoProfile -ExecutionPolicy Bypass -File $script -Mode Quick -DaysBack $DaysBack -InitCanary -Quiet
    Write-Host "Primera ejecucion terminada (codigo $LASTEXITCODE)."
} elseif ($RunNow) {
    & schtasks.exe /Run /TN $TaskQuick | Out-Null
    Write-Host 'Primera ejecucion lanzada en segundo plano.'
}

Write-Host ''
Write-Host "Informes:        $InstallDir\reports\ULTIMO_$($env:COMPUTERNAME).txt"
Write-Host "Historial:       $InstallDir\reports\historial.csv"
Write-Host 'Alertas (SIEM):  registro Aplicacion, origen NightSpireHunter, evento 9002 = hallazgos altos/criticos NUEVOS'
exit 0
