#requires -Version 2.0
<#
.SYNOPSIS
    Ejecuta NightSpire-Hunter en varios servidores por WinRM y trae los informes.

.DESCRIPTION
    Para cada servidor: envia el script y los IOCs a C:\ProgramData\NightSpireHunter,
    ejecuta el escaneo y guarda el informe en .\resultados\<servidor>\.
    Con -Install ademas deja la tarea programada en cada servidor.

    Compatible con PowerShell 2.0 en ambos extremos (no usa Copy-Item -ToSession):
    los archivos viajan dentro de la propia sesion remota.
    Requiere WinRM habilitado en los destinos ("winrm quickconfig" o Enable-PSRemoting)
    y una cuenta administradora. En Server 2008 WinRM viene con WMF 2.0 (KB968930).

.EXAMPLE
    .\Invoke-RemoteScan.ps1 -ComputerName SRV-VEEAM01,SRV-DB02 -Credential (Get-Credential)
.EXAMPLE
    .\Invoke-RemoteScan.ps1 -ComputerName (Get-Content .\servidores.txt) -Mode Full -Install
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]]$ComputerName,
    [System.Management.Automation.PSCredential]$Credential,
    [ValidateSet('Quick', 'Full')][string]$Mode = 'Quick',
    [int]$DaysBack = 60,
    [switch]$Install,
    [int]$IntervalHours = 4,
    [string]$ResultDir
)
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ResultDir) { $ResultDir = Join-Path $Here 'resultados' }
New-Item -ItemType Directory -Path $ResultDir -Force | Out-Null

$payload = @{}
foreach ($f in @('NightSpire-Hunter.ps1', 'iocs.psd1', 'Install-ScheduledScan.ps1')) {
    $p = Join-Path $Here $f
    if (-not (Test-Path -LiteralPath $p)) { Write-Host "ERROR: falta $f junto a este script."; exit 1 }
    $payload[$f] = [System.IO.File]::ReadAllBytes($p)
}
# Opcional: IOCs y excepciones propios de la organizacion
$pLocal = Join-Path $Here 'iocs.local.psd1'
if (Test-Path -LiteralPath $pLocal) { $payload['iocs.local.psd1'] = [System.IO.File]::ReadAllBytes($pLocal) }

$remote = {
    param($Files, $Mode, $DaysBack, $DoInstall, $IntervalHours)
    $dir = Join-Path $env:ProgramData 'NightSpireHunter'
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $out = @{ PSVersion = [string]$PSVersionTable.PSVersion; InstallLog = ''; Code = -1; Report = ''; Csv = '' }

    # Archivos de IOCs: si el servidor ya tiene los suyos (quiza con excepciones propias) no se
    # pisan, salvo con -Install (el instalador guarda copia de los anteriores)
    foreach ($name in $Files.Keys) {
        $dst = Join-Path $dir $name
        if ($name -like 'iocs*.psd1' -and (Test-Path -LiteralPath $dst) -and -not $DoInstall) { continue }
        [System.IO.File]::WriteAllBytes($dst, [byte[]]$Files[$name])
    }
    if ($DoInstall) {
        $out.InstallLog = (& $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $dir 'Install-ScheduledScan.ps1') -IntervalHours $IntervalHours -DaysBack $DaysBack 2>&1 | Out-String)
    }
    & $ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $dir 'NightSpire-Hunter.ps1') -Mode $Mode -DaysBack $DaysBack -Quiet 2>&1 | Out-Null
    $out.Code = $LASTEXITCODE

    $last = Join-Path $dir ("reports\ULTIMO_{0}.txt" -f $env:COMPUTERNAME)
    if (Test-Path -LiteralPath $last) { $out.Report = [System.IO.File]::ReadAllText($last) }
    $runDir = Get-ChildItem -LiteralPath (Join-Path $dir 'reports') -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($runDir) {
        $csv = Join-Path $runDir.FullName 'hallazgos.csv'
        if (Test-Path -LiteralPath $csv) { $out.Csv = [System.IO.File]::ReadAllText($csv) }
    }
    return $out
}

$summary = @()
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
foreach ($c in $ComputerName) {
    Write-Host "=== $c ===" -ForegroundColor Cyan
    $estado = ''; $informe = ''; $psv = ''
    try {
        $ic = @{ ComputerName = $c; ScriptBlock = $remote; ErrorAction = 'Stop'
            ArgumentList = @($payload, $Mode, $DaysBack, [bool]$Install, $IntervalHours) }
        if ($Credential) { $ic['Credential'] = $Credential }
        $res = Invoke-Command @ic

        $dest = Join-Path $ResultDir $c
        if (-not (Test-Path -LiteralPath $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }
        $informe = Join-Path $dest "informe_$stamp.txt"
        [System.IO.File]::WriteAllText($informe, [string]$res.Report)
        if ($res.Csv) { [System.IO.File]::WriteAllText((Join-Path $dest "hallazgos_$stamp.csv"), [string]$res.Csv) }
        if ($res.InstallLog) { Write-Host ($res.InstallLog.TrimEnd()) }
        $psv = [string]$res.PSVersion
        switch ([int]$res.Code) {
            0 { $estado = 'Sin hallazgos relevantes' }
            1 { $estado = 'Hallazgos MEDIOS' }
            2 { $estado = 'Hallazgos ALTOS/CRITICOS' }
            default { $estado = "Error del escaner (codigo $($res.Code))" }
        }
        Write-Host "  $estado  (PowerShell $psv)  ->  $informe"
    } catch {
        $estado = "ERROR: $($_.Exception.Message)"
        Write-Host "  $estado" -ForegroundColor Red
    }
    $summary += New-Object PSObject -Property @{ Equipo = $c; Resultado = $estado; PowerShell = $psv; Informe = $informe }
}
$summary | Select-Object Equipo, Resultado, PowerShell, Informe | Format-Table -AutoSize -Wrap
$summary | Select-Object Equipo, Resultado, PowerShell, Informe | Export-Csv -Path (Join-Path $ResultDir "resumen_$stamp.csv") -NoTypeInformation -Encoding UTF8
