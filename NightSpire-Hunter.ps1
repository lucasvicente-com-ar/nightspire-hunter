#requires -Version 2.0
<#
.SYNOPSIS
    NightSpire-Hunter: busca rastros del ransomware NightSpire en un servidor Windows.

.DESCRIPTION
    Herramienta defensiva de SOLO LECTURA (lo unico que escribe son sus propios informes,
    su archivo de estado y, si se pide, archivos canario). Busca:
      - archivos cifrados (.nspire / .0nspire) y notas de rescate
      - herramientas usadas por NightSpire (AnyDesk, Chrome Remote Desktop, Everything,
        MEGAcmd/MEGAsync, WinSCP, Rclone, Mimikatz, PsExec, Advanced IP Scanner, enc.exe...)
      - hashes conocidos del cifrador
      - persistencia (servicios, tareas, claves Run, IFEO, carpetas de inicio)
      - registros de eventos: borrado de logs, cuentas nuevas, RDP sospechoso, fuerza bruta,
        servicios instalados, Defender deshabilitado, comandos sospechosos
      - red: conexiones y cache DNS hacia infraestructura conocida
    Pensada para ejecutarse periodicamente: recuerda lo ya visto y marca lo NUEVO.

    COMPATIBILIDAD: PowerShell 2.0 en adelante (Windows Server 2008 SP2 con WMF 2.0,
    2008 R2, 2012, 2016, 2019, 2022). No usa nada posterior a PowerShell 2.0 / .NET 2.0
    salvo dentro de bloques con alternativa.

.PARAMETER Mode
    Quick (por defecto): perfiles de usuario, ProgramData, temporales y 2 niveles de cada disco.
    Full: todos los discos fijos completos (lento; usar semanalmente).

.PARAMETER DaysBack
    Dias hacia atras para registros de eventos y archivos "recientes". Por defecto 60.

.PARAMETER Path
    Carpetas adicionales a recorrer completas (por ejemplo, recursos compartidos de datos).

.PARAMETER PathOnly
    Recorre solo las carpetas indicadas en -Path (no los discos).

.PARAMETER InitCanary
    Crea archivos canario en las carpetas de "CanaryDirs" (iocs.psd1). En cada ejecucion
    posterior se verifica que sigan intactos; si cambian o desaparecen => alerta critica.

.PARAMETER CentralShare
    Ruta UNC donde copiar cada informe (se crea una subcarpeta por servidor).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\NightSpire-Hunter.ps1
.EXAMPLE
    .\NightSpire-Hunter.ps1 -Mode Full -DaysBack 90 -Path D:\Datos,E:\Compartido

.NOTES
    Ejecutar como Administrador (sin privilegios no se leen Security, Prefetch ni otros perfiles).
    Codigos de salida: 0 = sin hallazgos relevantes, 1 = hallazgos medios, 2 = altos o criticos.
#>
[CmdletBinding()]
param(
    [ValidateSet('Quick', 'Full')][string]$Mode = 'Quick',
    [int]$DaysBack = 60,
    [string[]]$Path,
    [switch]$PathOnly,
    [string]$IocFile,
    [string]$DataDir = (Join-Path $env:ProgramData 'NightSpireHunter'),
    [string]$OutputDir,
    [string]$CentralShare,
    [switch]$InitCanary,
    [switch]$SkipFileScan,
    [switch]$SkipEventLogs,
    [int]$MaxHashMB = 200,
    [switch]$Quiet,
    [switch]$ForceWevtutil      # leer eventos con wevtutil.exe aunque Get-WinEvent funcione (para pruebas)
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$ScriptVersion = '1.3'
$SelfMarker = 'NSH-SELF-7f3a1c'   # para excluirse a si mismo de los registros de PowerShell
$RunStart = Get-Date
$Since = $RunStart.AddDays(-$DaysBack)
$HostName = $env:COMPUTERNAME
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PSMajor = $PSVersionTable.PSVersion.Major
# -Path admite varias carpetas separadas por ';' (necesario al llamar con -File o desde el .cmd)
if ($Path) { $Path = @($Path | ForEach-Object { ([string]$_).Split(';') } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }

# PowerShell 2.0: Get-WinEvent devuelve el mensaje vacio si la cultura no es en-US
if ($PSMajor -lt 3) {
    try { [System.Threading.Thread]::CurrentThread.CurrentCulture = New-Object System.Globalization.CultureInfo 'en-US' } catch { }
}

$script:Findings = New-Object System.Collections.ArrayList
$script:Notes = New-Object System.Collections.ArrayList
$script:Suppressed = 0
$script:KeysThisRun = @{}
$SevRank = @{ Critical = 4; High = 3; Medium = 2; Low = 1; Info = 0 }

# ----------------------------------------------------------------------------
# Utilidades
# ----------------------------------------------------------------------------
function Write-Log([string]$Msg) {
    if (-not $Quiet) { Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Msg) }
}
function Add-Note([string]$Msg) { if (-not $script:Notes.Contains($Msg)) { [void]$script:Notes.Add($Msg) } }
function New-Obj([hashtable]$Props) { New-Object PSObject -Property $Props }
function Test-Cmd([string]$Name) { return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

function ConvertTo-RxBody([string]$Wild) {
    [regex]::Escape($Wild).Replace('\*', '.*').Replace('\?', '.')
}
function New-WildRegex($Wilds) {
    $list = @($Wilds | Where-Object { $_ })
    if ($list.Count -eq 0) { return $null }
    $body = @($list | ForEach-Object { ConvertTo-RxBody $_ }) -join '|'
    New-Object regex ("^(?:$body)$"), 'IgnoreCase'
}
function New-KeywordRegex($Words) {
    $list = @($Words | Where-Object { $_ })
    if ($list.Count -eq 0) { return $null }
    New-Object regex (@($list | ForEach-Object { [regex]::Escape($_) }) -join '|'), 'IgnoreCase'
}
function Test-Rx($Rx, [string]$Text) {
    if ($null -eq $Rx -or -not $Text) { return $false }
    return $Rx.IsMatch($Text)
}

function Add-Finding {
    param([string]$Severity, [string]$Category, [string]$Title, [string]$Detail,
        [string]$Path, $When, [string]$Key)
    if (-not $Key) { $Key = "$Category|$Title|$Path" }
    if ($script:KeysThisRun.ContainsKey($Key)) { return }
    $script:KeysThisRun[$Key] = 1
    if ((Test-Rx $script:RxAllow $Key) -or (Test-Rx $script:RxAllow $Path)) { $script:Suppressed++; return }
    $whenStr = ''
    if ($When -is [datetime]) { $whenStr = $When.ToString('yyyy-MM-dd HH:mm:ss') } elseif ($When) { $whenStr = [string]$When }
    [void]$script:Findings.Add((New-Obj @{
                Host = $HostName; Severity = $Severity; Category = $Category; Title = $Title
                Detail = $Detail; Path = $Path; EvidenceTime = $whenStr; Key = $Key; IsNew = $true
            }))
}

function Get-Sha256([string]$File) {
    try {
        $sha = $null
        try { $sha = [System.Security.Cryptography.SHA256]::Create() } catch { }
        if ($null -eq $sha) { $sha = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider }   # equipos con FIPS
        $fs = [System.IO.File]::Open($File, 'Open', 'Read', 'ReadWrite')
        try { return ([BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-', '').ToLower() }
        finally { $fs.Close() }
    } catch { return $null }
}

function ConvertTo-IpNum([string]$Ip) {
    $a = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$a)) { return $null }
    if ([string]$a.AddressFamily -ne 'InterNetwork') { return $null }
    $b = $a.GetAddressBytes()
    return ([double]$b[0] * 16777216) + ([double]$b[1] * 65536) + ([double]$b[2] * 256) + [double]$b[3]
}
function ConvertTo-Range([string]$Cidr) {
    $p = $Cidr.Split('/')
    $n = ConvertTo-IpNum $p[0]
    if ($null -eq $n) { return $null }
    $bits = 32; if ($p.Length -gt 1) { $bits = [int]$p[1] }
    $size = [math]::Pow(2, 32 - $bits)
    $start = [math]::Floor($n / $size) * $size
    return @{ Start = [double]$start; End = [double]($start + $size - 1); Text = $Cidr }
}
function Test-InRanges($Num, $Ranges) {
    foreach ($r in @($Ranges)) { if ($r -and $Num -ge $r.Start -and $Num -le $r.End) { return $true } }
    return $false
}
# Devuelve IOC / WATCH / PUBLIC / PRIVATE / '' para una IP
function Get-IpClass([string]$Ip) {
    if (-not $Ip) { return '' }
    $Ip = $Ip.Trim() -replace '^::ffff:', ''
    if (@('-', '::1', '127.0.0.1', 'LOCAL') -contains $Ip) { return '' }
    $n = ConvertTo-IpNum $Ip
    if ($null -eq $n) { return '' }
    if (Test-InRanges $n $script:IocRanges) { return 'IOC' }
    if (Test-InRanges $n $script:WatchRanges) { return 'WATCH' }
    if (Test-InRanges $n $script:PrivRanges) { return 'PRIVATE' }
    return 'PUBLIC'
}

# --- Lectura de eventos -------------------------------------------------------
# Via 1: Get-WinEvent (necesita .NET 3.5; no esta en Server 2008 sin R2 de fabrica).
# Via 2: wevtutil.exe (viene con Windows desde Vista/2008; sin dependencias).
$script:UseWevt = $false
function Initialize-EventReader {
    if ($ForceWevtutil) { $script:UseWevt = $true; return }
    if (-not (Test-Cmd 'Get-WinEvent')) { $script:UseWevt = $true; return }
    try { Get-WinEvent -ListLog 'Application' -ErrorAction Stop | Out-Null } catch { $script:UseWevt = $true }
}
$script:LogNames = $null
function Get-LogNames([string]$Pattern) {
    if ($script:UseWevt) {
        if ($null -eq $script:LogNames) { $script:LogNames = @(& wevtutil.exe el 2>$null) }
        return @($script:LogNames | Where-Object { $_ -like $Pattern })
    }
    try { return @(Get-WinEvent -ListLog $Pattern -ErrorAction Stop | ForEach-Object { $_.LogName }) } catch { return @() }
}
function Test-Log([string]$Name) { return (@(Get-LogNames $Name).Count -gt 0) }

function ConvertFrom-WevtXml([string[]]$Lines) {
    $res = New-Object System.Collections.ArrayList
    if (-not $Lines -or $Lines.Length -eq 0) { return @() }
    $doc = New-Object System.Xml.XmlDocument
    try { $doc.LoadXml('<r>' + ($Lines -join "`n") + '</r>') } catch { return @() }
    foreach ($ev in @($doc.DocumentElement.ChildNodes)) {
        if (-not $ev -or $ev.LocalName -ne 'Event') { continue }
        $id = 0; $time = [datetime]::MinValue; $msg = ''; $props = @()
        foreach ($n in @($ev.ChildNodes)) {
            if ($n.LocalName -eq 'System') {
                foreach ($c in @($n.ChildNodes)) {
                    if ($c.LocalName -eq 'EventID') { [void][int]::TryParse($c.InnerText, [ref]$id) }
                    elseif ($c.LocalName -eq 'TimeCreated') {
                        try { $time = [datetime]::Parse($c.GetAttribute('SystemTime'), [System.Globalization.CultureInfo]::InvariantCulture) } catch { }
                    }
                }
            } elseif ($n.LocalName -eq 'EventData') {
                foreach ($c in @($n.ChildNodes)) { if ($c.LocalName -eq 'Data') { $props += (New-Obj @{ Value = [string]$c.InnerText }) } }
            } elseif ($n.LocalName -eq 'RenderingInfo') {
                foreach ($c in @($n.ChildNodes)) { if ($c.LocalName -eq 'Message') { $msg = [string]$c.InnerText } }
            }
        }
        $o = New-Obj @{ Id = $id; TimeCreated = $time; Message = $msg; Properties = $props; RawXml = $ev.OuterXml }
        $o | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.RawXml } -Force
        [void]$res.Add($o)
    }
    return @($res.ToArray())
}

# Siempre usar como @(Get-Ev ...): en PowerShell 2.0 un resultado vacio se vuelve $null
function Get-Ev {
    param([string]$Log, [int[]]$Ids, [int]$Max = 5000, [string]$XPath)
    if ($script:UseWevt) {
        if (-not $XPath) {
            $ms = [int64]$DaysBack * 86400000
            $cond = "TimeCreated[timediff(@SystemTime) <= $ms]"
            if ($Ids -and $Ids.Length -gt 0) { $cond = '(' + (@($Ids | ForEach-Object { "EventID=$_" }) -join ' or ') + ') and ' + $cond }
            $XPath = "*[System[$cond]]"
        }
        $raw = @(& wevtutil.exe qe $Log "/q:$XPath" /f:RenderedXml "/c:$Max" /rd:true 2>&1)
        if ($LASTEXITCODE -ne 0) {
            $m = Limit-Text (($raw | ForEach-Object { [string]$_ }) -join ' ') 110
            Add-Note ("No se pudo leer el registro '{0}' (wevtutil): {1}" -f $Log, $m)
            return @()
        }
        return @(ConvertFrom-WevtXml @($raw | ForEach-Object { [string]$_ }))
    }
    try {
        if ($XPath) { return @(Get-WinEvent -LogName $Log -FilterXPath $XPath -MaxEvents $Max -ErrorAction Stop) }
        $fh = @{ LogName = $Log; StartTime = $Since }
        if ($Ids -and $Ids.Length -gt 0) { $fh['Id'] = $Ids }
        return @(Get-WinEvent -FilterHashtable $fh -MaxEvents $Max -ErrorAction Stop)
    } catch {
        $id = [string]$_.FullyQualifiedErrorId
        if ($id -notlike 'NoMatchingEventsFound*') {
            $m = [string]$_.Exception.Message
            if ($m.Length -gt 110) { $m = $m.Substring(0, 110) }
            Add-Note ("No se pudo leer el registro '{0}': {1}" -f $Log, $m)
        }
        return @()
    }
}
function Get-EvData($Ev) {
    $h = @{}
    try {
        $x = [xml]$Ev.ToXml()
        foreach ($d in @($x.Event.EventData.Data)) { if ($d -and $d.Name) { $h[$d.Name] = [string]$d.'#text' } }
    } catch { }
    return $h
}
function Get-Prop($Ev, [int]$Index) {
    try { if ($Ev.Properties.Count -gt $Index) { return [string]$Ev.Properties[$Index].Value } } catch { }
    return ''
}
function Limit-Text([string]$s, [int]$n = 300) {
    if (-not $s) { return '' }
    $s = ($s -replace '\s+', ' ').Trim()
    if ($s.Length -gt $n) { return $s.Substring(0, $n) + '...' }
    return $s
}
function ConvertFrom-WmiDate($d) {
    if ($d -is [datetime]) { return $d }
    try { return [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$d) } catch { return $null }
}
function Get-SubDirs([string]$Dir) {
    @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer })
}

# ----------------------------------------------------------------------------
# Carga de IOCs y estado
# ----------------------------------------------------------------------------
function Import-IocData([string]$File) {
    $data = $null
    try {
        # Lectura segura (modo de datos restringido: el archivo no puede ejecutar codigo)
        Import-LocalizedData -BindingVariable data -BaseDirectory (Split-Path -Parent $File) -FileName (Split-Path -Leaf $File) -ErrorAction Stop
    } catch {
        $loadErr = $_.Exception.Message
        try {
            # Misma garantia por otra via: se valida que el archivo solo contenga datos antes de evaluarlo
            $sbIoc = [scriptblock]::Create([System.IO.File]::ReadAllText($File))
            $sbIoc.CheckRestrictedLanguage([string[]]@(), [string[]]@(), $false)
            $data = & $sbIoc
        } catch { $loadErr = "$loadErr / $($_.Exception.Message)"; $data = $null }
        if ($null -eq $data) { Write-Error "No se pudo leer ${File}: $loadErr"; exit 3 }
    }
    if (-not ($data -is [hashtable])) { Write-Error "El archivo de IOCs esta vacio o mal formado: $File"; exit 3 }
    return $data
}

if (-not $IocFile) { $IocFile = Join-Path $ScriptDir 'iocs.psd1' }
if (-not (Test-Path -LiteralPath $IocFile)) { Write-Error "No se encuentra el archivo de IOCs: $IocFile"; exit 3 }
$Ioc = Import-IocData $IocFile
if (-not $Ioc.EncryptedExtensions) { Write-Error "El archivo de IOCs esta vacio o mal formado: $IocFile"; exit 3 }

# iocs.local.psd1 (opcional, junto a iocs.psd1): indicadores y excepciones propios de la
# organizacion que no se publican. Las listas se suman, las tablas (Sha256) se combinan y
# los valores simples reemplazan a los de iocs.psd1.
$IocLocalFile = Join-Path (Split-Path -Parent $IocFile) 'iocs.local.psd1'
$IocLocalLoaded = $false
if (Test-Path -LiteralPath $IocLocalFile) {
    $loc = Import-IocData $IocLocalFile
    foreach ($k in @($loc.Keys)) {
        if ($k -eq 'Version') { continue }
        $v = $loc[$k]
        if ($v -is [hashtable] -and $Ioc[$k] -is [hashtable]) {
            foreach ($hk in @($v.Keys)) { $Ioc[$k][$hk] = $v[$hk] }
        } elseif ($v -is [array] -or $Ioc[$k] -is [array]) {
            $Ioc[$k] = @(@($Ioc[$k]) + @($v) | Where-Object { $null -ne $_ })
        } else {
            $Ioc[$k] = $v
        }
    }
    $IocLocalLoaded = $true
}

$IsAdmin = $false
try {
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }
if (-not $IsAdmin) { Add-Note 'SIN PRIVILEGIOS DE ADMINISTRADOR: resultado parcial (no se leen Security, Prefetch ni perfiles ajenos).' }

try { if (-not (Test-Path -LiteralPath $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force -ErrorAction Stop | Out-Null } }
catch { $DataDir = Join-Path $env:TEMP 'NightSpireHunter'; New-Item -ItemType Directory -Path $DataDir -Force | Out-Null; Add-Note "No se pudo usar ProgramData; datos en $DataDir" }
if (-not $OutputDir) { $OutputDir = Join-Path $DataDir 'reports' }
$RunDir = Join-Path $OutputDir ("{0}_{1}" -f $HostName, $RunStart.ToString('yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $RunDir -Force | Out-Null

$StateFile = Join-Path $DataDir 'state.xml'
$State = $null
if (Test-Path -LiteralPath $StateFile) { try { $State = Import-Clixml -Path $StateFile } catch { } }
$Seen = @{}
if ($State -and $State.SeenKeys) { foreach ($k in @($State.SeenKeys)) { if ($k) { $Seen[[string]$k] = 1 } } }
$FirstRun = ($null -eq $State)

$script:RxAllow = New-WildRegex $Ioc.Allowlist
$RxEncExt = New-Object regex (('(?:' + (@($Ioc.EncryptedExtensions | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')$'), 'IgnoreCase')
$RxNote = New-WildRegex (@($Ioc.RansomNoteNames) + @($Ioc.RansomNoteWildcards))
$RxGenericNote = New-WildRegex $Ioc.GenericNoteNames
$RxMarkers = New-KeywordRegex $Ioc.NoteContentMarkers
$RxToolFile = New-WildRegex @($Ioc.Tools | ForEach-Object { $_.Pattern })
$ToolDefs = @($Ioc.Tools | ForEach-Object { New-Obj @{ Rx = (New-WildRegex @($_.Pattern)); Def = $_ } })
$RxToolStr = New-KeywordRegex $Ioc.ToolKeywords
$RxSoftware = New-WildRegex $Ioc.SoftwareNames
$RxService = New-WildRegex $Ioc.ServiceNames
$RxEmails = New-KeywordRegex $Ioc.Emails
$HashIoc = @{}
if ($Ioc.Sha256) { foreach ($k in @($Ioc.Sha256.Keys)) { $HashIoc[([string]$k).ToLower()] = [string]$Ioc.Sha256[$k] } }

$script:IocRanges = @(); foreach ($i in (@($Ioc.IPs) + @($Ioc.Cidrs))) { if ($i) { $r = ConvertTo-Range $i; if ($r) { $script:IocRanges += $r } } }
$script:WatchRanges = @(); foreach ($i in @($Ioc.WatchRanges)) { if ($i) { $r = ConvertTo-Range $i; if ($r) { $script:WatchRanges += $r } } }
$script:PrivRanges = @(); foreach ($i in @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '127.0.0.0/8', '100.64.0.0/10')) { $script:PrivRanges += (ConvertTo-Range $i) }

# Todo lo que coincide por nombre de archivo, en una sola expresion (rapida)
$anyBody = @('.*' + $RxEncExt.ToString())
foreach ($w in (@($Ioc.RansomNoteNames) + @($Ioc.RansomNoteWildcards) + @($Ioc.GenericNoteNames) + @($Ioc.Tools | ForEach-Object { $_.Pattern }))) { if ($w) { $anyBody += (ConvertTo-RxBody $w) } }
$RxAnyName = New-Object regex ('^(?:' + ($anyBody -join '|') + ')$'), 'IgnoreCase'

$RxStaging = New-Object regex '\\(Downloads|Descargas|Desktop|Escritorio|Temp|Tmp|PerfLogs|Public|Music|Videos|Pictures)$|\\(Windows\\Temp|ProgramData)$|^[A-Za-z]:\\$', 'IgnoreCase'
$RxSkipDir = New-Object regex '\\Windows\\(WinSxS|servicing|assembly|Installer|SoftwareDistribution)$|\\System Volume Information$|\\node_modules$|\\\.git$|\\AppData\\Local\\(Packages|Microsoft\\Windows\\(INetCache|WebCache))$|\\User Data\\[^\\]+\\(Cache|Code Cache|Service Worker)$', 'IgnoreCase'
$RxArchive = New-Object regex '\.(7z|zip|rar|tar|gz|tgz)$', 'IgnoreCase'
$RxSuspHigh = New-Object regex '\\Users\\Public\\|\\Temp\\|\\Tmp\\|\\PerfLogs\\|powershell[^|]*\s-(e|en|enc|enco\w*)\s|-w(indowstyle)?\s+h|mshta|certutil[^|]*(urlcache|-decode)|bitsadmin[^|]*transfer|%COMSPEC%|ADMIN\$|\\\\127\.0\.0\.1\\', 'IgnoreCase'
$RxSuspLow = New-Object regex '\\AppData\\|\\Downloads\\|\\Desktop\\|\\ProgramData\\[^\\"]+\.(exe|bat|cmd|ps1|vbs|js)|^"?[A-Za-z]:\\[^\\"]+\.(exe|bat|cmd|ps1|vbs)', 'IgnoreCase'
$RxCmd = New-Object regex ('sekurlsa|lsadump|mimikatz|procdump[^|\r\n]{0,200}lsass|comsvcs[^|\r\n]{0,200}MiniDump|vssadmin(\.exe)?"?\s+delete|wbadmin(\.exe)?"?\s+delete|' +
    'wevtutil(\.exe)?"?\s+(cl|clear-log)\s|Clear-EventLog\s+-|bcdedit[^|\r\n]{0,200}recoveryenabled|mega-(put|login|sync|export)\s|megaclient|' +
    'rclone(\.exe)?"?\s+(copy|sync|move|config)\s|winscp[^|\r\n]{0,200}(/command|/script)|Set-MpPreference\s[^|\r\n]{0,200}-(Disable\w+|Exclusion\w+)\s|Add-MpPreference\s[^|\r\n]{0,200}-Exclusion\w+\s|' +
    'DisableAntiSpyware[^|\r\n]{0,40}(/d\s+1|=\s*1)|net1?(\.exe)?"?\s+user\s+\S+\s+\S+\s+/add|net1?(\.exe)?"?\s+localgroup\s+admin\w+\s+\S+\s+/add|' +
    'advanced_ip_scanner|Get-VBRCredentials|Remove-VBR(Backup|Job|RestorePoint)\s|\.nspire\b|nightspire'), 'IgnoreCase'

Write-Log "NightSpire-Hunter v$ScriptVersion en $HostName | PowerShell $($PSVersionTable.PSVersion) | modo $Mode | ventana $DaysBack dias | admin: $IsAdmin"

# ----------------------------------------------------------------------------
# 1. Archivos: cifrados, notas, herramientas, hashes, staging
# ----------------------------------------------------------------------------
$Enc = @{ Count = 0; First = $null; Last = $null; Samples = (New-Object System.Collections.ArrayList); Dirs = @{} }
$Counters = @{ Notes = 0; Files = 0; Dirs = 0; StagingExe = 0; Tools = 0 }

function Test-OneFile([string]$File, [string]$Name) {
    if ($RxEncExt.IsMatch($Name)) {
        $Enc.Count++
        try {
            $t = [System.IO.File]::GetLastWriteTime($File)
            if (-not $Enc.First -or $t -lt $Enc.First) { $Enc.First = $t }
            if (-not $Enc.Last -or $t -gt $Enc.Last) { $Enc.Last = $t }
        } catch { }
        if ($Enc.Samples.Count -lt 25) { [void]$Enc.Samples.Add($File) }
        $d = [System.IO.Path]::GetDirectoryName($File); $top = $d
        $parts = $d.Split('\'); if ($parts.Length -gt 3) { $top = ($parts[0..2] -join '\') }
        $Enc.Dirs[$top] = 1 + [int]$Enc.Dirs[$top]
        return
    }
    $fi = $null
    try { $fi = New-Object System.IO.FileInfo $File } catch { return }

    if (Test-Rx $RxNote $Name) {
        $Counters.Notes++
        if ($Counters.Notes -le 40) {
            Add-Finding Critical 'NOTA' 'Nota de rescate de NightSpire' "Nombre de archivo coincide con notas conocidas ($Name)" $File $fi.CreationTime
        }
        return
    }
    if (Test-Rx $RxGenericNote $Name) {
        if ($fi.Length -gt 0 -and $fi.Length -lt 65536) {
            $txt = $null
            try { $txt = [System.IO.File]::ReadAllText($File) } catch { }
            if ($txt -and (Test-Rx $RxMarkers $txt)) {
                $Counters.Notes++
                if ($Counters.Notes -le 40) {
                    Add-Finding Critical 'NOTA' 'Nota de rescate de NightSpire' ("Contenido coincide con marcadores de NightSpire: " + $RxMarkers.Match($txt).Value) $File $fi.CreationTime
                }
            }
        }
        return
    }
    if (Test-Rx $RxToolFile $Name) {
        $def = $null
        foreach ($td in $ToolDefs) { if ($td.Rx.IsMatch($Name)) { $def = $td.Def; break } }
        if ($def) {
            $Counters.Tools++
            $sev = $def.Severity; $detail = "Etapa: $($def.Stage). Tamano: $($fi.Length) bytes. Creado: $($fi.CreationTime.ToString('yyyy-MM-dd HH:mm'))"
            if ($Name -match '\.exe$' -and $fi.Length -le ($MaxHashMB * 1MB)) {
                $h = Get-Sha256 $File
                if ($h) {
                    $detail += ". SHA256: $h"
                    if ($HashIoc.ContainsKey($h)) { $sev = 'Critical'; $detail += " => HASH CONOCIDO: $($HashIoc[$h])" }
                }
            }
            if ($Counters.Tools -le 150) { Add-Finding $sev 'HERRAMIENTA' $def.Name $detail $File $fi.CreationTime }
        }
        return
    }
}

function Test-StagingFile([string]$File, [string]$Name) {
    $isExe = $Name.EndsWith('.exe', [System.StringComparison]::OrdinalIgnoreCase)
    $isArc = $RxArchive.IsMatch($Name)
    if (-not ($isExe -or $isArc)) { return }
    $fi = $null
    try { $fi = New-Object System.IO.FileInfo $File } catch { return }
    if ($isExe) {
        if ($fi.Length -gt ($MaxHashMB * 1MB) -or $fi.Length -eq 0) { return }
        $recent = ($fi.CreationTime -ge $Since -or $fi.LastWriteTime -ge $Since)
        $h = Get-Sha256 $File
        if ($h -and $HashIoc.ContainsKey($h)) {
            Add-Finding Critical 'HASH' 'Ejecutable con hash conocido de NightSpire' "SHA256 $h => $($HashIoc[$h])" $File $fi.CreationTime
        } elseif ($recent) {
            $Counters.StagingExe++
            if ($Counters.StagingExe -le 40) {
                Add-Finding Low 'STAGING' 'Ejecutable reciente en carpeta de paso' "SHA256 $h. Tamano $($fi.Length). Revisar si es esperado." $File $fi.CreationTime
            }
        }
    } elseif ($fi.Length -ge 200MB -and $fi.LastWriteTime -ge $Since) {
        Add-Finding Medium 'STAGING' 'Archivo comprimido grande y reciente (posible preparacion de exfiltracion)' ("{0:N0} MB" -f ($fi.Length / 1MB)) $File $fi.LastWriteTime
    }
}

$Visited = @{}
function Invoke-Walk([string]$Root, [int]$MaxDepth) {
    if (-not $Root -or -not (Test-Path -LiteralPath $Root)) { return }
    $stack = New-Object System.Collections.Stack
    $stack.Push(@($Root, 0))
    while ($stack.Count -gt 0) {
        $item = $stack.Pop(); $dir = [string]$item[0]; $depth = [int]$item[1]
        $vk = $dir.TrimEnd('\')
        if ($Visited.ContainsKey($vk)) { continue }
        $Visited[$vk] = 1
        if ($dir.StartsWith($DataDir, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $Counters.Dirs++
        $isStaging = $RxStaging.IsMatch($dir)
        try {
            # GetFiles/GetDirectories: disponibles en .NET 2.0 (Enumerate* es de .NET 4)
            foreach ($f in [System.IO.Directory]::GetFiles($dir)) {
                $Counters.Files++
                $name = [System.IO.Path]::GetFileName($f)
                if ($RxAnyName.IsMatch($name)) { Test-OneFile $f $name }
                elseif ($isStaging) { Test-StagingFile $f $name }
            }
        } catch { }
        if ($MaxDepth -ge 0 -and $depth -ge $MaxDepth) { continue }
        try {
            $di = New-Object System.IO.DirectoryInfo $dir
            foreach ($sd in $di.GetDirectories()) {
                if (($sd.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                if ($RxSkipDir.IsMatch($sd.FullName)) { continue }
                $stack.Push(@($sd.FullName, ($depth + 1)))
            }
        } catch { }
    }
}

if (-not $SkipFileScan) {
    $drives = @()
    try { $drives = @([System.IO.DriveInfo]::GetDrives() | Where-Object { [string]$_.DriveType -eq 'Fixed' -and $_.IsReady } | ForEach-Object { $_.RootDirectory.FullName }) } catch { }
    $sys = $env:SystemDrive + '\'
    if ($Path) { foreach ($p in @($Path)) { if ($p) { Write-Log "Recorriendo $p ..."; Invoke-Walk $p -1 } } }
    if (-not $PathOnly) {
        if ($Mode -eq 'Full') {
            foreach ($d in $drives) { Write-Log "Recorrido completo de $d ..."; Invoke-Walk $d -1 }
        } else {
            foreach ($r in @("${sys}Users", $env:ProgramData, "$env:SystemRoot\Temp", "${sys}PerfLogs", "${sys}Temp", "${sys}Tools", "${sys}Intel", "${sys}`$Recycle.Bin")) {
                Write-Log "Recorriendo $r ..."; Invoke-Walk $r -1
            }
            foreach ($d in $drives) { Write-Log "Recorriendo 2 niveles de $d ..."; Invoke-Walk $d 2 }
        }
    }
    Write-Log ("Archivos revisados: {0:N0} en {1:N0} carpetas" -f $Counters.Files, $Counters.Dirs)

    if ($Enc.Count -gt 0) {
        $topDirs = @($Enc.Dirs.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 | ForEach-Object { "$($_.Key) ($($_.Value))" }) -join '; '
        $det = "{0:N0} archivos con extension de NightSpire. Modificados entre {1} y {2}. Carpetas: {3}. Ejemplos: {4}" -f $Enc.Count, $Enc.First, $Enc.Last, $topDirs, (@($Enc.Samples | Select-Object -First 5) -join ' | ')
        Add-Finding Critical 'CIFRADO' 'Archivos cifrados por NightSpire (.nspire)' $det '' $Enc.First 'CIFRADO|archivos'
        $prev = 0; if ($State -and $State.EncryptedCount) { $prev = [int]$State.EncryptedCount }
        if (-not $FirstRun -and $Enc.Count -gt $prev) {
            Add-Finding Critical 'CIFRADO' 'CIFRADO EN CURSO: aumento la cantidad de archivos cifrados' "Antes: $prev. Ahora: $($Enc.Count). Ultimo archivo modificado: $($Enc.Last). AISLAR EL EQUIPO." '' $Enc.Last ("CIFRADO|aumento|" + $Enc.Count)
        }
        $Enc.Samples | Set-Content -LiteralPath (Join-Path $RunDir 'archivos_cifrados_muestra.txt') -Encoding UTF8
    }
    if ($Counters.Notes -gt 40) { Add-Finding Critical 'NOTA' 'Notas de rescate adicionales' "Total de notas encontradas: $($Counters.Notes) (se listan las primeras 40)" '' $null 'NOTA|total' }
}

# ----------------------------------------------------------------------------
# 2. Canarios (alerta temprana de cifrado)
# ----------------------------------------------------------------------------
$Canaries = @()
if ($State -and $State.Canaries) { $Canaries = @($State.Canaries | Where-Object { $_ -and $_.Path }) }
if ($InitCanary) {
    $Canaries = @()
    foreach ($cd in @($Ioc.CanaryDirs)) {
        if (-not $cd -or -not (Test-Path -LiteralPath $cd)) { continue }
        foreach ($cn in @('!000_inventario_claves.docx', '~zzz_respaldo_contable.xlsx')) {
            $cf = Join-Path $cd $cn
            try {
                $bytes = New-Object byte[] 24576; (New-Object Random).NextBytes($bytes)
                [System.IO.File]::WriteAllBytes($cf, $bytes)
                $Canaries += (New-Obj @{ Path = $cf; Sha256 = (Get-Sha256 $cf) })
                Write-Log "Canario creado: $cf"
            } catch { Add-Note "No se pudo crear el canario $cf : $($_.Exception.Message)" }
        }
    }
}
foreach ($c in $Canaries) {
    if (-not (Test-Path -LiteralPath $c.Path)) {
        $renamed = @(Get-ChildItem -LiteralPath (Split-Path -Parent $c.Path) -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like ((Split-Path -Leaf $c.Path) + '*') })
        Add-Finding Critical 'CANARIO' 'Archivo canario desaparecido o renombrado' ("Posible cifrado en curso. Archivos similares: " + (@($renamed | ForEach-Object { $_.Name }) -join ', ')) $c.Path (Get-Date) ("CANARIO|falta|" + $c.Path + '|' + (Get-Date -Format 'yyyyMMdd'))
    } elseif ((Get-Sha256 $c.Path) -ne $c.Sha256) {
        Add-Finding Critical 'CANARIO' 'Archivo canario modificado' 'El contenido cambio: posible cifrado en curso.' $c.Path (Get-Item -LiteralPath $c.Path -Force).LastWriteTime ("CANARIO|cambio|" + $c.Path + '|' + (Get-Date -Format 'yyyyMMdd'))
    }
}

# ----------------------------------------------------------------------------
# 3. Procesos en ejecucion
# ----------------------------------------------------------------------------
Write-Log 'Procesos, servicios, software y persistencia ...'
$procs = @()
try { $procs = @(Get-WmiObject Win32_Process -ErrorAction Stop) } catch { Add-Note "No se pudieron listar los procesos: $($_.Exception.Message)" }
$procNames = @{}
$hashedProc = @{}
foreach ($p in $procs) {
    if (-not $p) { continue }
    $procNames[[string]$p.ProcessId] = [string]$p.Name
    if ($p.ProcessId -eq $PID) { continue }
    $exe = [string]$p.ExecutablePath; $cl = [string]$p.CommandLine; $nm = [string]$p.Name
    $started = ConvertFrom-WmiDate $p.CreationDate
    if ($cl -match $SelfMarker -or $cl -match 'NightSpire-Hunter') { continue }
    if ((Test-Rx $RxToolFile $nm) -or (Test-Rx $RxToolStr $exe)) {
        Add-Finding High 'PROCESO' "Herramienta asociada a NightSpire en ejecucion: $nm" (Limit-Text "PID $($p.ProcessId). $cl") $exe $started "PROCESO|$nm|$exe"
    } elseif (Test-Rx $RxCmd $cl) {
        Add-Finding High 'PROCESO' "Proceso con linea de comandos sospechosa: $nm" (Limit-Text "PID $($p.ProcessId). $cl" 500) $exe $started "PROCESO|cmd|$nm|$(Limit-Text $cl 120)"
    } elseif (Test-Rx $RxSuspHigh $exe) {
        Add-Finding Medium 'PROCESO' "Proceso ejecutandose desde carpeta temporal/publica: $nm" (Limit-Text "PID $($p.ProcessId). $cl") $exe $started "PROCESO|ruta|$exe"
    }
    if ($exe -and $exe -notmatch '^[A-Za-z]:\\Windows\\' -and -not $hashedProc.ContainsKey($exe)) {
        $hashedProc[$exe] = 1
        try {
            if ((New-Object System.IO.FileInfo $exe).Length -le ($MaxHashMB * 1MB)) {
                $h = Get-Sha256 $exe
                if ($h -and $HashIoc.ContainsKey($h)) { Add-Finding Critical 'HASH' "Proceso en ejecucion con hash conocido de NightSpire: $nm" "SHA256 $h => $($HashIoc[$h]). PID $($p.ProcessId)" $exe $started }
            }
        } catch { }
    }
}

# ----------------------------------------------------------------------------
# 4. Servicios y software instalado
# ----------------------------------------------------------------------------
$svcs = @()
try { $svcs = @(Get-WmiObject Win32_Service -ErrorAction Stop) } catch { Add-Note "No se pudieron listar los servicios: $($_.Exception.Message)" }
foreach ($s in $svcs) {
    if (-not $s) { continue }
    $pn = [string]$s.PathName
    if ((Test-Rx $RxService ([string]$s.Name)) -or (Test-Rx $RxService ([string]$s.DisplayName)) -or (Test-Rx $RxToolStr $pn)) {
        Add-Finding High 'SERVICIO' "Servicio de acceso remoto / herramienta asociada: $($s.DisplayName)" "Nombre: $($s.Name). Estado: $($s.State). Inicio: $($s.StartMode). Cuenta: $($s.StartName)" $pn $null "SERVICIO|$($s.Name)"
    } elseif (Test-Rx $RxSuspHigh $pn) {
        Add-Finding Medium 'SERVICIO' "Servicio con ejecutable en ruta sospechosa: $($s.Name)" "Estado: $($s.State). Inicio: $($s.StartMode). Cuenta: $($s.StartName)" $pn $null "SERVICIO|ruta|$($s.Name)"
    }
    if ($s.Name -eq 'EventLog' -and $s.State -ne 'Running') {
        Add-Finding Critical 'LOGS' 'El servicio Registro de eventos de Windows esta detenido' "Estado: $($s.State). Inicio: $($s.StartMode)" '' (Get-Date) 'LOGS|EventLog detenido'
    }
}

$unKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
$hku = @()
try { $hku = @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction Stop | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object { $_.PSChildName }) } catch { }
foreach ($sid in $hku) { $unKeys += "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" }
foreach ($k in $unKeys) {
    foreach ($a in @(Get-ItemProperty $k -ErrorAction SilentlyContinue)) {
        if (-not $a) { continue }
        $dn = [string]$a.DisplayName
        if ($dn -and (Test-Rx $RxSoftware $dn)) {
            $idate = [string]$a.InstallDate
            Add-Finding Medium 'SOFTWARE' "Software instalado a revisar: $dn" "Version: $($a.DisplayVersion). Editor: $($a.Publisher). Fecha de instalacion: $idate" ([string]$a.InstallLocation) $idate "SOFT|$dn"
        }
    }
}

# ----------------------------------------------------------------------------
# 5. Persistencia: Run/RunOnce, IFEO, carpetas de inicio, tareas programadas
# ----------------------------------------------------------------------------
$regRun = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')
foreach ($sid in $hku) {
    $regRun += "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $regRun += "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
}
foreach ($k in $regRun) {
    $it = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
    if (-not $it) { continue }
    foreach ($vn in @($it.GetValueNames())) {
        $v = [string]$it.GetValue($vn)
        if (-not $v) { continue }
        if (Test-Rx $RxToolStr $v) { Add-Finding High 'PERSISTENCIA' "Clave Run con herramienta asociada a NightSpire: $vn" $v $k $null "RUN|$k|$vn" }
        elseif (Test-Rx $RxSuspHigh $v) { Add-Finding Medium 'PERSISTENCIA' "Clave Run con comando sospechoso: $vn" $v $k $null "RUN|$k|$vn" }
        elseif (Test-Rx $RxSuspLow $v) { Add-Finding Low 'PERSISTENCIA' "Clave Run apuntando a carpeta de usuario: $vn" $v $k $null "RUN|$k|$vn" }
    }
}
foreach ($ifeo in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
    foreach ($sub in @(Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue)) {
        if (-not $sub) { continue }
        $dbg = $sub.GetValue('Debugger')
        if ($dbg) { Add-Finding High 'PERSISTENCIA' "IFEO con Debugger: $($sub.PSChildName)" ([string]$dbg) $sub.Name $null "IFEO|$($sub.PSChildName)" }
    }
}
$userDirs = Get-SubDirs "$($env:SystemDrive)\Users"
$startDirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
foreach ($u in $userDirs) {
    $startDirs += (Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
    if ($u.CreationTime -ge $Since -and @('Public', 'Default', 'All Users', 'Default User') -notcontains $u.Name) {
        Add-Finding Low 'CUENTAS' "Perfil de usuario creado en la ventana: $($u.Name)" 'Primer inicio de sesion interactivo de esa cuenta en este equipo.' $u.FullName $u.CreationTime "PERFIL|$($u.Name)"
    }
}
foreach ($sd in $startDirs) {
    if (-not (Test-Path -LiteralPath $sd)) { continue }
    foreach ($f in @(Get-ChildItem -LiteralPath $sd -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Name -ne 'desktop.ini' })) {
        $sev = 'Low'; if ($f.CreationTime -ge $Since) { $sev = 'Medium' }
        if (Test-Rx $RxToolStr $f.Name) { $sev = 'High' }
        Add-Finding $sev 'PERSISTENCIA' "Elemento en carpeta de Inicio: $($f.Name)" "Creado: $($f.CreationTime)" $f.FullName $f.CreationTime
    }
}
try {
    # Interfaz COM del Programador de tareas: existe desde Vista / Server 2008
    $ts = New-Object -ComObject Schedule.Service; $ts.Connect()
    $folders = New-Object System.Collections.Queue; $folders.Enqueue($ts.GetFolder('\'))
    while ($folders.Count -gt 0) {
        $fo = $folders.Dequeue()
        try { foreach ($sf in @($fo.GetFolders(0))) { if ($sf) { $folders.Enqueue($sf) } } } catch { }
        $tasks = @(); try { $tasks = @($fo.GetTasks(1)) } catch { }
        foreach ($t in $tasks) {
            if (-not $t -or $t.Name -like 'NightSpireHunter*') { continue }
            $x = $null; try { $x = [xml]$t.Xml } catch { continue }
            $acts = @($x.Task.Actions.Exec | Where-Object { $_ } | ForEach-Object { ("{0} {1}" -f $_.Command, $_.Arguments).Trim() }) -join ' ; '
            if (-not $acts) { continue }
            $regDate = [string]$x.Task.RegistrationInfo.Date; $author = [string]$x.Task.RegistrationInfo.Author
            $det = "Accion: $(Limit-Text $acts 400). Autor: $author. Registrada: $regDate"
            if ((Test-Rx $RxToolStr $acts) -or (Test-Rx $RxCmd $acts)) { Add-Finding High 'TAREA' "Tarea programada con herramienta/comando asociado a NightSpire: $($t.Path)" $det $t.Path $regDate "TAREA|$($t.Path)" }
            elseif (Test-Rx $RxSuspHigh $acts) { Add-Finding Medium 'TAREA' "Tarea programada con accion sospechosa: $($t.Path)" $det $t.Path $regDate "TAREA|$($t.Path)" }
            elseif ($t.Path -notlike '\Microsoft\*') {
                $rd = [datetime]::MinValue
                if ($regDate -and [datetime]::TryParse($regDate, [ref]$rd) -and $rd -ge $Since) { Add-Finding Low 'TAREA' "Tarea programada creada en la ventana: $($t.Path)" $det $t.Path $regDate "TAREA|$($t.Path)" }
            }
        }
    }
} catch { Add-Note "No se pudieron enumerar las tareas programadas: $($_.Exception.Message)" }

# ----------------------------------------------------------------------------
# 6. Artefactos de herramientas de exfiltracion y acceso remoto
# ----------------------------------------------------------------------------
Write-Log 'Artefactos de herramientas ...'
foreach ($sid in $hku) {
    foreach ($s in @(Get-ChildItem "Registry::HKEY_USERS\$sid\Software\Martin Prikryl\WinSCP 2\Sessions" -ErrorAction SilentlyContinue)) {
        if (-not $s) { continue }
        $hn = [string]$s.GetValue('HostName'); $un = [string]$s.GetValue('UserName')
        if (-not $hn) { continue }
        $sev = 'Medium'; if ((Get-IpClass $hn) -eq 'IOC') { $sev = 'Critical' }
        Add-Finding $sev 'EXFIL' "Sesion guardada de WinSCP hacia $hn" "Usuario remoto: $un. Perfil: $sid" $s.Name $null "WINSCP|$sid|$hn"
    }
    foreach ($s in @(Get-ChildItem "Registry::HKEY_USERS\$sid\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue)) {
        if (-not $s) { continue }
        Add-Finding Info 'LATERAL' "Destino RDP usado desde este equipo: $($s.PSChildName)" "Usuario sugerido: $($s.GetValue('UsernameHint')). Perfil: $sid" $s.Name $null "RDPOUT|$sid|$($s.PSChildName)"
    }
}
foreach ($u in $userDirs) {
    foreach ($rel in @('AppData\Local\MEGAcmd', 'AppData\Local\Mega Limited', 'AppData\Roaming\AnyDesk', 'AppData\Roaming\rclone', '.config\rclone', 'AppData\Roaming\Everything', 'AppData\Roaming\tox', 'AppData\Local\Google\Chrome Remote Desktop')) {
        $d = Join-Path $u.FullName $rel
        if (Test-Path -LiteralPath $d) {
            $di = Get-Item -LiteralPath $d -Force
            Add-Finding Medium 'ARTEFACTO' "Carpeta de datos de herramienta: $rel" "Usuario: $($u.Name). Creada: $($di.CreationTime). Ultima modificacion: $($di.LastWriteTime)" $d $di.CreationTime
        }
    }
    $hist = Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path -LiteralPath $hist) {
        $n = 0
        foreach ($line in @(Get-Content -LiteralPath $hist -ErrorAction SilentlyContinue)) {
            if ((Test-Rx $RxCmd $line) -or (Test-Rx $RxToolStr $line)) {
                $n++; if ($n -gt 15) { break }
                Add-Finding High 'COMANDO' "Historial de PowerShell de $($u.Name): comando sospechoso" (Limit-Text $line 400) $hist $null "PSHIST|$($u.Name)|$(Limit-Text $line 150)"
            }
        }
    }
}
foreach ($adDir in (@("$env:ProgramData\AnyDesk") + @($userDirs | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\AnyDesk' }))) {
    $ct = Join-Path $adDir 'connection_trace.txt'
    if (Test-Path -LiteralPath $ct) {
        foreach ($line in @(Get-Content -LiteralPath $ct -ErrorAction SilentlyContinue | Where-Object { $_ -match 'Incoming' } | Select-Object -Last 20)) {
            if ($line) { Add-Finding High 'ACCESO-REMOTO' 'Conexion ENTRANTE de AnyDesk registrada' (Limit-Text $line) $ct $null "ANYDESK|$(Limit-Text $line 150)" }
        }
    }
}
$crd = "$env:ProgramData\Google\Chrome Remote Desktop\host.json"
if (Test-Path -LiteralPath $crd) {
    $owner = ''
    try { $j = [System.IO.File]::ReadAllText($crd); $m = [regex]::Match($j, '"(host_owner|xmpp_login|host_owner_email)"\s*:\s*"([^"]+)"'); if ($m.Success) { $owner = $m.Groups[2].Value } } catch { }
    $sev = 'High'; if ($owner -and (Test-Rx $RxEmails $owner)) { $sev = 'Critical' }
    Add-Finding $sev 'ACCESO-REMOTO' 'Este equipo esta registrado como host de Chrome Remote Desktop' "Cuenta de Google propietaria: $owner" $crd (Get-Item -LiteralPath $crd -Force).CreationTime "CRD|$owner"
}
foreach ($pf in @(Get-ChildItem "$env:SystemRoot\Prefetch" -Filter '*.pf' -ErrorAction SilentlyContinue)) {
    if (-not $pf) { continue }
    $exeName = $pf.Name -replace '-[0-9A-F]{8}\.pf$', ''
    if (Test-Rx $RxToolFile $exeName) {
        Add-Finding Medium 'EJECUCION' "Prefetch: se ejecuto $exeName" "Primera ejecucion (aprox.): $($pf.CreationTime). Ultima: $($pf.LastWriteTime)" $pf.FullName $pf.LastWriteTime "PREFETCH|$($pf.Name)"
    }
}

# ----------------------------------------------------------------------------
# 7. Defender (solo donde existe el modulo: Server 2016 en adelante)
# ----------------------------------------------------------------------------
if (Test-Cmd 'Get-MpComputerStatus') {
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.AMServiceEnabled -and -not $mp.RealTimeProtectionEnabled) {
            Add-Finding Medium 'DEFENSA' 'Microsoft Defender: proteccion en tiempo real DESACTIVADA' "Modo: $($mp.AMRunningMode). Confirmar si hay otro antivirus o si fue deshabilitado." '' $null 'DEFENDER|RTP'
        }
        $pref = Get-MpPreference -ErrorAction Stop
        foreach ($e in (@($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension))) {
            if ($e -and $e -notmatch '^N/A') { Add-Finding Medium 'DEFENSA' "Exclusion de Defender configurada: $e" 'Los atacantes agregan exclusiones para sus herramientas. Confirmar que sea legitima.' '' $null "DEFENDER|excl|$e" }
        }
    } catch { }
}

# ----------------------------------------------------------------------------
# 8. Red: conexiones activas y cache DNS (netstat / ipconfig: presentes en todas las versiones)
# ----------------------------------------------------------------------------
Write-Log 'Conexiones de red y cache DNS ...'
foreach ($l in @(& netstat.exe -ano 2>$null)) {
    if ($l -match '^\s*TCP\s+\S+\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+\S+\s+(\d+)') {
        $rip = $Matches[1]; $rport = $Matches[2]; $rpid = $Matches[3]
        if ((Get-IpClass $rip) -eq 'IOC') {
            $pn = $procNames[$rpid]
            Add-Finding Critical 'RED' "Conexion ACTIVA con IP de la lista de IOCs: ${rip}:$rport" "Proceso: $pn (PID $rpid)" '' (Get-Date) "RED|$rip|$pn"
        }
    }
}
$dnsNames = @{}
foreach ($l in @(& ipconfig.exe /displaydns 2>$null)) {
    if ($l -match '^\s{4}(\S+\.\S+)\s*$') { $dnsNames[$Matches[1]] = 1 }
    elseif ($l -match ':\s*([A-Za-z0-9_.-]+\.[A-Za-z]{2,})\s*$') { $dnsNames[$Matches[1]] = 1 }
}
foreach ($dp in @($Ioc.DnsPatterns)) {
    if (-not $dp) { continue }
    $rx = New-WildRegex @($dp.Pattern)
    foreach ($n in @($dnsNames.Keys)) {
        if (Test-Rx $rx $n) { Add-Finding $dp.Severity 'RED' "Cache DNS: resolucion reciente de $n" "$($dp.Name). Indica que algun proceso de este equipo consulto ese dominio." '' $null "DNS|$n" }
    }
}

# ----------------------------------------------------------------------------
# 9. Registros de eventos
# ----------------------------------------------------------------------------
function Add-LogonFindings($Agg, [string]$Source) {
    foreach ($a in @($Agg.Values)) {
        if (-not $a) { continue }
        $cls = Get-IpClass $a.Ip
        $det = "{0} inicio(s) entre {1} y {2}; {3} en horario nocturno (00-06 h). Fuente: {4}" -f $a.Count, $a.First, $a.Last, $a.Night, $Source
        $key = "RDP|$($a.User)|$($a.Ip)"
        switch ($cls) {
            'IOC' { Add-Finding Critical 'RDP' "Inicio de sesion remoto de '$($a.User)' desde IP de la lista de IOCs $($a.Ip)" $det '' $a.First $key }
            'PUBLIC' { Add-Finding High 'RDP' "Inicio de sesion remoto de '$($a.User)' desde IP PUBLICA $($a.Ip)" $det '' $a.First $key }
            'WATCH' { Add-Finding Medium 'RDP' "Inicio de sesion remoto de '$($a.User)' desde pool SSL-VPN $($a.Ip)" $det '' $a.First $key }
            'PRIVATE' { if ($a.Night -gt 0) { Add-Finding Low 'RDP' "Inicio de sesion remoto nocturno de '$($a.User)' desde $($a.Ip)" $det '' $a.First $key } }
        }
    }
}
function Add-Agg($Agg, [string]$User, [string]$Ip, [datetime]$T) {
    $k = "$User|$Ip"
    if (-not $Agg.ContainsKey($k)) { $Agg[$k] = New-Obj @{ User = $User; Ip = $Ip; Count = 0; First = $T; Last = $T; Night = 0 } }
    $a = $Agg[$k]; $a.Count = $a.Count + 1
    if ($T -lt $a.First) { $a.First = $T }
    if ($T -gt $a.Last) { $a.Last = $T }
    if ($T.Hour -lt 6) { $a.Night = $a.Night + 1 }
}

if (-not $SkipEventLogs) {
    Initialize-EventReader
    if ($script:UseWevt) { Write-Log 'Registros de eventos (via wevtutil.exe) ...'; Add-Note 'Eventos leidos con wevtutil.exe (Get-WinEvent no disponible en este equipo o lectura forzada).' }
    else { Write-Log 'Registros de eventos ...' }
    $ms = [int64]$DaysBack * 86400000

    # 9.1 Borrado de registros y cambios de auditoria
    foreach ($e in @(Get-Ev -Log 'Security' -Ids 1102 -Max 30)) { Add-Finding High 'LOGS' 'Se BORRO el registro de seguridad (evento 1102)' (Limit-Text $e.Message) '' $e.TimeCreated "LOGS|1102|$($e.TimeCreated.Ticks)" }
    foreach ($e in @(Get-Ev -Log 'System' -Ids 104 -Max 60)) { Add-Finding High 'LOGS' 'Se borro un registro de eventos (evento 104)' (Limit-Text $e.Message) '' $e.TimeCreated "LOGS|104|$($e.TimeCreated.Ticks)" }
    foreach ($e in @(Get-Ev -Log 'Security' -Ids 4719 -Max 30)) { Add-Finding Medium 'LOGS' 'Cambio en la directiva de auditoria (evento 4719)' (Limit-Text $e.Message 400) '' $e.TimeCreated "LOGS|4719|$($e.TimeCreated.Ticks)" }

    # 9.2 Cuentas
    foreach ($e in @(Get-Ev -Log 'Security' -Ids 4720 -Max 100)) {
        $d = Get-EvData $e
        Add-Finding High 'CUENTAS' "Cuenta de usuario creada: $($d.TargetUserName)" "Creada por: $($d.SubjectDomainName)\$($d.SubjectUserName)" '' $e.TimeCreated "CUENTA|4720|$($d.TargetUserName)|$($e.TimeCreated.Ticks)"
    }
    foreach ($e in @(Get-Ev -Log 'Security' -Ids 4732, 4728, 4756 -Max 300)) {
        $d = Get-EvData $e
        $sev = 'Low'; if ([string]$d.TargetSid -match 'S-1-5-32-544$|-512$|-519$|-518$') { $sev = 'High' }
        Add-Finding $sev 'CUENTAS' "Miembro agregado al grupo '$($d.TargetUserName)'" "Miembro: $($d.MemberName) $($d.MemberSid). Agregado por: $($d.SubjectUserName)" '' $e.TimeCreated "CUENTA|grupo|$($d.TargetUserName)|$($d.MemberSid)|$($e.TimeCreated.Ticks)"
    }

    # 9.3 Fuerza bruta (4625)
    $fail = @(Get-Ev -Log 'Security' -Ids 4625 -Max 20000)
    if ($fail.Count -gt 0) {
        $byIp = @{}
        foreach ($e in $fail) { $ip = Get-Prop $e 19; if (-not $ip) { $ip = '-' }; $byIp[$ip] = 1 + [int]$byIp[$ip] }
        $top = @($byIp.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10)
        $sev = 'Low'; if ($top[0].Value -ge 100) { $sev = 'Medium' }
        Add-Finding $sev 'FUERZA-BRUTA' "Inicios de sesion fallidos en la ventana: $($fail.Count)" ("Principales origenes: " + (@($top | ForEach-Object { "$($_.Key) ($($_.Value))" }) -join ', ')) '' $null ("4625|resumen|" + (Get-Date -Format 'yyyyMMdd'))
        foreach ($ipk in @($byIp.Keys)) {
            if ((Get-IpClass $ipk) -eq 'IOC') { Add-Finding High 'FUERZA-BRUTA' "Inicios de sesion fallidos desde IP de la lista de IOCs $ipk" "$($byIp[$ipk]) intentos" '' $null "4625|$ipk" }
        }
    }

    # 9.4 Inicios de sesion remotos (4624 tipo 10 y registro de Terminal Services)
    $agg = @{}
    $xp = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]] and EventData[Data[@Name='LogonType']='10']]"
    foreach ($e in @(Get-Ev -Log 'Security' -XPath $xp -Max 5000)) { $d = Get-EvData $e; Add-Agg $agg "$($d.TargetDomainName)\$($d.TargetUserName)" ([string]$d.IpAddress) $e.TimeCreated }
    Add-LogonFindings $agg 'Security 4624 tipo 10'
    $agg2 = @{}
    $lsmLog = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    $lsmEv = @(); if (Test-Log $lsmLog) { $lsmEv = @(Get-Ev -Log $lsmLog -Ids 21, 25 -Max 5000) }
    foreach ($e in $lsmEv) {
        $u = ''; $ip = ''
        try { $x = [xml]$e.ToXml(); $u = [string]$x.Event.UserData.EventXML.User; $ip = [string]$x.Event.UserData.EventXML.Address } catch { continue }
        if (-not $agg.ContainsKey("$u|$ip")) { Add-Agg $agg2 $u $ip $e.TimeCreated }
    }
    Add-LogonFindings $agg2 'TerminalServices-LocalSessionManager 21/25'

    # 9.5 Nombres de equipo del atacante (toda la historia disponible)
    $atkHosts = @($Ioc.AttackerHostnames | Where-Object { $_ })
    if ($atkHosts.Count -gt 0) {
        $cond = @($atkHosts | ForEach-Object { "Data='$_'" }) -join ' or '
        foreach ($e in @(Get-Ev -Log 'Security' -XPath "*[System[(EventID=4624 or EventID=4625 or EventID=4776)] and EventData[$cond]]" -Max 100)) {
            $d = Get-EvData $e
            Add-Finding Critical 'ATACANTE' "Evento $($e.Id) con nombre de equipo de los operadores de NightSpire" "Usuario: $($d.TargetUserName). Equipo: $($d.WorkstationName)$($d.Workstation). IP: $($d.IpAddress)" '' $e.TimeCreated "HOSTATK|$($e.Id)|$($e.TimeCreated.Ticks)"
        }
    }

    # 9.6 Servicios instalados (7045)
    foreach ($e in @(Get-Ev -Log 'System' -Ids 7045 -Max 2000)) {
        $sn = Get-Prop $e 0; $img = Get-Prop $e 1; $acct = Get-Prop $e 4
        $k = "7045|$sn|$($e.TimeCreated.Ticks)"
        if ((Test-Rx $RxService $sn) -or (Test-Rx $RxToolStr $img) -or (Test-Rx $RxToolStr $sn)) { Add-Finding High 'SERVICIO' "Se instalo un servicio asociado a NightSpire: $sn" "Ejecutable: $img. Cuenta: $acct" $img $e.TimeCreated $k }
        elseif ((Test-Rx $RxSuspHigh $img) -or (Test-Rx $RxCmd $img)) { Add-Finding Medium 'SERVICIO' "Se instalo un servicio con ruta/comando sospechoso: $sn" "Ejecutable: $(Limit-Text $img 400). Cuenta: $acct" $img $e.TimeCreated $k }
    }

    # 9.7 Defender (el registro no existe en Server 2008: se omite sin error)
    $defLog = 'Microsoft-Windows-Windows Defender/Operational'
    if (Test-Log $defLog) {
        foreach ($e in @(Get-Ev -Log $defLog -Ids 5001 -Max 30)) { Add-Finding High 'DEFENSA' 'Defender: se deshabilito la proteccion en tiempo real (evento 5001)' (Limit-Text $e.Message) '' $e.TimeCreated "DEF|5001|$($e.TimeCreated.Ticks)" }
        foreach ($e in @(Get-Ev -Log $defLog -Ids 5007 -Max 500)) {
            if ([string]$e.Message -match 'Exclusions|DisableRealtimeMonitoring|DisableAntiSpyware|DisableBehaviorMonitoring') { Add-Finding Medium 'DEFENSA' 'Defender: cambio de configuracion relevante (evento 5007)' (Limit-Text $e.Message 400) '' $e.TimeCreated "DEF|5007|$($e.TimeCreated.Ticks)" }
        }
        foreach ($e in @(Get-Ev -Log $defLog -Ids 1116, 1117 -Max 200)) {
            $d = Get-EvData $e
            Add-Finding High 'DEFENSA' "Defender detecto una amenaza: $($d.'Threat Name')" "Ruta: $(Limit-Text $d.Path 300). Usuario: $($d.'Detection User'). Proceso: $($d.'Process Name')" '' $e.TimeCreated "DEF|det|$($d.'Threat Name')|$(Limit-Text $d.Path 120)"
        }
    }

    # 9.8 Comandos: creacion de procesos (4688, si esta auditado) y bloques de PowerShell (4104, PS 5+)
    $n = 0
    foreach ($e in @(Get-Ev -Log 'Security' -Ids 4688 -Max 20000)) {
        $np = Get-Prop $e 5; $cl = Get-Prop $e 8
        if ($cl -match $SelfMarker -or $cl -match 'NightSpire-Hunter') { continue }
        if ((Test-Rx $RxToolStr $np) -or (Test-Rx $RxCmd $cl)) {
            $n++; if ($n -gt 60) { break }
            Add-Finding High 'COMANDO' "Ejecucion registrada (4688): $([System.IO.Path]::GetFileName($np))" (Limit-Text "$np | $cl" 500) $np $e.TimeCreated "4688|$np|$(Limit-Text $cl 120)|$($e.TimeCreated.Ticks)"
        }
    }
    $n = 0
    if (Test-Log 'Microsoft-Windows-PowerShell/Operational') {
        foreach ($e in @(Get-Ev -Log 'Microsoft-Windows-PowerShell/Operational' -Ids 4104 -Max 5000)) {
            $msg = [string]$e.Message
            if (-not $msg -or $msg -match $SelfMarker -or $msg -match 'NightSpire-Hunter|NightSpireHunter') { continue }
            $m = $RxCmd.Match($msg)
            if ($m.Success) {
                $n++; if ($n -gt 40) { break }
                $start = [math]::Max(0, $m.Index - 120); $len = [math]::Min(400, $msg.Length - $start)
                Add-Finding High 'COMANDO' "PowerShell (4104): bloque de script con '$($m.Value)'" (Limit-Text $msg.Substring($start, $len) 400) '' $e.TimeCreated "4104|$($m.Value)|$($e.TimeCreated.Ticks)"
            }
        }
    }

    # 9.9 Tareas programadas creadas (4698 si esta auditado)
    foreach ($e in @(Get-Ev -Log 'Security' -Ids 4698 -Max 200)) {
        $d = Get-EvData $e
        if ([string]$d.TaskName -like '*NightSpireHunter*') { continue }
        Add-Finding Medium 'TAREA' "Tarea programada creada (4698): $($d.TaskName)" "Creada por: $($d.SubjectUserName). $(Limit-Text $d.TaskContent 300)" '' $e.TimeCreated "4698|$($d.TaskName)|$($e.TimeCreated.Ticks)"
    }

    # 9.10 Veeam: eliminacion de respaldos (NightSpire suele borrar respaldos antes de cifrar)
    foreach ($vl in @(Get-LogNames 'Veeam*')) {
        if (-not $vl) { continue }
        $n = 0
        foreach ($e in @(Get-Ev -Log $vl -Max 5000)) {
            if ([string]$e.Message -match 'delet|remov|elimin|borr') {
                $n++; if ($n -gt 30) { break }
                Add-Finding Medium 'VEEAM' "Veeam: evento de eliminacion ($($e.Id))" (Limit-Text $e.Message 400) '' $e.TimeCreated "VEEAM|$($e.Id)|$($e.TimeCreated.Ticks)"
            }
        }
    }
}

# ----------------------------------------------------------------------------
# 10. Informe
# ----------------------------------------------------------------------------
foreach ($f in $script:Findings) { if ($Seen.ContainsKey($f.Key)) { $f.IsNew = $false } }
$sorted = @($script:Findings | Sort-Object @{ Expression = { $SevRank[$_.Severity] }; Descending = $true }, Category, EvidenceTime)
$newOnes = @($sorted | Where-Object { $_.IsNew })
$cnt = @{}; $cntNew = @{}
foreach ($s in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
    $cnt[$s] = @($sorted | Where-Object { $_.Severity -eq $s }).Count
    $cntNew[$s] = @($newOnes | Where-Object { $_.Severity -eq $s }).Count
}
$duration = [int]((Get-Date) - $RunStart).TotalSeconds

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('=' * 78)
[void]$sb.AppendLine("NightSpire-Hunter v$ScriptVersion - INFORME")
[void]$sb.AppendLine("Equipo: $HostName    Fecha: $($RunStart.ToString('yyyy-MM-dd HH:mm:ss'))    Duracion: ${duration}s")
[void]$sb.AppendLine("Modo: $Mode    Ventana: $DaysBack dias    Administrador: $IsAdmin    PowerShell: $($PSVersionTable.PSVersion)    IOCs: $($Ioc.Version)$(if ($IocLocalLoaded) { ' + iocs.local.psd1' })")
[void]$sb.AppendLine(("Archivos revisados: {0:N0}    Hallazgos omitidos por lista de excepciones: {1}" -f $Counters.Files, $script:Suppressed))
[void]$sb.AppendLine('=' * 78)
[void]$sb.AppendLine(("TOTAL   Criticos: {0}  Altos: {1}  Medios: {2}  Bajos: {3}  Info: {4}" -f $cnt.Critical, $cnt.High, $cnt.Medium, $cnt.Low, $cnt.Info))
if ($FirstRun) { [void]$sb.AppendLine('Primera ejecucion en este equipo: todo figura como NUEVO.') }
else { [void]$sb.AppendLine(("NUEVOS  Criticos: {0}  Altos: {1}  Medios: {2}  Bajos: {3}  Info: {4}" -f $cntNew.Critical, $cntNew.High, $cntNew.Medium, $cntNew.Low, $cntNew.Info)) }
foreach ($nt in $script:Notes) { [void]$sb.AppendLine("AVISO: $nt") }
[void]$sb.AppendLine('')
foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
    $grp = @($sorted | Where-Object { $_.Severity -eq $sev })
    if ($grp.Count -eq 0) { continue }
    [void]$sb.AppendLine("----- $($sev.ToUpper()) ($($grp.Count)) " + ('-' * 50))
    foreach ($f in $grp) {
        $tag = ''; if ($f.IsNew -and -not $FirstRun) { $tag = '[NUEVO] ' }
        [void]$sb.AppendLine("$tag[$($f.Category)] $($f.Title)")
        if ($f.Path) { [void]$sb.AppendLine("    Ruta:    $($f.Path)") }
        if ($f.EvidenceTime) { [void]$sb.AppendLine("    Fecha:   $($f.EvidenceTime)") }
        if ($f.Detail) { [void]$sb.AppendLine("    Detalle: $($f.Detail)") }
    }
    [void]$sb.AppendLine('')
}
if ($sorted.Count -eq 0) { [void]$sb.AppendLine('Sin hallazgos.') }
$report = $sb.ToString()

$cols = @('Host', 'Severity', 'Category', 'Title', 'Detail', 'Path', 'EvidenceTime', 'IsNew', 'Key')
$report | Set-Content -LiteralPath (Join-Path $RunDir 'informe.txt') -Encoding UTF8
if ($sorted.Count -gt 0) { $sorted | Select-Object $cols | Export-Csv -Path (Join-Path $RunDir 'hallazgos.csv') -NoTypeInformation -Encoding UTF8 }
else { ('"' + ($cols -join '","') + '"') | Set-Content -LiteralPath (Join-Path $RunDir 'hallazgos.csv') -Encoding UTF8 }
if (Test-Cmd 'ConvertTo-Json') {   # PowerShell 3+; en 2.0 queda solo el CSV
    try {
        New-Obj @{ Host = $HostName; Start = $RunStart.ToString('s'); DurationSec = $duration; Mode = $Mode; DaysBack = $DaysBack; IsAdmin = $IsAdmin
            Version = $ScriptVersion; IocVersion = $Ioc.Version; Counts = $cnt; NewCounts = $cntNew; Notes = @($script:Notes); Findings = @($sorted | Select-Object $cols)
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $RunDir 'hallazgos.json') -Encoding UTF8
    } catch { }
}
$report | Set-Content -LiteralPath (Join-Path $OutputDir "ULTIMO_$HostName.txt") -Encoding UTF8

$histFile = Join-Path $OutputDir 'historial.csv'
if (-not (Test-Path -LiteralPath $histFile)) { 'Fecha,Equipo,Modo,Criticos,Altos,Medios,Bajos,NuevosCriticos,NuevosAltos,ArchivosCifrados,DuracionSeg' | Set-Content -LiteralPath $histFile -Encoding UTF8 }
('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10}' -f $RunStart.ToString('s'), $HostName, $Mode, $cnt.Critical, $cnt.High, $cnt.Medium, $cnt.Low, $cntNew.Critical, $cntNew.High, $Enc.Count, $duration) | Add-Content -LiteralPath $histFile -Encoding UTF8

# Estado para la proxima ejecucion (CLIXML: disponible desde PowerShell 2.0)
foreach ($f in $sorted) { $Seen[$f.Key] = 1 }
$encCount = $Enc.Count
if ($SkipFileScan -and $State -and $State.EncryptedCount) { $encCount = [int]$State.EncryptedCount }
try {
    New-Obj @{ LastRun = $RunStart.ToString('s'); EncryptedCount = $encCount; Canaries = @($Canaries); SeenKeys = @($Seen.Keys) } |
        Export-Clixml -Path $StateFile -Depth 4
} catch { Write-Log "No se pudo guardar el estado: $($_.Exception.Message)" }

# Evento en el registro de Aplicacion (para Wazuh / Graylog / SIEM)
$worstNew = 0; foreach ($f in $newOnes) { if ($SevRank[$f.Severity] -gt $worstNew) { $worstNew = $SevRank[$f.Severity] } }
$worst = 0; foreach ($f in $sorted) { if ($SevRank[$f.Severity] -gt $worst) { $worst = $SevRank[$f.Severity] } }
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists('NightSpireHunter')) { New-EventLog -LogName Application -Source 'NightSpireHunter' -ErrorAction Stop }
    $evId = 9000; $evType = 'Information'
    if ($worstNew -ge 3) { $evId = 9002; $evType = 'Error' } elseif ($worstNew -eq 2) { $evId = 9001; $evType = 'Warning' }
    $evMsg = $report; if ($evMsg.Length -gt 30000) { $evMsg = $evMsg.Substring(0, 30000) }
    Write-EventLog -LogName Application -Source 'NightSpireHunter' -EventId $evId -EntryType $evType -Message $evMsg -ErrorAction Stop
} catch { }

if ($CentralShare) {
    try {
        $dest = Join-Path $CentralShare $HostName
        if (-not (Test-Path -LiteralPath $dest)) { New-Item -ItemType Directory -Path $dest -Force -ErrorAction Stop | Out-Null }
        Copy-Item -LiteralPath $RunDir -Destination $dest -Recurse -Force -ErrorAction Stop
        Copy-Item -LiteralPath (Join-Path $OutputDir "ULTIMO_$HostName.txt") -Destination $dest -Force
    } catch { Write-Log "No se pudo copiar el informe a $CentralShare : $($_.Exception.Message)" }
}

if (-not $Quiet) { Write-Host ''; Write-Host $report; Write-Host "Informe guardado en: $RunDir" }
if ($worst -ge 3) { exit 2 } elseif ($worst -eq 2) { exit 1 } else { exit 0 }
