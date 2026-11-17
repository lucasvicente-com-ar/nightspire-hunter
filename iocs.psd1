# IOCs de NightSpire tomados de fuentes publicas (S-RM, Huntress, Halcyon, Barracuda,
# Proven Data, 0x70RVS). Ver docs/NIGHTSPIRE.md.
# Los indicadores y excepciones propios de cada organizacion van en iocs.local.psd1
# (mismo formato, junto a este archivo; ver iocs.local.example.psd1). Ese archivo no se publica.
# Formato: archivo de datos de PowerShell (compatible con PowerShell 2.0 en adelante).
# Usar comillas simples. Dentro de ellas la barra invertida se escribe una sola vez (C:\Carpeta).
@{
    Version             = '2026-11-16'

    EncryptedExtensions = @('.nspire', '.0nspire')

    RansomNoteNames     = @(
        '[NSPIRE_README].txt',
        '[nspire_msg].txt',
        '_nightspire_readme.txt',
        'nightspire_readme.txt'
    )
    RansomNoteWildcards = @('*nspire*readme*', '*readme*nspire*', '*nspire_msg*')

    # Nombres genericos: solo se informan si el CONTENIDO tiene alguno de los marcadores
    GenericNoteNames    = @('readme.txt', 'readme_2.txt')
    # (las direcciones onion, correos y IDs de qTox de una nota recibida van en iocs.local.psd1)
    NoteContentMarkers  = @('NightSpire', 'onionmail.org')

    Sha256              = @{
        'bde50a42efc079edde1a314243ad339db2d42e343fbbcd39117803b0f5960355' = 'enc.exe - cifrador NightSpire (Huntress, 02/12/2025)'
        'ad67031e2ca68764fe1a7d6632c02b02a299d59efb920710011a9a2ccf4399b7' = 'enc.exe - cifrador NightSpire (Huntress, 25/03/2026)'
        'e275b8a02bf23b565bdaabadb220b39409eddc6b8253eb04e0f092d697e3b53d' = 'v7.exe - payload NightSpire (0x70RVS / Halcyon)'
        '35cefe4bc4a98ad73dda4444c700aac9f749efde8f9de6a643a57a5b605bd4e7' = 'Everything.exe usado por NightSpire (S-RM). Halcyon lo rotula como payload: verificar'
    }

    # 14.139.185.60 = servidor WinSCP/C2 de NightSpire (S-RM, Barracuda, Halcyon)
    IPs                 = @('14.139.185.60')
    Cidrs               = @()

    # Redes propias que no son maliciosas pero merecen revision si aparecen en un inicio de
    # sesion RDP (por ejemplo, el pool de direcciones de la VPN). Se cargan en iocs.local.psd1.
    WatchRanges         = @()

    AttackerHostnames   = @('XDRAGON-SERVER1', 'WINDOWS-DTX-8GB')
    Emails              = @('prince1990905@gmail.com')

    DnsPatterns         = @(
        @{ Pattern = '*.onion'; Severity = 'High'; Name = 'Dominio Tor' },
        @{ Pattern = '*onionmail.org'; Severity = 'High'; Name = 'OnionMail (contacto NightSpire)' },
        @{ Pattern = '*tox.chat'; Severity = 'Medium'; Name = 'qTox' },
        @{ Pattern = '*torproject.org'; Severity = 'Medium'; Name = 'Tor Project' },
        @{ Pattern = '*mega.nz'; Severity = 'Medium'; Name = 'MEGA (exfiltracion)' },
        @{ Pattern = '*mega.co.nz'; Severity = 'Medium'; Name = 'MEGA (exfiltracion)' },
        @{ Pattern = '*mega.io'; Severity = 'Medium'; Name = 'MEGA (exfiltracion)' },
        @{ Pattern = '*anydesk.com'; Severity = 'Medium'; Name = 'AnyDesk' },
        @{ Pattern = '*remotedesktop.google.com'; Severity = 'Medium'; Name = 'Chrome Remote Desktop' },
        @{ Pattern = '*rclone.org'; Severity = 'Medium'; Name = 'Rclone' }
    )

    # Archivos buscados por nombre (admite * y ?)
    Tools               = @(
        @{ Pattern = 'enc.exe'; Name = 'enc.exe (nombre del cifrador NightSpire)'; Severity = 'High'; Stage = 'Impacto' },
        @{ Pattern = 'v7.exe'; Name = 'v7.exe (nombre de payload NightSpire)'; Severity = 'High'; Stage = 'Impacto' },
        @{ Pattern = 'mimikatz*'; Name = 'Mimikatz'; Severity = 'High'; Stage = 'Credenciales' },
        @{ Pattern = 'mimi*.exe'; Name = 'Mimikatz (variante)'; Severity = 'Medium'; Stage = 'Credenciales' },
        @{ Pattern = 'PSEXESVC.exe'; Name = 'Servicio PsExec (ejecucion remota recibida)'; Severity = 'High'; Stage = 'Movimiento lateral' },
        @{ Pattern = 'PsExec*.exe'; Name = 'PsExec'; Severity = 'Medium'; Stage = 'Movimiento lateral' },
        @{ Pattern = 'AnyDesk*.exe'; Name = 'AnyDesk'; Severity = 'High'; Stage = 'Persistencia' },
        @{ Pattern = 'remoting_host.exe'; Name = 'Chrome Remote Desktop host'; Severity = 'High'; Stage = 'Persistencia' },
        @{ Pattern = 'chromeremotedesktop*.msi'; Name = 'Instalador Chrome Remote Desktop'; Severity = 'High'; Stage = 'Persistencia' },
        @{ Pattern = 'Everything*.exe'; Name = 'Everything (voidtools)'; Severity = 'Medium'; Stage = 'Descubrimiento' },
        @{ Pattern = 'Everything.db'; Name = 'Indice de Everything'; Severity = 'Medium'; Stage = 'Descubrimiento' },
        @{ Pattern = 'Everything.ini'; Name = 'Configuracion de Everything'; Severity = 'Low'; Stage = 'Descubrimiento' },
        @{ Pattern = 'advanced_ip_scanner*'; Name = 'Advanced IP Scanner'; Severity = 'Medium'; Stage = 'Descubrimiento' },
        @{ Pattern = 'netscan*.exe'; Name = 'SoftPerfect Network Scanner'; Severity = 'Medium'; Stage = 'Descubrimiento' },
        @{ Pattern = 'WinSCP*.exe'; Name = 'WinSCP'; Severity = 'Medium'; Stage = 'Exfiltracion' },
        @{ Pattern = 'WinSCP.ini'; Name = 'Configuracion de WinSCP (sesiones guardadas)'; Severity = 'Low'; Stage = 'Exfiltracion' },
        @{ Pattern = 'MEGAcmd*.exe'; Name = 'MEGAcmd'; Severity = 'High'; Stage = 'Exfiltracion' },
        @{ Pattern = 'MEGAclient.exe'; Name = 'MEGAcmd client'; Severity = 'High'; Stage = 'Exfiltracion' },
        @{ Pattern = 'mega-*.bat'; Name = 'Scripts de MEGAcmd'; Severity = 'High'; Stage = 'Exfiltracion' },
        @{ Pattern = 'MEGAsync*.exe'; Name = 'MEGAsync'; Severity = 'High'; Stage = 'Exfiltracion' },
        @{ Pattern = 'rclone*.exe'; Name = 'Rclone'; Severity = 'High'; Stage = 'Exfiltracion' },
        @{ Pattern = 'rclone.conf'; Name = 'Configuracion de Rclone (destinos remotos)'; Severity = 'High'; Stage = 'Exfiltracion' },
        @{ Pattern = '7z2408-x64.exe'; Name = 'Instalador 7-Zip 24.08 (el usado por NightSpire)'; Severity = 'Medium'; Stage = 'Exfiltracion' },
        @{ Pattern = 'qtox*.exe'; Name = 'qTox'; Severity = 'Medium'; Stage = 'Comunicacion' },
        @{ Pattern = 'tor.exe'; Name = 'Tor'; Severity = 'Medium'; Stage = 'Comunicacion' }
    )

    # Texto buscado dentro de lineas de comando, rutas de servicios, tareas y claves Run
    ToolKeywords        = @(
        'anydesk', 'chrome remote desktop', 'chromoting', 'remoting_host',
        'mimikatz', 'psexesvc', 'psexec', 'everything.exe',
        'advanced_ip_scanner', 'advanced ip scanner', 'netscan',
        'winscp', 'megacmd', 'megasync', 'megaclient', 'mega-', 'rclone',
        '\enc.exe', '\v7.exe', 'qtox', '\tor.exe'
    )

    # Nombres en "Programas y caracteristicas"
    SoftwareNames       = @(
        'AnyDesk*', 'Chrome Remote Desktop*', '*MEGAsync*', '*MEGAcmd*', 'WinSCP*',
        'Everything *', 'Advanced IP Scanner*', '*Rclone*', 'VMware Workstation*',
        'WPS Office*', 'Tor Browser*', 'qTox*', 'TeamViewer*', '*Splashtop*',
        '*ScreenConnect*', '*RustDesk*', '*Atera*', '*SoftPerfect Network Scanner*'
    )

    ServiceNames        = @('chromoting', 'Chrome Remote Desktop*', 'AnyDesk*', 'PSEXESVC*', '*RustDesk*', '*ScreenConnect*', '*Splashtop*', 'TeamViewer*', '*Atera*')

    # Carpetas donde -InitCanary crea los archivos senuelo
    CanaryDirs          = @('C:\', 'C:\Users\Public\Documents')

    # Excepciones: patrones con * comparados contra la ruta y contra la clave (columna Key del CSV)
    # de cada hallazgo. Lo que coincida se omite del informe. Ejemplos:
    #   '*\Program Files (x86)\WinSCP\*'
    #   'SOFT|VMware Workstation*'
    #   'SERVICIO|AnyDesk*'
    Allowlist           = @()
}
