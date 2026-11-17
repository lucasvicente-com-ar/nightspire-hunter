# Cómo contribuir

Se aceptan IOCs nuevos, correcciones y mejoras. Para reportar un problema, abrir un *issue* con la versión de Windows y de PowerShell (`$PSVersionTable`) y el texto de los avisos del informe. **No pegar datos internos** (nombres de equipos, IP privadas, usuarios) en un *issue* público.

## Agregar indicadores

Todo está en [`iocs.psd1`](iocs.psd1); el script no necesita cambios. Solo se aceptan indicadores **públicos** con su fuente (un comentario en la línea o en la descripción del *pull request*). Lo propio de una organización va en `iocs.local.psd1`, que no se sube.

| Clave | Qué es |
|---|---|
| `EncryptedExtensions` | Extensiones de archivos cifrados. |
| `RansomNoteNames`, `RansomNoteWildcards` | Nombres exactos o con `*` de notas de rescate. |
| `GenericNoteNames` + `NoteContentMarkers` | Nombres comunes (`readme.txt`) que solo se informan si el contenido tiene algún marcador. |
| `Sha256` | Tabla `'hash' = 'descripción'`, **sin comas** entre entradas. |
| `IPs`, `Cidrs` | Infraestructura del atacante. |
| `WatchRanges` | Redes que no son maliciosas pero merecen revisión (normalmente solo en el archivo local). |
| `AttackerHostnames`, `Emails`, `DnsPatterns` | Otros indicadores. |
| `Tools` | Archivos buscados por nombre: `@{ Pattern; Name; Severity; Stage }`. Severidades: `Critical`, `High`, `Medium`, `Low`, `Info`. |
| `ToolKeywords` | Texto buscado en líneas de comando, servicios, tareas y claves Run. |
| `SoftwareNames`, `ServiceNames` | Programas instalados y servicios. |
| `CanaryDirs` | Dónde crear los archivos señuelo. |
| `Allowlist` | Excepciones. |

Al cambiar `iocs.psd1`, actualizar `Version` con la fecha.

## Modificar el código: compatibilidad con PowerShell 2.0

El objetivo es que el mismo archivo funcione en Windows Server 2008 SP2 con PowerShell 2.0 y .NET 2.0. Reglas:

- No usar `[pscustomobject]`, `-in` / `-notin`, `Get-CimInstance`, `ConvertTo-Json` / `ConvertFrom-Json` sin comprobar antes que existen, `-Raw`, `-Directory` / `-File` de `Get-ChildItem`, `Copy-Item -ToSession`, `Unblock-File` sin comprobar, ni métodos de .NET 4 (`EnumerateFiles`, `HashSet`, `String.IsNullOrWhiteSpace`).
- Envolver en `@()` todo resultado que se recorra o se cuente: en PowerShell 2.0 un `foreach` sobre `$null` itera una vez y un valor suelto no tiene `.Count`. `Get-Ev` siempre se llama como `@(Get-Ev ...)`.
- Eventos: usar `Get-Ev`, `Test-Log` y `Get-LogNames`, que eligen entre `Get-WinEvent` y `wevtutil.exe`. No llamar a `Get-WinEvent` directamente.
- Objetos: `New-Obj @{...}` (equivale a `New-Object PSObject -Property`).
- Archivos `.ps1`, `.psd1` y `.cmd` en **ASCII puro** (sin acentos) y con fin de línea CRLF: PowerShell 2.0 lee mal UTF-8 sin BOM, y `cmd.exe` falla con LF. `.gitattributes` fuerza el CRLF.
- Todo módulo nuevo tiene que ser de **solo lectura** y no debe cortar el escaneo si falla: capturar el error y registrar un aviso con `Add-Note`.

Hallazgos nuevos: `Add-Finding` con una clave estable (la misma en cada ejecución para el mismo hecho), que es lo que permite marcar `[NUEVO]` y usar `Allowlist`.

## Probar

Como mínimo, antes de un *pull request*:

```powershell
# Archivos de prueba en una carpeta aparte
.\NightSpire-Hunter.ps1 -Path C:\prueba -PathOnly -SkipEventLogs -DataDir C:\prueba-datos
# Escaneo real
.\NightSpire-Hunter.ps1 -DataDir C:\prueba-datos
# Misma lectura de eventos que en Server 2008
.\NightSpire-Hunter.ps1 -DataDir C:\prueba-datos2 -ForceWevtutil
```

Y verificar: que no haya avisos de error nuevos en el informe, que una segunda ejecución no marque nada como `[NUEVO]`, y que los archivos sigan siendo ASCII. Si se puede, probar en una máquina con PowerShell 2.0 (Windows 7 / Server 2008 R2) o en una de Server 2008.
