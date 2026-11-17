# NightSpire-Hunter

Herramienta defensiva para servidores Windows: busca archivos, herramientas, persistencia y registros que deja una intrusión del ransomware **NightSpire**, y puede quedar corriendo como tarea programada para avisar si aparece algo nuevo.

Es de **solo lectura**: no borra, no pone en cuarentena ni modifica nada del sistema. Lo único que escribe son sus informes, su archivo de estado y, si se pide, archivos canario.

Funciona desde **Windows Server 2008 SP2** (con PowerShell 2.0) hasta Server 2022, con el mismo archivo, sin instalar nada más.

- ¿Qué es NightSpire y cómo opera? → [docs/NIGHTSPIRE.md](docs/NIGHTSPIRE.md)
- ¿Cómo lo despliego en una organización, paso a paso? → [docs/DESPLIEGUE.md](docs/DESPLIEGUE.md)
- ¿Cómo agrego indicadores o modifico el código? → [CONTRIBUTING.md](CONTRIBUTING.md)

## Archivos

| Archivo | Para qué sirve |
|---|---|
| `NightSpire-Hunter.cmd` | Lanzador: doble clic o "Ejecutar como administrador". Comprueba que haya PowerShell 2.0 o superior y llama al escáner. |
| `NightSpire-Hunter.ps1` | El escáner. |
| `iocs.psd1` | Indicadores públicos de NightSpire (hashes, IP, nombres de herramientas y de notas). Se edita sin tocar el script. |
| `iocs.local.example.psd1` | Plantilla para `iocs.local.psd1`: indicadores y excepciones **propios** de tu organización, que no se publican. |
| `Install-ScheduledScan.ps1` | Instala el escáner en `C:\ProgramData\NightSpireHunter` y crea las tareas programadas. |
| `Invoke-RemoteScan.ps1` | Lanza el escaneo (o la instalación) en varios servidores por WinRM y trae los informes. |

## Inicio rápido

1. Descargar el repositorio (botón **Code → Download ZIP** o `git clone`) y copiar la carpeta a un **disco local** del servidor. No ejecutarlo desde un recurso compartido ni desde una carpeta sincronizada (Google Drive, OneDrive).
2. Si el ZIP se bajó de Internet, desbloquearlo antes de extraerlo: clic derecho → Propiedades → **Desbloquear**.
3. Opcional: copiar `iocs.local.example.psd1` como `iocs.local.psd1` y cargar los datos propios del incidente (ver [Indicadores propios](#indicadores-propios-iocslocalpsd1)).
4. Clic derecho sobre `NightSpire-Hunter.cmd` → **Ejecutar como administrador**.
5. Leer el informe: `C:\ProgramData\NightSpireHunter\reports\ULTIMO_<equipo>.txt`.

Sin privilegios de administrador no se leen el registro Security, Prefetch ni los perfiles de otros usuarios; el informe lo avisa.

## Compatibilidad

Los scripts usan solo lo que existe en **PowerShell 2.0 / .NET 2.0**:

| Sistema | PowerShell que trae | Qué hace falta |
|---|---|---|
| Windows Server 2008 SP2 | 1.0 (opcional) | Instalar una vez **Windows Management Framework 2.0 (KB968930)**. El lanzador `.cmd` avisa si falta. |
| Windows Server 2008 R2 / Windows 7 | 2.0 | Nada. |
| Windows Server 2012 / 2012 R2 | 3.0 / 4.0 | Nada. |
| Windows Server 2016 / 2019 / 2022, Windows 10/11 | 5.1 | Nada. |

### Server 2008 sin R2

1. Confirmar que tiene **Service Pack 2** (`winver`). WMF 2.0 no se instala sin SP2.
2. Descargar desde el Catálogo de Microsoft Update, en otra PC, el paquete **KB968930** para Windows Server 2008 (x86 o x64), copiarlo al servidor e instalarlo. Puede pedir reinicio.
3. Ejecutar `NightSpire-Hunter.cmd` como administrador.

No hace falta .NET 3.5: si el cmdlet de eventos de PowerShell no funciona, el escáner lee los registros con `wevtutil.exe`, que viene con Windows, y lo indica en el informe. Por esa vía los textos con acentos pueden verse mal en el detalle, pero los hallazgos son los mismos.

Diferencias según la versión:

- En PowerShell 2.0 no se genera `hallazgos.json` (sí el informe de texto y el CSV).
- Los módulos de Microsoft Defender solo corren donde existe (2016 en adelante); en 2008 se omiten sin error.
- En Server 2008 no existe el registro de bloques de PowerShell (evento 4104).

## Uso

Escaneo único desde una consola como administrador:

```bat
NightSpire-Hunter.cmd
```

Escaneo completo de todos los discos, 90 días de eventos y carpetas de datos adicionales (separadas por punto y coma dentro de las mismas comillas):

```bat
NightSpire-Hunter.cmd -Mode Full -DaysBack 90 -Path "D:\Datos;E:\Compartido"
```

Dejarlo corriendo cada 4 horas (Quick) y un completo los domingos 03:00, con canarios:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-ScheduledScan.ps1 -IntervalHours 4 -Canary
```

Varios servidores a la vez por WinRM (instala la tarea en cada uno y trae los informes a `.\resultados\`):

```powershell
.\Invoke-RemoteScan.ps1 -ComputerName (Get-Content .\servidores.txt) -Credential (Get-Credential) -Install
```

Quitar las tareas:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-ScheduledScan.ps1 -Uninstall
```

### Parámetros del escáner

| Parámetro | Por defecto | Descripción |
|---|---|---|
| `-Mode Quick\|Full` | `Quick` | Quick: perfiles, ProgramData, temporales, papelera y dos niveles de cada disco (unos 300 000 archivos en un minuto). Full: todos los discos fijos. |
| `-DaysBack N` | `60` | Días hacia atrás para eventos y archivos "recientes". |
| `-Path "a;b"` | | Carpetas adicionales a recorrer completas. |
| `-PathOnly` | | Recorre solo las carpetas de `-Path`, no los discos. |
| `-IocFile ruta` | `iocs.psd1` junto al script | Otro archivo de indicadores. Se busca `iocs.local.psd1` en la misma carpeta. |
| `-DataDir ruta` | `C:\ProgramData\NightSpireHunter` | Estado e informes. |
| `-OutputDir ruta` | `<DataDir>\reports` | Solo los informes. |
| `-CentralShare \\srv\recurso` | | Copia cada informe a una carpeta compartida (subcarpeta por equipo). |
| `-InitCanary` | | Crea archivos señuelo en `CanaryDirs`. |
| `-SkipFileScan`, `-SkipEventLogs` | | Omite esos módulos. |
| `-MaxHashMB N` | `200` | Tamaño máximo de archivo para calcular SHA-256. |
| `-Quiet` | | Sin salida por consola (para tareas programadas). |
| `-ForceWevtutil` | | Lee los eventos con `wevtutil.exe` aunque haya alternativa (pruebas). |

Parámetros del instalador: `-IntervalHours` (1 a 23), `-DaysBack`, `-ExtraPath "a;b"`, `-CentralShare`, `-Canary`, `-NoFullWeekly`, `-RunNow`, `-Uninstall`.

## Qué revisa

| Módulo | Qué busca | Severidad típica |
|---|---|---|
| Archivos cifrados | Extensiones `.nspire` y `.0nspire`; cuenta, rango de fechas y carpetas. Si la cantidad **aumenta** entre ejecuciones avisa "cifrado en curso". | Crítica |
| Notas de rescate | `[NSPIRE_README].txt`, `[nspire_msg].txt`, `_nightspire_readme.txt`; y `readme.txt` solo si el contenido tiene marcadores de NightSpire. | Crítica |
| Hashes | SHA-256 de ejecutables en carpetas de paso y de procesos en ejecución contra los hashes conocidos. | Crítica |
| Herramientas | AnyDesk, Chrome Remote Desktop, Everything, MEGAcmd/MEGAsync, WinSCP, Rclone, Mimikatz, PsExec/PSEXESVC, Advanced IP Scanner, `enc.exe`, `v7.exe`. | Alta / Media |
| Carpetas de paso | Ejecutables recientes y archivos comprimidos > 200 MB en Descargas, Escritorio, Temp, Public, PerfLogs, raíz de disco. | Media / Baja |
| Canarios | Archivos señuelo; si se modifican, renombran o desaparecen. | Crítica |
| Procesos y servicios | Herramientas en ejecución, líneas de comando sospechosas, servicios de acceso remoto, servicio de eventos detenido. | Alta |
| Software instalado | Acceso remoto y exfiltración instalados (incluye VMware Workstation y WPS Office, vistos en un caso de 2026). | Media |
| Persistencia | Claves Run/RunOnce, IFEO con Debugger, carpetas de Inicio, tareas programadas. | Alta / Media |
| Artefactos | Sesiones guardadas de WinSCP, `rclone.conf`, datos de MEGA, conexiones entrantes de AnyDesk, cuenta de Google dueña del host de Chrome Remote Desktop, Prefetch, historial de PowerShell. | Alta / Media |
| Defender | Protección en tiempo real desactivada, exclusiones, eventos 5001/5007, detecciones 1116/1117. | Alta / Media |
| Red | Conexiones activas a IP de la lista; caché DNS con MEGA, Tor, OnionMail, AnyDesk. | Crítica / Media |
| Eventos | Borrado de registros (1102, 104), cambios de auditoría (4719), cuentas creadas (4720) y altas en grupos privilegiados, fallos de inicio de sesión (4625), RDP desde IP pública / de la lista / rangos vigilados / de madrugada, nombres de equipo de los operadores, servicios instalados (7045), comandos (4688 y 4104), tareas creadas (4698), eliminaciones en Veeam. | Variable |

## Salida

En `C:\ProgramData\NightSpireHunter\reports\`:

- `ULTIMO_<equipo>.txt`: el último informe, ordenado por severidad. Lo que no estaba en ejecuciones anteriores aparece como `[NUEVO]`.
- `<equipo>_<fecha>\informe.txt`, `hallazgos.csv`, `hallazgos.json`: cada ejecución.
- `historial.csv`: una línea por ejecución, para ver la evolución.

Además escribe un evento en el registro **Aplicación**, origen `NightSpireHunter`, para recolectarlo con el SIEM (Wazuh, Graylog, etc.):

| Evento | Significado |
|---|---|
| 9002 (Error) | Hay hallazgos altos o críticos **nuevos**. |
| 9001 (Advertencia) | Hay hallazgos medios nuevos. |
| 9000 (Información) | Nada nuevo. |

Código de salida: `0` sin hallazgos relevantes, `1` medios, `2` altos o críticos (cuenta todos, no solo los nuevos), `3` no pudo iniciar.

## Indicadores propios (`iocs.local.psd1`)

`iocs.psd1` trae solo indicadores públicos. Lo que es propio de cada organización va en `iocs.local.psd1`, en la misma carpeta:

- texto de la nota de rescate que recibieron (dirección onion, correo, ID de qTox): permite detectar copias de la nota aunque se llamen `readme.txt`;
- IP vistas en sus propios registros (fuerza bruta, C2, exfiltración);
- redes internas a vigilar en `WatchRanges` (por ejemplo, el pool de la VPN: un RDP desde ahí no es malicioso por sí mismo, pero merece revisión);
- hashes de muestras propias;
- excepciones (`Allowlist`).

Partir de `iocs.local.example.psd1`. Las listas se suman a las de `iocs.psd1`, las tablas se combinan. El archivo está en `.gitignore`, así que no se sube por accidente. El instalador y el script remoto lo copian a los servidores si existe. El informe indica `IOCs: <versión> + iocs.local.psd1` cuando lo cargó.

## Falsos positivos

Casi todo lo que usa NightSpire es software legítimo, así que un hallazgo **no** es prueba de intrusión: hay que mirar la fecha, la carpeta y quién lo instaló. Para silenciar lo que se confirmó como legítimo, agregar patrones en `Allowlist` de `iocs.local.psd1` (se comparan contra la ruta y contra la clave del hallazgo, columna `Key` del CSV):

```powershell
Allowlist = @('*\Program Files (x86)\WinSCP\*', 'SOFT|VMware Workstation*')
```

Usar patrones lo más específicos posible: `'SERVICIO|AnyDesk*'` también ocultaría un AnyDesk instalado por el atacante.

Los archivos `.psd1` son archivos de datos de PowerShell: comillas simples, elementos separados por coma, y la barra invertida se escribe una sola vez. El escáner los lee en modo restringido: no pueden ejecutar código.

## Límites

- **Lo que se probó:** ejecución real en Windows 11 con PowerShell 5.1 sin privilegios de administrador (archivos de prueba con extensiones, notas, herramientas y `rclone.conf`; canarios; segunda ejecución sin falsos "nuevos"), una revisión automática del código que confirma que no usa nada posterior a PowerShell 2.0, y la lectura de eventos por `wevtutil.exe`, que dio los mismos hallazgos que la vía normal.
- **Lo que no se probó todavía:** una ejecución real sobre PowerShell 2.0 / Server 2008, los módulos que requieren administrador (registro Security, Prefetch), el instalador y el script remoto. Antes de desplegar, correr `NightSpire-Hunter.cmd` como administrador en **un** servidor de cada versión y revisar que el informe salga sin avisos de error. Si encontrás un problema, abrí un *issue* con el texto del aviso.
- Los eventos 4688, 4104 y 4698 solo existen si la auditoría correspondiente está activada. Vale la pena activarla (creación de procesos con línea de comandos y registro de bloques de PowerShell).
- No inspecciona ESXi, vCenter, NAS ni el firewall; cubre los Windows (Veeam, servidores de aplicaciones y bases, estaciones de administración). Ver la lista de revisión manual en [docs/NIGHTSPIRE.md](docs/NIGHTSPIRE.md#qué-revisar-a-mano-además-del-escáner).
- Un atacante con privilegios de SYSTEM puede desactivar la tarea. La ausencia del evento 9000 durante más de un intervalo también es una señal: conviene alertar por eso en el SIEM.
- Los hashes cambian entre incidentes: no encontrar un hash conocido no descarta nada.

## Licencia

Pendiente de definir.
