# Despliegue en una organización

Guía para quien tiene que poner NightSpire-Hunter a funcionar en varios servidores Windows, después de un incidente o de forma preventiva.

## 1. Preparar

- [ ] Descargar el repositorio y copiarlo a una carpeta local de una estación de administración (por ejemplo `C:\Herramientas\NightSpire-Hunter`). Si se bajó como ZIP, desbloquearlo antes de extraer (Propiedades → Desbloquear).
- [ ] Hacer la lista de servidores Windows a cubrir, empezando por los críticos: respaldos (Veeam), controladores de dominio, servidores de archivos, bases de datos, estaciones de administración y equipos con RDP expuesto.
- [ ] Anotar la versión de cada uno. Los Server 2008 sin R2 necesitan WMF 2.0 (KB968930) antes de empezar; ver el [README](../README.md#server-2008-sin-r2).
- [ ] Si hubo un incidente: copiar `iocs.local.example.psd1` como `iocs.local.psd1` y cargar lo propio (texto de la nota recibida, IP de los registros del firewall, pool de la VPN en `WatchRanges`). **No subir ese archivo a ningún repositorio público.**

## 2. Probar en un servidor de cada versión

- [ ] Copiar la carpeta al disco local del servidor.
- [ ] Ejecutar `NightSpire-Hunter.cmd` como administrador.
- [ ] Revisar las líneas `AVISO:` al principio del informe. Es normal ver que leyó los eventos con `wevtutil.exe` (Server 2008) o que Defender no existe. Cualquier error de lectura o un corte del script hay que resolverlo antes de seguir.
- [ ] Revisar los hallazgos. La primera vez aparece todo como `[NUEVO]` y habrá software legítimo (AnyDesk de soporte, WinSCP de un administrador, etc.). Confirmar cada uno con el responsable del equipo.

## 3. Ajustar excepciones

- [ ] Lo confirmado como legítimo va en `Allowlist` de `iocs.local.psd1`, con el patrón más específico posible (la ruta exacta mejor que el nombre).
- [ ] Volver a ejecutar y verificar que esos hallazgos ya no aparecen y que el resto sigue.

## 4. Dejarlo programado

En cada servidor, como administrador, desde la carpeta copiada:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-ScheduledScan.ps1 -IntervalHours 4 -Canary -ExtraPath "D:\Datos"
```

O en todos a la vez desde la estación de administración (necesita WinRM habilitado en los destinos):

```powershell
.\Invoke-RemoteScan.ps1 -ComputerName (Get-Content .\servidores.txt) -Credential (Get-Credential) -Install
```

- [ ] Verificar en el Programador de tareas que existen `NightSpireHunter-Quick` y `NightSpireHunter-Full`, ejecutándose como SYSTEM.
- [ ] Verificar que `C:\ProgramData\NightSpireHunter` solo tiene permisos para SYSTEM y Administradores (la tarea corre como SYSTEM: si otro usuario pudiera modificar el script, podría elevar privilegios).

## 5. Conectar al SIEM

- [ ] Recolectar del registro **Aplicación** los eventos del origen `NightSpireHunter`.
- [ ] Alertar con prioridad alta por el evento **9002** (hallazgos altos o críticos nuevos) y media por el **9001**.
- [ ] Alertar también si un servidor pasa más de dos intervalos sin registrar ningún evento 9000/9001/9002: puede significar que la tarea se desactivó.
- [ ] Opcional: `-CentralShare \\servidor\recurso` en el instalador para juntar todos los informes en un solo lugar (la cuenta de equipo de cada servidor necesita permiso de escritura).

## 6. Mantener

- [ ] Revisar periódicamente las fuentes de [docs/NIGHTSPIRE.md](NIGHTSPIRE.md#fuentes) y actualizar `iocs.psd1` con hashes, nombres de nota o herramientas nuevas.
- [ ] Para distribuir IOCs nuevos, volver a ejecutar el instalador (o `Invoke-RemoteScan.ps1 -Install`): guarda copia de los archivos de IOCs anteriores antes de reemplazarlos.
- [ ] Activar la auditoría que el escáner aprovecha si no está: creación de procesos con línea de comandos (4688), registro de bloques de PowerShell (4104) y creación de tareas (4698).

## Desinstalar

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-ScheduledScan.ps1 -Uninstall
```

Quita las tareas. Los informes y el script quedan en `C:\ProgramData\NightSpireHunter` hasta que se borre la carpeta a mano.
