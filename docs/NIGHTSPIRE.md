# Cómo opera NightSpire

Resumen de fuentes públicas (ver [Fuentes](#fuentes)) y de lo observado en un incidente de 2026 en Argentina. Donde las fuentes no coinciden, se indica. Sirve para entender qué busca el escáner y por qué.

## Perfil

- Grupo de doble extorsión visto desde febrero-marzo de 2025; sitio de filtraciones identificado el 12/03/2025. Operadores conocidos por los alias `xdragon128` (también `Xdragon333`) y `cuteliyuan`.
- Modelo de negocio discutido: Halcyon y Proven Data lo describen como grupo cerrado; Barracuda dice que anunció un esquema de afiliados (RaaS) en abril de 2026. Huntress señala que los TTP cambian de un incidente a otro, lo que es compatible con afiliados.
- Rescates de 150 000 a 2 000 000 USD, con plazos de 48 a 72 horas y descuentos escalonados por pago rápido.
- Presión: publican el nombre parcial de la víctima y luego el completo, escriben a empleados y publican fragmentos de la negociación.

## Cadena de ataque

| Etapa | Qué hacen | Qué deja en Windows |
|---|---|---|
| Acceso inicial | Explotación de **CVE-2024-55591** (bypass de autenticación en FortiOS/FortiProxy que da super-admin por el módulo WebSocket de Node.js). También fuerza bruta de RDP/VPN, phishing, fatiga de MFA y abuso de herramientas RMM. | En el FortiGate: administradores nuevos, cambios de políticas, usuarios SSL-VPN agregados. En Windows: 4625 masivos, RDP desde IP externas o desde el pool de la VPN. |
| Persistencia | **AnyDesk** (servicio + acceso directo de inicio) y **Chrome Remote Desktop** (servicio `chromoting`, atado a una cuenta de Google del atacante). Algunas fuentes mencionan claves Run/RunOnce, tareas programadas e IFEO, sin nombres concretos. | Servicios nuevos (7045), `C:\ProgramData\AnyDesk`, `host.json` de Chrome Remote Desktop. |
| Credenciales | **Mimikatz** sobre LSASS; credenciales guardadas. | Detecciones de Defender, 4688/4104 con `sekurlsa`, volcados de LSASS. |
| Descubrimiento | **Everything** (voidtools) para ubicar archivos de interés; **Advanced IP Scanner** para la red. | `Everything.exe`, `Everything.db`, Prefetch. |
| Movimiento lateral | RDP, **PsExec** sobre recursos administrativos, WMI, PowerShell remoto. | Servicio `PSEXESVC`, 4624 tipo 3/10, 7045. |
| Recolección y exfiltración | **7-Zip** para empaquetar (a veces con contraseña) y salida por **MEGAcmd/MEGAsync**, **WinSCP** o **Rclone**. | Archivos comprimidos grandes en carpetas de paso, `rclone.conf`, sesiones de WinSCP, datos de MEGA, DNS hacia `mega.nz`. |
| Impacto | Cifrador en **Go**, normalmente llamado `enc.exe` y lanzado a mano. Suelen borrar respaldos (Veeam) antes de cifrar. | `.nspire`, nota de rescate en cada carpeta, eliminaciones en Veeam. |

En un caso de marzo de 2026 (Huntress) el orden fue: RDP → Chrome Remote Desktop → Everything → MEGAsync dos días después → VMware Workstation → 7-Zip → WPS Office al día siguiente → cifrado. Todo descargado al equipo; la carpeta de trabajo del atacante era `Descargas` del usuario comprometido. Por eso el escáner mira con atención las carpetas de paso.

## El cifrador

- Binario en Go. Cifrado híbrido: una clave AES por archivo, envuelta con la clave pública RSA del atacante y agregada al final del archivo.
- **Cifrado parcial** en archivos grandes: bloques de 1 MB para `.iso .vhdx .vmdk .zip .vib .bak .mdf .flt .ldf`; el resto se cifra completo.
- Extensión `.nspire`; en 2026 también se vio `.0nspire`. Los archivos de OneDrive se cifran **sin** cambiar nombre ni extensión.
- Nombres de nota que cambian entre campañas: `readme.txt`, `_nightspire_readme.txt` (dic-2025), `[nspire_msg].txt` (mar-2026), `[NSPIRE_README].txt` (oct-2026).
- **No borra las instantáneas de volumen** en los casos observados. En un Windows afectado conviene revisar `vssadmin list shadows` antes de restaurar.
- Los hashes cambian entre incidentes (compilaciones por operación): no encontrar un hash conocido no descarta nada.
- Halcyon indica que la variante ESXi/Linux estaba "en desarrollo", pero hay casos de 2026 con entornos ESXi afectados: no hay que descartar daño en la virtualización.

## Indicadores públicos

Están en [`iocs.psd1`](../iocs.psd1). Los principales:

| Tipo | Valor | Origen |
|---|---|---|
| SHA-256 | `bde50a42efc079edde1a314243ad339db2d42e343fbbcd39117803b0f5960355` — `enc.exe` | Huntress, 02/12/2025 |
| SHA-256 | `ad67031e2ca68764fe1a7d6632c02b02a299d59efb920710011a9a2ccf4399b7` — `enc.exe` | Huntress, 25/03/2026 |
| SHA-256 | `e275b8a02bf23b565bdaabadb220b39409eddc6b8253eb04e0f092d697e3b53d` — `v7.exe` | 0x70RVS, Halcyon |
| SHA-256 | `35cefe4bc4a98ad73dda4444c700aac9f749efde8f9de6a643a57a5b605bd4e7` — `Everything.exe` según S-RM (fuente original); Halcyon lo rotula como payload | S-RM, 25/03/2025 |
| IP | `14.139.185.60` — servidor remoto de WinSCP (S-RM, Barracuda) o C2 (Halcyon). Posible equipo académico comprometido; no se sabe si sigue activo | S-RM |
| Equipos del atacante | `XDRAGON-SERVER1`, `WINDOWS-DTX-8GB` (aparecen como nombre de estación en eventos 4624/4625) | S-RM |
| Cuenta | `prince1990905@gmail.com` (dueña del host de Chrome Remote Desktop) | Huntress |

Dato sin respaldo de una segunda fuente: 0x70RVS asocia al grupo con infostealers (Azorult, Lumma, RedLine, Vidar) sin citar evidencia.

Los indicadores de una intrusión concreta (datos de la nota recibida, IP vistas en los propios registros, redes internas) van en `iocs.local.psd1`, que no se publica. Ver el [README](../README.md#indicadores-propios-iocslocalpsd1).

## Qué revisar a mano además del escáner

1. **FortiGate / firewall**: administradores y usuarios locales no reconocidos, cambios de políticas, `diagnose debug crashlog read`, versión de FortiOS frente a CVE-2024-55591, y archivos de persistencia por symlink en el sistema de archivos del equipo.
2. **Veeam**: historial de sesiones y de eliminación de respaldos, cuentas de la consola, y credenciales guardadas (rotarlas todas: las guardadas en Veeam se pueden extraer).
3. **vCenter / ESXi**: `hostd.log`, `auth.log`, `shell.log`; SSH habilitado; accesos desde el pool de la VPN.
4. **Directorio Activo**: cuentas creadas desde el inicio estimado de la intrusión, cambios en grupos privilegiados, y doble rotación de `krbtgt` si hubo Mimikatz en un controlador de dominio.
5. **OneDrive / archivos sincronizados**: archivos que no abren aunque conserven la extensión.

## Fuentes

- [S-RM — Ransomware in focus: Meet NightSpire](https://www.s-rminform.com/latest-thinking/ransomware-in-focus-meet-nightspire)
- [Huntress — Leveling Up with NightSpire Ransomware](https://www.huntress.com/blog/nightspire-ransomware)
- [Halcyon — NightSpire](https://www.halcyon.ai/threat-group/nightspire)
- [Barracuda — NightSpire: Wannabe warlords in ransomware's shadow realm](https://blog.barracuda.com/2026/05/01/nightspire-wannabe-warlords-in-ransomwares-shadow-realm)
- [Proven Data — NightSpire Ransomware](https://www.provendata.com/blog/nightspire-ransomware)
- [0x70RVS — NightSpire APT Profiling](https://7orvs.github.io/apt%20profiling/NightSpire-APT-Group-Profiling/)
- [Cyber Security News — NightSpire uses RDP access and remote admin tools](https://cybersecuritynews.com/nightspire-ransomware-uses-rdp-access-and-remote-admin-tools/)
- [SOC Prime — NightSpire Ransomware: RDP Intrusions and Tooling Abuse](https://socprime.com/active-threats/nightspire-ransomware-evolves-updated-techniques-and-detection-tips/)
