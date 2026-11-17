# Cambios

## 1.3 — 2026-11-17

- `iocs.local.psd1` opcional para indicadores y excepciones propios de cada organización; se suma a `iocs.psd1` y no se publica. El instalador y el script remoto lo copian si existe.
- `iocs.psd1` queda solo con indicadores públicos.
- Documentación separada: guía de despliegue, perfil de NightSpire y guía para contribuir.

## 1.2 — 2026-11-16

- Funciona en Windows Server 2008 sin R2 sin .NET 3.5: si `Get-WinEvent` no está disponible, lee los eventos con `wevtutil.exe`.
- Segunda vía de lectura segura de `iocs.psd1` para PowerShell 2.0.
- Parámetro `-ForceWevtutil` para probar esa vía.

## 1.1 — 2026-11-16

- Compatible con PowerShell 2.0 (Windows Server 2008 SP2 con WMF 2.0 y 2008 R2).
- IOCs en `iocs.psd1` (antes `iocs.json`).
- Lanzador `NightSpire-Hunter.cmd`.

## 1.0 — 2026-11-16

- Primera versión: archivos, notas, herramientas, hashes, canarios, procesos, servicios, persistencia, artefactos, Defender, red y registros de eventos; tarea programada e informes con marca de nuevos.
