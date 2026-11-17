@echo off
rem ============================================================================
rem  NightSpire-Hunter - lanzador
rem  Doble clic (o "Ejecutar como administrador") para un escaneo rapido.
rem  Tambien acepta los parametros del script, por ejemplo:
rem     NightSpire-Hunter.cmd -Mode Full -DaysBack 90 -Path "D:\Datos;E:\Compartido"
rem  Compatible con Windows Server 2008 (con PowerShell 2.0), 2008 R2, 2012, 2016+.
rem ============================================================================
setlocal
set "RC=3"
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS%" (
    echo [ERROR] Este equipo no tiene PowerShell instalado.
    echo         Windows Server 2008 SP2: instalar "Windows Management Framework 2.0" ^(KB968930^).
    goto :fin
)

rem PowerShell 1.0 no sirve: no tiene $PSVersionTable y devuelve 0
"%PS%" -NoProfile -Command "exit $PSVersionTable.PSVersion.Major" >nul 2>&1
if %ERRORLEVEL% LSS 2 (
    echo [ERROR] Se necesita PowerShell 2.0 o superior ^(este equipo tiene la 1.0^).
    echo         Windows Server 2008 SP2: instalar "Windows Management Framework 2.0" ^(KB968930^).
    goto :fin
)

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [AVISO] No se esta ejecutando como Administrador: el resultado sera PARCIAL.
    echo         Clic derecho sobre este archivo ^> "Ejecutar como administrador".
    echo.
)

"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0NightSpire-Hunter.ps1" %*
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" echo Resultado: sin hallazgos relevantes.
if "%RC%"=="1" echo Resultado: hay hallazgos MEDIOS para revisar.
if "%RC%"=="2" echo Resultado: hay hallazgos ALTOS o CRITICOS. Revisar el informe.
if "%RC%"=="3" echo Resultado: el escaner no pudo iniciar ^(ver el error de arriba^).

:fin
rem Si se abrio con doble clic (sin parametros), dejar la ventana abierta
if "%~1"=="" pause
endlocal & exit /b %RC%
