@echo off
chcp 65001 >nul
title CyberAudit Pro - Auditoria de seguridad web
color 0B
set "DIR=%~dp0"
cd /d "%DIR%"

where python >nul 2>nul
if errorlevel 1 (
    cls
    echo.
    echo  [ERROR] No se encuentró Python en el sistema.
    echo  Instalalo desde https://www.python.org/downloads/
    echo  y marca la casilla "Add Python to PATH".
    echo.
    pause
    exit /b 1
)

:menu
cls
echo.
echo  ============================================================
echo     CYBERAUDIT PRO - Auditoria de seguridad web
echo  ============================================================
echo.
echo  Herramienta profesional de analisis de ciberseguridad.
echo  * USO LEGAL: solo en webs tuyas o con permiso del dueno.
echo.
echo   [1] Auditoria completa (cabeceras, contenido, rutas, DNS, APIs, logins y pagos)
echo   [2] Auditoria + escaneo de puertos + subdominios
echo   [3] Auditoria exhaustiva (+ pruebas activas benignas: XSS, redirect, GraphQL)
echo   [4] Prueba de credenciales por defecto en el login (--fuzz-login)
echo   [5] Salir
echo.
set "op="
set /p "op=Elige una opcion (1-5): "

if "%op%"=="1" (set "modo=1" & goto pedir)
if "%op%"=="2" (set "modo=2" & goto pedir)
if "%op%"=="3" (set "modo=3" & goto pedir)
if "%op%"=="4" (set "modo=4" & goto pedir)
if "%op%"=="5" exit /b 0
goto menu

:pedir
cls
echo.
echo  ============================================================
echo     CYBERAUDIT PRO - Auditoria de seguridad web
echo  ============================================================
echo.
echo  Introduce la URL a auditar.
echo  Ejemplo: tudominio.com   o   https://miweb.es/panel
echo.
set "URL="
set /p "URL=URL: "
if "%URL%"=="" goto pedir

cls
echo  Auditando %URL% ...
echo  (puede tardar unos minutos. No cierres esta ventana)
echo.
if "%modo%"=="3" goto nivel3
if "%modo%"=="2" goto nivel2
if "%modo%"=="4" goto nivel4
goto nivel1

:nivel1
python main.py -u "%URL%" --yes -f json md html
goto fin

:nivel2
python main.py -u "%URL%" --yes --ports --subdomains -f json md html
goto fin

:nivel3
python main.py -u "%URL%" --yes --ports --active -f json md html
goto fin

:nivel4
python main.py -u "%URL%" --yes --fuzz-login --include fuzzer -f json html
goto fin

:fin
if errorlevel 1 (
    echo.
    echo  [ERROR] No se pudo completar la auditoria.
    echo  Comprueba la URL y tu conexion a Internet.
    pause
    goto menu
)
echo.
echo  ============================================================
echo     RESULTADO
echo  ============================================================
set "ultimo="
for /f "delims=" %%i in ('dir /b /o:-d reports\*.html 2^>nul') do if not defined ultimo set "ultimo=%%i"
if defined ultimo (
    echo  Abriendo el informe HTML: %ultimo%
    start "" "%DIR%\reports\%ultimo%"
) else (
    echo  No se localizo informe HTML. Revisa la carpeta reports.
)
echo.
set "op2="
set /p "op2=Pulsa ENTER para volver al menu, o 's' para salir: "
if /i "%op2%"=="s" exit /b 0
goto menu