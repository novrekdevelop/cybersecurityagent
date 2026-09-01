@echo off
chcp 65001 >nul
title CyberAudit Pro - Web security audit
color 0B
set "DIR=%~dp0"
cd /d "%DIR%"

where python >nul 2>nul
if errorlevel 1 (
    cls
    echo.
    echo  [ERROR] Python was not found on the system.
    echo  Install it from https://www.python.org/downloads/
    echo  and check the "Add Python to PATH" box.
    echo.
    pause
    exit /b 1
)

:menu
cls
echo.
echo  ============================================================
echo     CYBERAUDIT PRO - Web security audit
echo  ============================================================
echo.
echo  Professional cybersecurity analysis tool.
echo  * LEGAL USE: only on websites you own or with permission from the owner.
echo.
echo   [1] Full audit (headers, content, paths, DNS, APIs, logins and payments)
echo   [2] Audit + port scanning + subdomains
echo   [3] Exhaustive audit (+ benign active tests: XSS, redirect, GraphQL)
echo   [4] Default credential test on the login (--fuzz-login)
echo   [5] Exit
echo.
set "op="
set /p "op=Choose an option (1-5): "

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
echo     CYBERAUDIT PRO - Web security audit
echo  ============================================================
echo.
echo  Enter the URL to audit.
echo  Example: yourdomain.com   or   https://myweb.es/panel
echo.
set "URL="
set /p "URL=URL: "
if "%URL%"=="" goto pedir

cls
echo  Auditing %URL% ...
echo  (it may take a few minutes. Do not close this window)
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
    echo  [ERROR] The audit could not be completed.
    echo  Check the URL and your Internet connection.
    pause
    goto menu
)
echo.
echo  ============================================================
echo     RESULTS
echo  ============================================================
set "ultimo="
for /f "delims=" %%i in ('dir /b /o:-d reports\*.html 2^>nul') do if not defined ultimo set "ultimo=%%i"
if defined ultimo (
    echo  Opening the HTML report: %ultimo%
    start "" "%DIR%\reports\%ultimo%"
) else (
    echo  No HTML report found. Check the reports folder.
)
echo.
set "op2="
set /p "op2=Press ENTER to return to the menu, or 's' to exit: "
if /i "%op2%"=="s" exit /b 0
goto menu