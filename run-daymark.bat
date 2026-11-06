@echo off
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 goto use_py
where python >nul 2>nul
if not errorlevel 1 goto use_python
echo Python was not found. Open index.html directly, or install Python to use offline and install support.
pause
exit /b 1

:use_py
start "Daymark local server" /min py -m http.server 8765 --bind 127.0.0.1
goto open_app

:use_python
start "Daymark local server" /min python -m http.server 8765 --bind 127.0.0.1

:open_app
timeout /t 2 /nobreak >nul
start "" http://127.0.0.1:8765/index.html
