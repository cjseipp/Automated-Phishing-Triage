@echo off
cd /d "%~dp0"
where py >nul 2>&1
if %errorlevel%==0 (
    py -3 desktop\app.py
) else (
    python desktop\app.py
)
if errorlevel 1 (
    echo.
    echo Could not start the application. Check that Python 3.10+ is installed.
    pause
)
