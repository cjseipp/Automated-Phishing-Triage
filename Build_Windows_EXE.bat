@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if %errorlevel%==0 (
  set "PY=py -3"
) else (
  set "PY=python"
)
%PY% -m pip install --upgrade pyinstaller
if errorlevel 1 goto :error
%PY% -m PyInstaller --noconfirm --clean --onefile --windowed --name PhishingTriageAssistant --paths . desktop\app.py
if errorlevel 1 goto :error
echo.
echo Build complete: dist\PhishingTriageAssistant.exe
echo Test on another Windows computer before distribution.
pause
exit /b 0
:error
echo Build failed. Review errors above.
pause
exit /b 1
