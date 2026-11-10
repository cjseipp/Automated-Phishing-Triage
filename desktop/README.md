# Phase 1.2 Desktop Interface

Double-click `Launch_Desktop.bat` from the project root on a Windows computer with Python 3.10+ installed. This is a development launcher; the eventual packaged `.exe` will not require Python.

Choose an `.eml` file, click **Analyze Email**, review the results, and click **Save Report** to export JSON. The **Open Reports Folder** button opens `Documents/Phishing Triage Reports` (the default save location).

The app uses the same `phishing_triage.analyzer.analyze_file` function as the CLI. It does not render email HTML, fetch URLs, or execute attachments. Reports may contain sensitive data and should be stored and shared securely.

## Optional Windows executable build (developer only)

From the project root in PowerShell:

```powershell
python -m pip install pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --windowed --name PhishingTriageAssistant --paths . desktop/app.py
```

The executable is produced under `dist/PhishingTriageAssistant.exe`. Test it on a clean Windows machine and review antivirus warnings before distribution. Do not distribute sample or real client messages in packaged releases.
