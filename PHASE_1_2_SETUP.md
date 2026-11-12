# Phase 1.2 — Windows GUI setup

1. Extract this ZIP to a **new** folder (do not overwrite your original project).
2. Open the inner `automated-phishing-triage` folder.
3. Double-click **Launch_Desktop.bat**. Windows may warn about downloaded scripts; review the file before running. Python 3.10+ is required for this development launcher.
4. Click **Choose Email (.eml)** and select `samples/suspicious_login.eml`.
5. Click **Analyze Email**. Expected score: **65 / 100**, priority **HIGH**, with two findings.
6. Click **Save Report** and choose a destination. Use **Open Reports Folder** to open the default reports location.

For developers, run tests from the project root:

```powershell
python -m unittest discover -s tests -v
```

This is not yet a standalone executable; build instructions are in `desktop/README.md`. No email URLs are opened, attachments executed, or external APIs called. Unknown findings are not proof of safety.
