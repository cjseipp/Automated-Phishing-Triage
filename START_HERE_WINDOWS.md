# Automated Phishing Triage — Desktop Edition (Phase 1.2)

## Run on your Windows PC (Python 3.10+ already installed)

1. Extract the ZIP. Open the inner `automated-phishing-triage` folder.
2. Double-click **Launch_Desktop.bat**. The desktop GUI should appear.
3. Click **Choose Email** and select `samples/suspicious_login.eml`.
4. Click **Analyze Email** and inspect the findings and heuristic score.
5. Click **Save Report** to save a JSON file. The **Open Report Folder** control opens `Documents/Phishing Triage Reports` (the default save directory).

## Create an executable (developer only)

Double-click **Build_Windows_EXE.bat** on a Windows development PC with Python and internet access. It installs PyInstaller and builds `dist/PhishingTriageAssistant.exe`. This ZIP contains source code, **not a precompiled Windows executable**. Test the EXE on a clean Windows machine before distributing.

## GitHub

The package is based on the previously prepared Phase 1.2 project files, not a verified checkout of your GitHub repository. Compare with the GitHub branch before committing, and avoid uploading actual client email messages or incident reports.

## Security limitations

Offline static analysis only. No URLs are visited and no attachments executed. Scores are preliminary heuristics, not maliciousness probabilities. No VirusTotal/AbuseIPDB checks. A low score **does not prove safety**. Treat saved reports as sensitive.

## Run tests (developer)

From the project folder: `python -m unittest discover -s tests -v`
