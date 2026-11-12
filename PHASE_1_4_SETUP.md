# Phase 1.4 — Advanced Phishing Detection

This is an offline heuristic triage tool, not a definitive phishing classifier. Do not upload real organizational emails to a public demo.

## Run locally (Windows PowerShell)

```powershell
cd "C:\CyberReady\automated-phishing-triage-phase1-4\automated-phishing-triage"
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
$env:DEMO_ONLY="true"
python -m streamlit run browser/app.py --server.address 127.0.0.1
```

Test the bundled `html_attachment_lure.eml` and `suspicious_login.eml` files. Scores are heuristic prioritization only, not probabilities. URL shorteners are identified without resolving them; HTML attachments are scanned as bounded text without execution. The scanning is intentionally limited and may miss obfuscation or unusual encodings. The app is not an antivirus sandbox.

## GitHub and Render

Create branch `feature/advanced-phishing-detection` from `feature/render-web-app` (not from main). Commit changed files from this package to that branch, review diffs, then update your Render service's branch to test it. Keep `DEMO_ONLY=true`. Do not merge until verified.

## New rules

Shortened URLs (+15), numeric-IP URLs (+20), active attachment types (+25), HTML forms (+15), password fields (+25), script tags (+15), and possible redirects (+20). One contribution per rule type; total capped at 100. Existing misleading hyperlink (+50) and Reply-To mismatch (+15) rules remain. These weights are provisional and not empirically calibrated.
