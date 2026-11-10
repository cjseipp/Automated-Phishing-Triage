# Phase 1.3 — Render Web Application

## Purpose
Browser UI for the existing offline `phishing_triage` engine. **Public demo accepts only bundled fictional emails**. No real organizational emails should be uploaded.

## Local test (Windows PowerShell)
From the repository root:

```powershell
python -m pip install -r requirements.txt
python -m streamlit run browser/app.py
```

Open the localhost URL shown in the terminal. Select `suspicious_login.eml` and click Analyze Email. Expected preliminary score: **65/100**, two unique URL entries, and two findings. Download the JSON report.

Run the engine tests:

```powershell
python -m unittest discover -s tests -v
```

## Deploy on Render
1. Commit these project files to a **new branch** of your GitHub repository (suggested: `feature/render-web-app`). Do not replace your working branch until tested.
2. In Render, choose **New → Blueprint** and connect the repository containing `render.yaml` (or create a Web Service manually).
3. If creating a Web Service manually: Python runtime, build command `pip install -r requirements.txt`, start command `streamlit run browser/app.py --server.address 0.0.0.0 --server.port $PORT --server.headless true`.
4. Set environment variables `PYTHON_VERSION=3.11.9` and `DEMO_ONLY=true`.
5. Deploy and test the three fictional samples. Verify download works and that uploads of other files are rejected in demo mode.

**Security:** This is a public demonstration, not a production phishing-analysis service. Only sample messages are allowed by default. Streamlit file uploads reach the server before the demo hash check, so do not solicit real sensitive email uploads. Add authentication, retention policies, upload isolation, and a privacy review before considering real-world processing. No threat-intelligence APIs are called.

**Note:** Free Render instance availability and limits may change. If Blueprint free plan is unavailable, choose the currently supported web-service plan.
