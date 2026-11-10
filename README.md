# Automated Phishing Triage

Offline static analysis of `.eml` files for a Cyber Ready Clinic capstone.

## Requirements
Python 3.10 or newer. Phase 1 has no third-party dependencies.

## Run
From the project root:

```powershell
python -m phishing_triage.cli samples/suspicious_login.eml --output reports/suspicious_login.json
python -m unittest discover -s tests -v
```

Use `py -3` instead of `python` on Windows if needed.

## Privacy and safety
Do not commit real organizational emails or reports. Samples use fictional `.example` domains. The analyzer does not follow links, execute attachments, or verify the authenticity of email authentication headers. Reports may contain sensitive information and should be stored securely.

## Roadmap
- Phase 2: configurable threat intelligence, explainable scoring and incident tickets
- Phase 3: local Tkinter desktop and Streamlit browser interfaces
- Phase 4: safe phishing simulations

## Phase 1.2 — Desktop GUI

A Tkinter desktop interface is included. On Windows with Python installed, double-click `Launch_Desktop.bat` to select and analyze an `.eml` file without typing commands. See `PHASE_1_2_SETUP.md` for instructions. The optional PyInstaller build procedure is documented in `desktop/README.md`. The downloadable package contains source code and a development launcher, **not** a prebuilt `.exe`.

## Phase 1.3 — Streamlit browser application on Render

The `browser/app.py` Streamlit interface uses the same Python engine as the CLI and desktop app. It offers fictional demo email selection, analysis, plain-English findings, and JSON report download. Public demo mode (`DEMO_ONLY=true`) accepts only the bundled fictional sample emails. Risk scores are preliminary heuristics, not a maliciousness probability.

See [PHASE_1_3_RENDER_SETUP.md](PHASE_1_3_RENDER_SETUP.md) for local testing and Render deployment. The repository includes a `render.yaml` Blueprint.


## Phase 1.4

Adds bounded static HTML attachment inspection, URL-shortener and IP-literal detection, active attachment flags, and plain-language recommendations. See `PHASE_1_4_SETUP.md`.
