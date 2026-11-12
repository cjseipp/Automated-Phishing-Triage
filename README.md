# Automated Phishing Triage Assistant

**Cyber Ready Clinic Capstone Project**

An educational cybersecurity application designed to help nonprofit organizations, small businesses, and IT support personnel perform preliminary phishing email assessments.

The application examines `.eml` email files using offline static analysis and produces an explainable risk assessment with recommended actions.

**Current development version:** Phase 1.5 — Enhanced Validation and Reporting

**[Launch the Phase 1.5 Public Demonstration](https://automated-phishing-triage-phase15-test.onrender.com)**

## 1. The Problem

Nonprofit organizations and small businesses frequently receive suspicious emails involving credential requests, misleading links, unexpected attachments, and impersonation attempts.

These organizations may lack dedicated cybersecurity personnel or sophisticated email investigation tools.

The Automated Phishing Triage Assistant helps users identify potentially suspicious characteristics and understand why those characteristics warrant further investigation.

The application supports preliminary triage. It does not replace professional incident response, secure email gateways, or other email security controls.

## 2. Project Objectives

The application is designed to:

- Analyze suspicious email messages without opening links or executing attachments.
- Identify selected phishing indicators.
- Calculate a preliminary heuristic risk score.
- Explain technical findings in language understandable to nontechnical users.
- Provide separate recommendations for email recipients and IT/security providers.
- Preserve technical evidence for further investigation.
- Generate a downloadable JSON incident report.

## 3. Phase 1.5 — Enhanced Reporting

Phase 1.5 introduces improved reporting and interpretation while preserving the underlying detection engine.

### Executive Summary

Each assessment includes:

- Preliminary risk score from 0 to 100.
- Risk severity classification.
- Summary of the most important findings.
- Explanation that the score represents investigation priority, not the probability of maliciousness.

### Consolidated Findings

Duplicate or equivalent findings are consolidated into a more readable presentation.

Each finding includes three elements:

**Technical Observation:** What the analyzer detected.

**Why It Matters:** Why the observed characteristic may indicate phishing or another security concern.

**Recommended Action:** What the recipient or IT/security provider should consider doing.

The original technical findings remain available in the detailed report.

### Risk Score Breakdown

The application displays the individual heuristic scoring contributions, making the assessment easier to understand and review.

### Risk-Based Recommendations

Recommendations vary according to the assessed risk severity.

Higher-risk messages receive stronger guidance regarding verification, reporting, and investigation.

Lower-risk messages receive proportionate recommendations. A low score does not establish that a message is safe.

### Enhanced JSON Incident Report

The downloadable report contains:

- Executive summary.
- Consolidated findings and explanations.
- Risk score and scoring contributions.
- Recipient recommendations.
- IT/security provider recommendations.
- Original technical analysis.
- Email headers and extracted indicators.
- Attachment metadata and SHA-256 hashes.
- Analysis limitations.

## 4. Detection Capabilities

The application includes rules for identifying selected suspicious characteristics, including:

- Potentially active or risky attachments.
- HTML attachments containing forms.
- HTML password-entry fields.
- Shortened URLs.
- Sender and link domain mismatches.
- Selected lookalike-domain indicators.
- IP-address-based links.
- Suspicious URL structures.
- Disguised or misleading attachment filenames.

Detection is based on predefined rules and heuristics. Findings require contextual interpretation and are not definitive evidence of malicious activity.

## 5. Example Assessments

The repository includes fictional demonstration email samples.

| Sample | Score | Interpretation |
|---|---:|---|
| `html_attachment_lure.eml` | 90/100 | High investigation priority |
| `legitimate_html_attachment.eml` | 25/100 | Low investigation priority |

The high-risk example contains multiple suspicious characteristics, including an HTML attachment, password-entry field, shortened URL, and sender/link domain mismatch.

The lower-risk example contains an HTML attachment but fewer suspicious indicators.

These scores demonstrate the application's current heuristic rules. They are not probabilities or independently measured detection accuracy.

## 6. Public Demonstration

**[Open the Automated Phishing Triage Assistant — Phase 1.5](https://automated-phishing-triage-phase15-test.onrender.com)**

The public demonstration is hosted on Render using Streamlit.

### Public Demo Restrictions

The public deployment uses `DEMO_ONLY=true`.

In this mode:

- Only bundled fictional demonstration email files are accepted for analysis.
- Arbitrary organizational email uploads are not accepted.
- The demonstration uses fictional email addresses and domains.
- The application does not visit extracted links.
- Attachments are not executed.

**Do not upload real organizational emails to the public demonstration.**

The free Render service may take additional time to respond after a period of inactivity.

## 7. Installation Requirements

- Python 3.10 or newer.
- Windows, Linux, or another supported Python environment for command-line operation.
- Streamlit and other dependencies specified in `requirements.txt` for the browser interface.

The core Phase 1 analyzer uses Python's standard library.

### Clone the Repository

```powershell
git clone https://github.com/cjseipp/Automated-Phishing-Triage.git
cd Automated-Phishing-Triage
```

### Install Browser Dependencies

```powershell
python -m pip install -r requirements.txt
```

### Run the Browser Application

```powershell
python -m streamlit run browser/app.py
```

Streamlit will display a local browser address, usually `http://localhost:8501`.

### Run the Command-Line Analyzer

From the project root:

```powershell
python -m phishing_triage.cli samples/suspicious_login.eml --output reports/suspicious_login.json
```

On Windows, `py -3` may be used instead of `python` where appropriate.

### Run the Desktop Interface

A Tkinter desktop interface is also included.

On Windows with Python installed, use:

`Launch_Desktop.bat`

The desktop setup is described in `PHASE_1_2_SETUP.md`.

The optional PyInstaller procedure is documented in `desktop/README.md`.

The source distribution does not automatically include a prebuilt Windows executable.

## 8. Automated Testing and Validation

The Phase 1.5 development branch successfully completed **44 automated tests** on November 11, 2026.

The tests cover:

- Original email analyzer functionality.
- Attachment and URL detection rules.
- Phase 1.4 detection enhancements.
- Risk score preservation.
- Consolidated findings.
- Executive summary generation.
- Scoring transparency.
- Plain-English finding explanations.
- Finding-specific recommended actions.
- Low-risk conditional guidance.
- High-risk protective recommendations.
- Preservation of original analyzer evidence.

### Run the Tests

```powershell
python -m unittest discover -s tests -v
```

The verified Phase 1.5 test run completed with:

```text
Ran 44 tests

OK
```

### Additional Verification

Phase 1.5 was also checked through:

- Local Windows execution.
- High-risk and low-risk fictional email assessments.
- Successful GitHub feature-branch deployment to Render.
- Browser interface inspection.
- Downloaded enhanced JSON report inspection.

These checks demonstrate functionality against the tested scenarios. They do not establish real-world phishing detection accuracy.

## 9. Privacy, Safety, and Limitations

**Offline static analysis:** The analyzer does not visit links or execute attachments.

**Limited detection coverage:** The application uses predefined rules rather than comprehensive malware detection or threat intelligence.

**Heuristic scoring:** Risk scores represent preliminary investigation priority, not probability of maliciousness.

**No safe-email guarantee:** A low score does not prove an email is legitimate or safe.

**Email authentication:** Authentication-Results headers are not independently verified and may be forged. Trusted receiving-server context is required.

**Domain interpretation:** Lookalike-domain and domain-mismatch findings require additional verification.

**Sensitive information:** Reports can contain email addresses, message contents, links, and other sensitive information. Store and share reports securely.

**Public demo:** Only bundled fictional samples are permitted. Real organizational email should not be uploaded.

**Validation scope:** Automated tests and fictional demonstration samples are not substitutes for evaluation using a broader, independently labeled dataset.

This application is an educational and preliminary triage tool, not a production-grade secure email gateway or a definitive maliciousness assessment system.

## 10. Development History

### Phase 1 — Core Analyzer

Initial offline `.eml` analysis, indicator extraction, heuristic scoring, and JSON reporting.

### Phase 1.2 — Desktop GUI

Tkinter desktop interface for users who prefer not to use the command line.

See `PHASE_1_2_SETUP.md`.

### Phase 1.3 — Streamlit Browser Interface

Browser-based interface using the same Python analysis engine, including fictional demonstration samples and downloadable JSON reports.

See `PHASE_1_3_RENDER_SETUP.md`.

### Phase 1.4 — Detection Enhancements

Added bounded static HTML attachment inspection, additional URL and attachment detection rules, and improved recommendations.

See `PHASE_1_4_SETUP.md`.

### Phase 1.5 — Enhanced Validation and Reporting

Added executive-friendly explanations, consolidated findings, risk-based recommendations, transparent scoring, and enhanced JSON reporting.

The Phase 1.5 reporting improvements were committed as `bd538ae` on the branch:

`feature/phase-1-5-validation-reporting`

The changes were successfully deployed to the separate Phase 1.5 Render test service.

## 11. Future Development

Potential enhancements include:

- Broader phishing detection validation using independently labeled samples.
- Optional threat intelligence integrations.
- More detailed incident ticket generation.
- Additional reporting formats such as PDF.
- Improved accessibility and executive-facing presentation.
- Additional security controls and deployment hardening.

These are future development possibilities, not current capabilities.

## 12. Intended Audience

This project was developed as a Cyber Ready Clinic capstone to demonstrate how accessible cybersecurity tools can help nonprofit organizations and small businesses recognize, assess, and respond to potentially suspicious email messages.

Its central objective is to make preliminary phishing analysis more understandable and actionable while preserving technical evidence for further review.