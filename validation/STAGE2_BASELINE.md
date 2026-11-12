# Phase 1.5 — Stage 2 Detection Validation Baseline

**Project:** Automated Phishing Triage  
**Development Branch:** `feature/phase-1-5-validation-reporting`  
**Validation Date:** November 10, 2026  
**Detection Engine:** `heuristic_v2`  
**Classification Threshold:** 30/100  
**Dataset:** 10 fictional, labeled email samples

## 1. Purpose

Establish a measurable baseline for the Automated Phishing Triage application's detection capabilities before implementing additional detection rules.

Stage 2 expands the original four-email validation dataset to ten samples, introducing more challenging phishing and legitimate email scenarios.

The baseline will be used to evaluate detection improvements, false positives, false negatives, and regression risks in subsequent development stages.

## 2. Validation Results

| Sample | Expected | Predicted | Score | Result |
|---|---|---|---|---|
| suspicious_login.eml | Phishing | Phishing | 65 | True Positive |
| legitimate_notice.eml | Legitimate | Legitimate | 0 | True Negative |
| invoice_attachment.eml | Legitimate | Legitimate | 0 | True Negative |
| html_attachment_lure.eml | Phishing | Phishing | 80 | True Positive |
| legitimate_html_attachment.eml | Legitimate | Legitimate | 25 | True Negative |
| phishing_plain_text.eml | Phishing | Legitimate | 0 | False Negative |
| legitimate_short_url.eml | Legitimate | Legitimate | 15 | True Negative |
| phishing_lookalike_domain.eml | Phishing | Legitimate | 0 | False Negative |
| legitimate_newsletter.eml | Legitimate | Legitimate | 0 | True Negative |
| phishing_credential_form.eml | Phishing | Phishing | 65 | True Positive |

Emails scoring 30 or higher are classified as phishing for validation purposes. Scores below 30 are classified as legitimate by the validation runner. These labels are experimental classifications, not safety guarantees.

## 3. Confusion Matrix

| Actual / Predicted | Phishing | Legitimate |
|---|---:|---:|
| Phishing | 3 (TP) | 2 (FN) |
| Legitimate | 0 (FP) | 5 (TN) |

**True Positives (TP):** 3  
**False Positives (FP):** 0  
**True Negatives (TN):** 5  
**False Negatives (FN):** 2

## 4. Performance Metrics

| Metric | Result |
|---|---:|
| Accuracy | 80.00% |
| Precision | 100.00% |
| Recall (Sensitivity) | 60.00% |
| Specificity | 100.00% |
| F1 Score | 75.00% |

### Metric Interpretation

**Accuracy:** Eight of the ten samples were correctly classified.

**Precision:** All three emails classified as phishing were labeled phishing in the dataset.

**Recall:** Only three of five phishing samples were detected. Two phishing samples were missed.

**Specificity:** All five legitimate samples were correctly classified.

**F1 Score:** The harmonic mean of precision and recall is 75%, reflecting the reduced recall despite perfect measured precision.

## 5. Identified Detection Gaps

### Gap 1 — Plain-Text Social Engineering

**Sample:** `phishing_plain_text.eml`  
**Expected:** Phishing  
**Predicted:** Legitimate  
**Score:** 0/100

The current detection rules did not identify the malicious intent represented in this fictional plain-text phishing scenario.

**Proposed improvement:** Develop contextual detection rules for credential requests, financial information requests, urgency, and attempts to discourage independent verification.

### Gap 2 — Lookalike Domain Impersonation

**Sample:** `phishing_lookalike_domain.eml`  
**Expected:** Phishing  
**Predicted:** Legitimate  
**Score:** 0/100

The current detection rules did not identify the domain impersonation scenario.

**Proposed improvement:** Introduce carefully scoped domain impersonation detection, including character substitution and comparison against explicitly defined reference domains.

## 6. Stage 3 Development Objectives

1. Improve detection of plain-text social-engineering indicators.
2. Improve identification of suspicious lookalike domains.
3. Maintain low false-positive rates.
4. Preserve existing detection capabilities.
5. Rerun the complete validation dataset after each significant detection change.
6. Document scoring changes and their impact on classification results.

## 7. Baseline Limitations

This validation uses ten fictional email samples created for educational testing.

The dataset is small, synthetic, and not representative of real-world phishing prevalence, attacker behavior, or legitimate organizational email traffic.

The reported performance metrics must not be interpreted as production detection rates or guarantees of phishing identification.

The current engine performs offline static analysis. It does not visit URLs, execute attachments, or independently verify message authenticity.

A low risk score does not establish that an email is safe.

## 8. Baseline Preservation

This document records the Stage 2 results before implementing additional detection capabilities.

**Baseline status:** Established  
**Validation command:** `python validation/validate.py`  
**Next milestone:** Phase 1.5 — Stage 3: Detection Improvements

All future validation results should be compared against this baseline to identify measurable improvements and potential regressions.
