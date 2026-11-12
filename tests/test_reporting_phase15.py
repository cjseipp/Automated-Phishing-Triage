
"""Additional regression tests for Phase 1.5 reporting."""

import unittest
from pathlib import Path

from phishing_triage.analyzer import analyze_bytes
from phishing_triage.reporting import build_enhanced_report


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def analyze_sample(filename):
    raw = (SAMPLES / filename).read_bytes()
    return analyze_bytes(raw)


class Phase15ReportingTests(unittest.TestCase):

    def test_plain_english_explanations(self):
        result = analyze_sample("html_attachment_lure.eml")
        report = build_enhanced_report(result)

        for finding in report["consolidated_findings"]:
            with self.subTest(finding=finding["type"]):
                self.assertTrue(
                    finding["why_it_matters"].strip()
                )

    def test_finding_recommended_actions(self):
        result = analyze_sample("html_attachment_lure.eml")
        report = build_enhanced_report(result)

        for finding in report["consolidated_findings"]:
            with self.subTest(finding=finding["type"]):
                self.assertTrue(
                    finding["recommended_action"].strip()
                )

    def test_password_field_explanation(self):
        result = analyze_sample("html_attachment_lure.eml")
        report = build_enhanced_report(result)

        password_findings = [
            finding
            for finding in report["consolidated_findings"]
            if finding["type"] == "html_password_field"
        ]

        self.assertEqual(len(password_findings), 1)
        self.assertIn(
            "credentials",
            password_findings[0]["why_it_matters"].lower(),
        )

    def test_low_risk_conditional_guidance(self):
        result = analyze_sample(
            "legitimate_html_attachment.eml"
        )
        report = build_enhanced_report(result)

        actions = " ".join(
            report["recommended_actions"]["it_provider"]
        ).lower()

        self.assertIn(
            "no urgent technical investigation",
            actions,
        )
        self.assertIn(
            "if the attachment is unexpected",
            actions,
        )

    def test_high_risk_protective_guidance(self):
        result = analyze_sample("html_attachment_lure.eml")
        report = build_enhanced_report(result)

        recipient = " ".join(
            report["recommended_actions"]["recipient"]
        ).lower()

        provider = " ".join(
            report["recommended_actions"]["it_provider"]
        ).lower()

        self.assertIn("do not click links", recipient)
        self.assertIn(
            "isolated analysis environment",
            provider,
        )

    def test_analyzer_evidence_unchanged(self):
        result = analyze_sample("html_attachment_lure.eml")

        import copy
        original = copy.deepcopy(result)

        build_enhanced_report(result)

        self.assertEqual(result, original)


if __name__ == "__main__":
    unittest.main()
