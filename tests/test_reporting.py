
"""Automated tests for Phase 1.5 Enhanced Reporting."""

import unittest
from pathlib import Path

from phishing_triage.analyzer import analyze_bytes
from phishing_triage.reporting import build_enhanced_report


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def analyze_sample(filename):
    """Analyze a bundled fictional email."""
    raw = (SAMPLES / filename).read_bytes()
    return analyze_bytes(raw)


class EnhancedReportingTests(unittest.TestCase):

    def test_high_risk_score_preserved(self):
        """Reporting must not change the analyzer score."""
        result = analyze_sample("html_attachment_lure.eml")
        report = build_enhanced_report(result)

        self.assertEqual(result["risk"]["score"], 90)
        self.assertEqual(report["scoring"]["score"], 90)

    def test_high_risk_findings_consolidated(self):
        """Seven original findings should become five."""
        result = analyze_sample("html_attachment_lure.eml")
        report = build_enhanced_report(result)

        self.assertEqual(len(result["findings"]), 7)
        self.assertEqual(
            len(report["consolidated_findings"]), 5
        )

    def test_low_risk_score_preserved(self):
        """A legitimate sample must retain its original score."""
        result = analyze_sample(
            "legitimate_html_attachment.eml"
        )
        report = build_enhanced_report(result)

        self.assertEqual(result["risk"]["score"], 25)
        self.assertEqual(report["scoring"]["score"], 25)

    def test_low_risk_findings_consolidated(self):
        """Duplicate attachment warnings should be merged."""
        result = analyze_sample(
            "legitimate_html_attachment.eml"
        )
        report = build_enhanced_report(result)

        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual(
            len(report["consolidated_findings"]), 1
        )

    def test_executive_summary_generated(self):
        """Executive summary should explain the assessment."""
        result = analyze_sample("html_attachment_lure.eml")
        report = build_enhanced_report(result)

        summary = report["executive_summary"]

        self.assertIsInstance(summary, str)
        self.assertIn("90/100", summary)
        self.assertIn("not the probability", summary)

    def test_low_score_not_declared_safe(self):
        """Low scores must not be interpreted as proof of safety."""
        result = analyze_sample(
            "legitimate_html_attachment.eml"
        )
        report = build_enhanced_report(result)

        summary = report["executive_summary"].lower()

        self.assertIn(
            "does not establish that the message is safe",
            summary,
        )

    def test_scoring_breakdown(self):
        """Scoring contributions should be transparent."""
        result = analyze_sample("html_attachment_lure.eml")
        report = build_enhanced_report(result)

        contributions = report["scoring"]["contributions"]

        self.assertEqual(len(contributions), 5)

        total = sum(
            item["points"] for item in contributions
        )

        self.assertEqual(total, 90)

    def test_recommendations_present(self):
        """Recipients and IT providers need separate guidance."""
        result = analyze_sample("html_attachment_lure.eml")
        report = build_enhanced_report(result)

        actions = report["recommended_actions"]

        self.assertIn("recipient", actions)
        self.assertIn("it_provider", actions)

        self.assertGreater(len(actions["recipient"]), 0)
        self.assertGreater(len(actions["it_provider"]), 0)

    def test_original_findings_unchanged(self):
        """Reporting must preserve original analyzer evidence."""
        result = analyze_sample("html_attachment_lure.eml")

        original_findings = [
            dict(item) for item in result["findings"]
        ]

        build_enhanced_report(result)

        self.assertEqual(
            result["findings"], original_findings
        )

    def test_report_version(self):
        """Enhanced reports should identify their version."""
        result = analyze_sample("html_attachment_lure.eml")
        report = build_enhanced_report(result)

        self.assertEqual(report["report_version"], "1.5")


if __name__ == "__main__":
    unittest.main()
