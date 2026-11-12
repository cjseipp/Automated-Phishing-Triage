
import unittest

from phishing_triage.analyzer import analyze_bytes
from phishing_triage.reporting import (
    consolidate_findings,
    build_enhanced_report,
)


class TestPhase18Reporting(unittest.TestCase):

    def setUp(self):
        self.findings = [
            {
                "type": "payment_instruction_change",
                "detail": "Bank account change requested",
            }
        ]

        self.raw_email = (
            b"From: billing@example.org\n"
            b"To: accounts@example.net\n"
            b"Subject: Invoice payment update\n"
            b"\n"
            b"Please update our bank account for future "
            b"invoice payments."
        )

    def test_payment_fraud_title(self):
        findings = consolidate_findings(self.findings)

        self.assertEqual(
            findings[0]["title"],
            "Suspicious payment instruction change"
        )

    def test_payment_fraud_explanation(self):
        findings = consolidate_findings(self.findings)

        self.assertIn(
            "banking",
            findings[0]["why_it_matters"].lower()
        )

    def test_payment_fraud_recommendation(self):
        findings = consolidate_findings(self.findings)

        self.assertIn(
            "verify",
            findings[0]["recommended_action"].lower()
        )

    def test_payment_fraud_in_enhanced_report(self):
        result = analyze_bytes(self.raw_email)
        report = build_enhanced_report(result)

        finding_types = [
            item["type"]
            for item in report["consolidated_findings"]
        ]

        self.assertIn(
            "payment_instruction_change",
            finding_types
        )

    def test_original_risk_score_preserved(self):
        result = analyze_bytes(self.raw_email)
        report = build_enhanced_report(result)

        self.assertEqual(
            report["scoring"]["score"],
            result["risk"]["score"]
        )

        self.assertEqual(
            report["scoring"]["score"],
            25
        )

    # Phase 1.8: Nonprofit director recommendations.
    def test_recipient_payment_verification_guidance(self):
        result = analyze_bytes(self.raw_email)
        report = build_enhanced_report(result)

        recommendations = " ".join(
            report["recommended_actions"]["recipient"]
        ).lower()

        self.assertIn(
            "do not approve a bank account change",
            recommendations
        )

        self.assertIn(
            "previously verified telephone number",
            recommendations
        )

    # Phase 1.8: Managed service provider recommendations.
    def test_it_provider_payment_fraud_guidance(self):
        result = analyze_bytes(self.raw_email)
        report = build_enhanced_report(result)

        recommendations = " ".join(
            report["recommended_actions"]["it_provider"]
        ).lower()

        self.assertIn(
            "preserve the original email",
            recommendations
        )

        self.assertIn(
            "vendor impersonation",
            recommendations
        )

        self.assertIn(
            "regardless of the email's numerical triage score",
            recommendations
        )

    # Phase 1.8: Prevent contradictory low-risk guidance.
    def test_no_conflicting_low_risk_recommendation(self):
        result = analyze_bytes(self.raw_email)
        report = build_enhanced_report(result)

        self.assertEqual(
            report["scoring"]["score"],
            25
        )

        recommendations = " ".join(
            report["recommended_actions"]["it_provider"]
        ).lower()

        self.assertNotIn(
            "no urgent technical investigation",
            recommendations
        )


if __name__ == "__main__":
    unittest.main()
