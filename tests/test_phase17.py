import unittest

from phishing_triage.analyzer import (
    _text_findings,
    analyze_bytes,
)


class TestPhase17PaymentFraud(unittest.TestCase):

    def finding_types(self, message):
        findings = _text_findings(message)
        return [finding["type"] for finding in findings]

    def test_suspicious_bank_account_change(self):
        message = (
            "Please update our bank account for future "
            "invoice payments."
        )

        self.assertIn(
            "payment_instruction_change",
            self.finding_types(message)
        )

    def test_legitimate_invoice(self):
        message = (
            "Your November invoice is attached. "
            "Payment is due December 1. "
            "Thank you for your business."
        )

        self.assertNotIn(
            "payment_instruction_change",
            self.finding_types(message)
        )

    def test_payment_change_without_invoice_context(self):
        message = (
            "Please update your bank account information "
            "in your personal records."
        )

        self.assertNotIn(
            "payment_instruction_change",
            self.finding_types(message)
        )

    def test_vendor_payment_instruction_change(self):
        message = (
            "Our vendor requests that you change "
            "the payment instructions immediately."
        )

        self.assertIn(
            "payment_instruction_change",
            self.finding_types(message)
        )

    def test_payment_change_risk_score(self):
        raw_email = (
            b"From: billing@example.org\n"
            b"To: accounts@example.net\n"
            b"Subject: Invoice payment update\n"
            b"\n"
            b"Please update our bank account for future "
            b"invoice payments."
        )

        result = analyze_bytes(raw_email)

        self.assertEqual(
            result["risk"]["score"],
            25
        )

        self.assertEqual(
            result["risk"]["severity"],
            "low"
        )

        contributions = result["risk"]["contributions"]

        self.assertTrue(
            any(
                item["type"] == "payment_instruction_change"
                and item["points"] == 25
                for item in contributions
            )
        )


if __name__ == "__main__":
    unittest.main()