
"""Tests for offline email authentication-header interpretation."""

import unittest
from phishing_triage.analyzer import analyze_bytes
from phishing_triage.reporting import build_enhanced_report
from email.parser import Parser

from phishing_triage.email_authentication import (
    analyze_authentication_headers,
)


def analyze_email(raw_email):
    """Create a test email and analyze its authentication headers."""
    message = Parser().parsestr(raw_email)
    return analyze_authentication_headers(message)


class TestEmailAuthentication(unittest.TestCase):

    def test_spf_pass_but_domain_misaligned(self):
        """SPF can pass for a domain unrelated to the visible sender."""
        result = analyze_email(
            "From: Norton Security <alerts@norton.example>\n"
            "Authentication-Results: mx.example.org; "
            "spf=pass smtp.mailfrom=unrelated.example.net\n"
            "\n"
            "Test message"
        )

        self.assertEqual(result["from_domain"], "norton.example")
        self.assertEqual(result["spf"][0]["result"], "pass")
        self.assertEqual(
            result["spf"][0]["domain"], "unrelated.example.net"
        )
        self.assertFalse(result["spf"][0]["alignment"])
        self.assertFalse(result["spf"][0]["trusted"])

        types = [x["type"] for x in result["observations"]]
        self.assertIn("spf_reported_misalignment", types)

    def test_dkim_permanent_error(self):
        """A reported DKIM permerror should be recorded."""
        result = analyze_email(
            "From: Security <alerts@example.org>\n"
            "Authentication-Results: mx.example.org; "
            "dkim=permerror header.d=example.org\n"
            "\n"
            "Test message"
        )

        self.assertEqual(result["dkim"][0]["result"], "permerror")
        self.assertEqual(result["dkim"][0]["domain"], "example.org")

        types = [x["type"] for x in result["observations"]]
        self.assertIn("dkim_reported_problem", types)

    def test_dmarc_fail(self):
        """A reported DMARC failure should be recorded."""
        result = analyze_email(
            "From: Billing <billing@example.org>\n"
            "Authentication-Results: mx.example.org; "
            "dmarc=fail header.from=example.org\n"
            "\n"
            "Test message"
        )

        self.assertEqual(result["dmarc"][0]["result"], "fail")

        types = [x["type"] for x in result["observations"]]
        self.assertIn("dmarc_reported_problem", types)

    def test_dmarc_pass_is_still_unverified(self):
        """Reported DMARC success is not independently verified."""
        result = analyze_email(
            "From: Billing <billing@example.org>\n"
            "Authentication-Results: mx.example.org; "
            "dmarc=pass header.from=example.org\n"
            "\n"
            "Test message"
        )

        self.assertEqual(result["dmarc"][0]["result"], "pass")
        self.assertFalse(result["dmarc"][0]["trusted"])
        self.assertFalse(result["independent_verification"])

    def test_missing_authentication_results(self):
        """Missing authentication headers must not be called failures."""
        result = analyze_email(
            "From: Someone <person@example.org>\n"
            "Subject: Test\n"
            "\n"
            "Test message"
        )

        self.assertEqual(result["spf"], [])
        self.assertEqual(result["dkim"], [])
        self.assertEqual(result["dmarc"], [])
        self.assertEqual(result["observations"], [])
        self.assertEqual(
            result["evidence_status"], "unverified_header_claims"
        )

    def test_multiple_authentication_headers(self):
        """Preserve conflicting results rather than choosing one."""
        result = analyze_email(
            "From: Someone <person@example.org>\n"
            "Authentication-Results: mx.first.example; "
            "spf=pass smtp.mailfrom=example.org\n"
            "Authentication-Results: mx.second.example; "
            "spf=fail smtp.mailfrom=other.example.net\n"
            "\n"
            "Test message"
        )

        self.assertEqual(len(result["spf"]), 2)
        self.assertEqual(result["spf"][0]["result"], "pass")
        self.assertEqual(result["spf"][1]["result"], "fail")
        self.assertFalse(result["spf"][0]["trusted"])
        self.assertFalse(result["spf"][1]["trusted"])

    def test_aligned_spf_pass(self):
        """An aligned SPF pass should not produce a misalignment finding."""
        result = analyze_email(
            "From: Support <support@example.org>\n"
            "Authentication-Results: mx.example.org; "
            "spf=pass smtp.mailfrom=mail.example.org\n"
            "\n"
            "Test message"
        )

        self.assertTrue(result["spf"][0]["alignment"])

        types = [x["type"] for x in result["observations"]]
        self.assertNotIn("spf_reported_misalignment", types)

    def test_norton_style_impersonation(self):
        """A forged brand display name does not prove authentication."""
        result = analyze_email(
            "From: Norton Security ALERT "
            "<random@mailer.example.net>\n"
            "Authentication-Results: mx.example.org; "
            "spf=pass smtp.mailfrom=bulk.example.com; "
            "dkim=permerror header.d=mailer.example.net\n"
            "\n"
            "Your subscription has expired."
        )

        self.assertEqual(result["spf"][0]["result"], "pass")
        self.assertFalse(result["spf"][0]["alignment"])
        self.assertEqual(result["dkim"][0]["result"], "permerror")
        self.assertEqual(result["dmarc"], [])

        self.assertFalse(result["independent_verification"])


    def test_enhanced_report_preserves_authentication(self):
        """Enhanced reporting includes SPF, DKIM, and DMARC evidence."""
        raw = (
            b"From: Security <alerts@example.org>\n"
            b"Authentication-Results: mx.example.org; "
            b"spf=pass smtp.mailfrom=other.example.net; "
            b"dkim=permerror header.d=example.org; "
            b"dmarc=fail header.from=example.org\n"
            b"Subject: Authentication test\n"
            b"\n"
            b"Synthetic test message."
        )

        result = analyze_bytes(raw)
        report = build_enhanced_report(result)

        auth = report["email_authentication_assessment"]

        self.assertEqual(auth["spf"][0]["result"], "pass")
        self.assertFalse(auth["spf"][0]["alignment"])
        self.assertEqual(auth["dkim"][0]["result"], "permerror")
        self.assertEqual(auth["dmarc"][0]["result"], "fail")
        self.assertEqual(
            auth["evidence_status"],
            "unverified_header_claims",
        )
        self.assertFalse(auth["independent_verification"])

    def test_enhanced_report_handles_missing_authentication(self):
        """Missing results remain unknown, not failed."""
        raw = (
            b"From: Person <person@example.org>\n"
            b"Subject: No authentication results\n"
            b"\n"
            b"Synthetic test message."
        )

        result = analyze_bytes(raw)
        report = build_enhanced_report(result)

        auth = report["email_authentication_assessment"]

        self.assertEqual(auth["spf"], [])
        self.assertEqual(auth["dkim"], [])
        self.assertEqual(auth["dmarc"], [])
        self.assertEqual(auth["observations"], [])
        self.assertFalse(auth["independent_verification"])

    def test_authentication_does_not_change_risk_score(self):
        """Reported authentication failures do not add risk points."""
        base = (
            b"From: Person <person@example.org>\n"
            b"Subject: Routine test\n"
        )

        without_auth = analyze_bytes(
            base + b"\nSynthetic message."
        )

        with_auth = analyze_bytes(
            base
            + b"Authentication-Results: mx.example.org; "
            + b"spf=fail smtp.mailfrom=other.example.net; "
            + b"dkim=fail header.d=example.org; "
            + b"dmarc=fail header.from=example.org\n"
            + b"\nSynthetic message."
        )

        self.assertEqual(
            without_auth["risk"]["score"],
            with_auth["risk"]["score"],
        )

        report = build_enhanced_report(with_auth)

        self.assertEqual(
            report["scoring"]["score"],
            with_auth["risk"]["score"],
        )


if __name__ == "__main__":
    unittest.main()
