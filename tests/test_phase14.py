import unittest
from pathlib import Path
from phishing_triage.analyzer import analyze_bytes

ROOT = Path(__file__).resolve().parents[1]

class Phase14Tests(unittest.TestCase):
    def test_html_attachment(self):
        report = analyze_bytes((ROOT / 'samples/html_attachment_lure.eml').read_bytes())
        kinds = {f['type'] for f in report['findings']}
        self.assertTrue({'active_attachment', 'html_form', 'html_password_field', 'shortened_url'} <= kinds)
        self.assertGreater(report['risk']['score'], 0)
        self.assertTrue(report['recommendations'])

    def test_existing_login_score(self):
        report = analyze_bytes((ROOT / 'samples/suspicious_login.eml').read_bytes())
        self.assertEqual(report['risk']['score'], 75)

    def test_plain_invoice_no_false_positive(self):
        report = analyze_bytes((ROOT / 'samples/invoice_attachment.eml').read_bytes())
        self.assertEqual(report['risk']['score'], 0)

    def test_no_url_visits(self):
        report = analyze_bytes(b'From: test@example.org\nSubject: Test\n\nhttps://bit.ly/abc')
        self.assertIn('shortened_url', {f['type'] for f in report['findings']})

if __name__ == '__main__':
    unittest.main()
