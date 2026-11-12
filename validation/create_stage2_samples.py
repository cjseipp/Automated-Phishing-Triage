
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"

SAMPLES.mkdir(exist_ok=True)


def save_email(filename, subject, sender, body,
               html=None, attachment=None):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "recipient@example.org"
    msg["Subject"] = subject

    msg.set_content(body)

    if html:
        msg.add_alternative(html, subtype="html")

    if attachment:
        name, content = attachment
        msg.add_attachment(
            content.encode("utf-8"),
            maintype="text",
            subtype="html",
            filename=name
        )

    (SAMPLES / filename).write_bytes(msg.as_bytes())
    print("Created:", filename)


# 1. Legitimate HTML attachment
save_email(
    "legitimate_html_attachment.eml",
    "Meeting agenda",
    "director@example.org",
    "Attached is the agenda for our meeting.",
    attachment=(
        "agenda.html",
        "<html><body><h1>Meeting Agenda</h1>"
        "<p>Budget and volunteer updates.</p>"
        "</body></html>"
    )
)

# 2. Phishing without suspicious URLs
save_email(
    "phishing_plain_text.eml",
    "URGENT: Confidential payment request",
    "finance@billing-example.net",
    "Please urgently send the organization's "
    "bank account details and password. "
    "Do not contact the director."
)

# 3. Legitimate shortened URL
save_email(
    "legitimate_short_url.eml",
    "Community event registration",
    "events@example.org",
    "Our event registration link is "
    "https://bit.ly/example-event"
)

# 4. Lookalike-domain phishing
save_email(
    "phishing_lookalike_domain.eml",
    "Account verification required",
    "support@micros0ft-example.com",
    "Verify your account at "
    "https://micros0ft-example.com/login"
)

# 5. Legitimate newsletter
save_email(
    "legitimate_newsletter.eml",
    "Monthly nonprofit newsletter",
    "newsletter@example.org",
    "Visit https://example.org/news "
    "and https://example.org/events "
    "for community updates."
)

# 6. Credential collection form
save_email(
    "phishing_credential_form.eml",
    "Payroll verification required",
    "payroll@billing-example.net",
    "Complete the attached payroll verification.",
    attachment=(
        "verify.html",
        '<html><body><form action="/submit">'
        '<input type="password" name="password">'
        '<input type="submit" value="Verify">'
        '</form></body></html>'
    )
)

print("\nStage 2 sample generation complete.")
