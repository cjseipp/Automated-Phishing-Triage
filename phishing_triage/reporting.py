"""Phase 1.5 enhanced reporting for phishing triage.

Produces executive-friendly summaries and evidence-based guidance.
Preserves analyzer findings and scores without modifying detection.
"""

from __future__ import annotations

from typing import Any


FINDING_TITLES = {
    "active_attachment": "Potentially active attachment",
    "risky_attachment": "Potentially active attachment",
    "html_form": "HTML form detected",
    "html_password_field": "Password field detected",
    "shortened_url": "Shortened URL detected",
    "url_shortener": "Shortened URL detected",
    "link_domain_mismatch": "Link and sender domains differ",
    "lookalike_domain": "Potential lookalike domain",
    "payment_instruction_change": (
        "Suspicious payment instruction change"
    ),
}


FINDING_EXPLANATIONS = {

    "payment_instruction_change": {
        "why_it_matters": (
            "The email appears to request a change to banking "
            "or payment instructions."
        ),
        "recommended_action": (
            "Verify the request using a previously established "
            "contact method."
        ),
    },

    "active_attachment": {
        "why_it_matters": (
            "Some attachment types can contain active content "
            "that may redirect users, request information, or "
            "perform unwanted actions."
        ),
        "recommended_action": (
            "Do not open unexpected attachments until the sender "
            "and business purpose have been verified."
        ),
    },
    "html_form": {
        "why_it_matters": (
            "An HTML form inside an attachment can collect "
            "information entered by the recipient. Such forms "
            "can be legitimate but are also used in phishing."
        ),
        "recommended_action": (
            "Verify the request independently before entering "
            "information into the form."
        ),
    },
    "html_password_field": {
        "why_it_matters": (
            "The attachment contains a password-entry field. "
            "Attackers sometimes use these forms to collect "
            "account credentials."
        ),
        "recommended_action": (
            "Do not enter passwords into the attachment. "
            "Contact IT or the claimed sender using a known "
            "trusted method."
        ),
    },
    "shortened_url": {
        "why_it_matters": (
            "A shortened link hides the destination website. "
            "This can make it harder to recognize an "
            "unexpected or malicious destination."
        ),
        "recommended_action": (
            "Do not follow an unexpected shortened link. "
            "Use an independently located official website "
            "or request IT verification."
        ),
    },
    "link_domain_mismatch": {
        "why_it_matters": (
            "A destination domain differs from the sender's "
            "domain. This may be legitimate, such as when "
            "using an external service, but it warrants "
            "verification in context."
        ),
        "recommended_action": (
            "Verify that the destination is authorized by "
            "the claimed organization."
        ),
    },
    "lookalike_domain": {
        "why_it_matters": (
            "The domain resembles another domain and could "
            "be intended to mislead recipients. Similar "
            "domain names can also have legitimate uses."
        ),
        "recommended_action": (
            "Confirm the sender's domain through a trusted "
            "contact method before responding."
        ),
    },
}


def consolidate_findings(findings: list[dict]) -> list[dict]:
    """Merge duplicate display findings while preserving raw evidence."""
    consolidated = []
    seen = set()

    aliases = {
        "risky_attachment": "active_attachment",
        "url_shortener": "shortened_url",
    }

    for finding in findings:
        original_type = str(finding.get("type", "unknown"))
        canonical_type = aliases.get(original_type, original_type)
        detail = str(finding.get("detail", ""))

        key = (canonical_type, detail.strip().lower())

        if key in seen:
            continue

        seen.add(key)

        explanation = FINDING_EXPLANATIONS.get(
            canonical_type,
            {
                "why_it_matters": (
                    "This indicator requires review in the "
                    "context of the original email."
                ),
                "recommended_action": (
                    "Ask the designated IT or security contact "
                    "to review the finding if the email is unexpected."
                ),
            },
        )

        consolidated.append({
            "type": canonical_type,
            "title": FINDING_TITLES.get(
                canonical_type,
                canonical_type.replace("_", " ").title(),
            ),
            "detail": detail,
            "why_it_matters": explanation["why_it_matters"],
            "recommended_action": explanation["recommended_action"],
        })

    return consolidated


def build_executive_summary(
    result: dict[str, Any],
    findings: list[dict],
) -> str:
    """Produce a cautious, plain-English assessment."""
    risk = result.get("risk", {})
    score = risk.get("score", 0)
    severity = str(risk.get("severity", "unknown")).lower()

    if severity in ("high", "critical"):
        opening = (
            "This email contains indicators that warrant prompt "
            "security review. Do not interact with its links or "
            "attachments until independently verified."
        )
    elif severity == "medium":
        opening = (
            "This email contains suspicious characteristics that "
            "require additional verification before use."
        )
    else:
        opening = (
            "This email received a relatively low triage score. "
            "This does not establish that the message is safe."
        )

    if findings:
        titles = [item["title"].lower() for item in findings[:3]]
        explanation = " Key observations: " + "; ".join(titles) + "."
    else:
        explanation = (
            " No indicators matched the current limited detection rules."
        )

    return (
        f"{opening}{explanation} "
        f"The preliminary triage score is {score}/100. "
        "This score represents investigation priority, "
        "not the probability that the email is malicious."
    )


def build_scoring_breakdown(result: dict[str, Any]) -> dict:
    """Retain the analyzer's actual scoring contributions."""
    risk = result.get("risk", {})
    contributions = []

    for item in risk.get("contributions", []):
        contributions.append({
            "type": item.get("type", "unknown"),
            "points": item.get("points", 0),
            "reason": item.get("reason", ""),
        })

    return {
        "score": risk.get("score", 0),
        "severity": risk.get("severity", "unknown"),
        "method": risk.get("method", "unknown"),
        "contributions": contributions,
        "explanation": (
            "Points are assigned by the analyzer's heuristic rules. "
            "This is a triage score, not a probability of maliciousness."
        ),
    }



def build_recommendations(
    result: dict[str, Any],
    findings: list[dict],
) -> dict:
    """Generate proportionate guidance for recipients and IT providers."""
    severity = str(
        result.get("risk", {}).get("severity", "unknown")
    ).lower()

    finding_types = {item["type"] for item in findings}

    elevated = severity in ("high", "critical", "medium")

    recipient = [
        "Verify unexpected requests using an independently known "
        "contact method."
    ]

    provider = []

    if elevated:
        recipient.insert(
            0,
            "Do not click links, open attachments, or provide "
            "credentials until the message has been reviewed.",
        )
        recipient.append(
            "Report the message to the designated IT or security contact."
        )
        provider.append(
            "Review the original email, headers, and recorded indicators."
        )
    else:
        recipient.append(
            "Use normal organizational verification procedures "
            "before opening unexpected attachments or links."
        )
        if "payment_instruction_change" not in finding_types:
            provider.append(
                "No urgent technical investigation is indicated solely "
                "by this low triage score. Review if the message is "
                "unexpected, reported, or inconsistent with policy."
            )

    # Phase 1.8: Business Email Compromise payment fraud guidance.
    if "payment_instruction_change" in finding_types:
        recipient.append(
            "Do not approve a bank account change, update payment "
            "instructions, or transfer funds based solely on this email."
        )
        recipient.append(
            "Contact the vendor using a previously verified telephone "
            "number or established contact method. Obtain approval "
            "from an authorized person before changing payment details."
        )

        provider.append(
            "Preserve the original email and review sender, Reply-To, "
            "message headers, and available authentication evidence."
        )
        provider.append(
            "Investigate possible vendor impersonation or compromised "
            "email accounts. Correlate with trusted mail-system logs "
            "when available."
        )
        provider.append(
            "Advise the organization to independently verify the "
            "payment instructions before approving changes, regardless "
            "of the email's numerical triage score."
        )

    if "active_attachment" in finding_types:
        if elevated:
            provider.append(
                "Inspect the attachment in an isolated analysis "
                "environment; do not execute it on a normal workstation."
            )
        else:
            provider.append(
                "If the attachment is unexpected or requires "
                "investigation, use approved isolated analysis "
                "procedures rather than opening it on a normal workstation."
            )

    if "html_password_field" in finding_types:
        provider.append(
            "Investigate the HTML password-entry field for "
            "possible credential harvesting."
        )

    if "shortened_url" in finding_types:
        provider.append(
            "Determine the shortened URL's destination using "
            "approved security analysis tools when investigation "
            "is warranted."
        )

    if "link_domain_mismatch" in finding_types:
        provider.append(
            "Verify whether the destination domain is authorized "
            "for the claimed sender."
        )

    if elevated:
        provider.append(
            "Correlate findings with trusted email gateway logs "
            "and other available security telemetry."
        )
    else:
        provider.append(
            "Escalate according to organizational procedures "
            "if additional suspicious indicators are identified."
        )

    return {
        "recipient": recipient,
        "it_provider": provider,
    }


def build_enhanced_report(result: dict[str, Any]) -> dict:
    """Build an enhanced report without modifying analyzer results."""
    findings = consolidate_findings(result.get("findings", []))

    return {
        "report_version": "1.5",
        "executive_summary": build_executive_summary(
            result, findings
        ),
        "consolidated_findings": findings,
        
        "email_authentication_assessment": {
            "evidence_status": result.get(
                "email_authentication", {}
            ).get("evidence_status", "not_available"),
            "independent_verification": result.get(
                "email_authentication", {}
            ).get("independent_verification", False),
            "from_domain": result.get(
                "email_authentication", {}
            ).get("from_domain", ""),
            "spf": result.get(
                "email_authentication", {}
            ).get("spf", []),
            "dkim": result.get(
                "email_authentication", {}
            ).get("dkim", []),
            "dmarc": result.get(
                "email_authentication", {}
            ).get("dmarc", []),
            "observations": result.get(
                "email_authentication", {}
            ).get("observations", []),
            "notes": result.get(
                "email_authentication", {}
            ).get("notes", []),
        },

        "scoring": build_scoring_breakdown(result),
        "recommended_actions": build_recommendations(
            result, findings
        ),
        "limitations": [
            "Offline static analysis only.",
            "No links were visited or attachments executed.",
            "A low score does not establish that an email is safe.",
            "Findings are indicators requiring context, not proof of an attack.",
        ],
    }
