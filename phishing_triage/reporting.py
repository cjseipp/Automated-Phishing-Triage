
"""Phase 1.5 enhanced reporting for phishing triage.

Converts analyzer results into an executive-friendly report.
Preserves the original analyzer output without modifying detection scores.
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
}


def consolidate_findings(findings: list[dict]) -> list[dict]:
    """Combine duplicate display findings without altering raw evidence."""
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
        consolidated.append({
            "type": canonical_type,
            "title": FINDING_TITLES.get(
                canonical_type,
                canonical_type.replace("_", " ").title()
            ),
            "detail": detail,
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
    """Generate evidence-based guidance for two audiences."""
    severity = str(
        result.get("risk", {}).get("severity", "unknown")
    ).lower()

    finding_types = {item["type"] for item in findings}

    recipient = [
        "Verify unexpected requests using an independently known "
        "contact method."
    ]

    provider = [
        "Review the original email, headers, and recorded indicators."
    ]

    if severity in ("high", "critical", "medium"):
        recipient.insert(
            0,
            "Do not click links, open attachments, or provide "
            "credentials until the message has been reviewed."
        )
        recipient.append(
            "Report the message to the designated IT or security contact."
        )
    else:
        recipient.append(
            "Use normal organizational verification procedures "
            "before opening unexpected attachments or links."
        )

    if "active_attachment" in finding_types:
        provider.append(
            "Inspect the attachment in an isolated analysis "
            "environment; do not execute it on a normal workstation."
        )

    if "html_password_field" in finding_types:
        provider.append(
            "Investigate the HTML password-entry field for "
            "possible credential harvesting."
        )

    if "shortened_url" in finding_types:
        provider.append(
            "Determine the shortened URL's destination using "
            "approved security analysis tools."
        )

    if "link_domain_mismatch" in finding_types:
        provider.append(
            "Verify whether the destination domain is authorized "
            "for the claimed sender."
        )

    provider.append(
        "Correlate findings with trusted email gateway logs "
        "and other available security telemetry."
    )

    return {
        "recipient": recipient,
        "it_provider": provider,
    }


def build_enhanced_report(result: dict[str, Any]) -> dict:
    """Build an enhanced report from the analyzer's JSON-compatible data."""
    findings = consolidate_findings(result.get("findings", []))

    return {
        "report_version": "1.5",
        "executive_summary": build_executive_summary(
            result, findings
        ),
        "consolidated_findings": findings,
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
