
"""Offline interpretation of reported email authentication results.

Authentication-Results headers can be forged. This module does not
independently verify SPF, DKIM, or DMARC and does not establish trust
in the server that supplied a header.
"""

from __future__ import annotations

import re
from email.message import Message
from email.utils import getaddresses

from phishing_triage.domains import registrable_domain


RESULT_RE = re.compile(
    r"(?<![\w.-])(spf|dkim|dmarc)\s*=\s*"
    r"(pass|fail|softfail|neutral|none|temperror|permerror|"
    r"policy|bestguesspass)",
    re.IGNORECASE,
)

PROPERTY_RE = re.compile(
    r"(?<![\w.-])"
    r"(smtp\.mailfrom|smtp\.helo|header\.d|header\.i|header\.from)"
    r"\s*=\s*"
    r'(?:"([^"]*)"|([^\s;()]+))',
    re.IGNORECASE,
)


def _clean_domain(value: str) -> str:
    """Normalize a reported domain or mailbox identity."""
    value = value.strip().strip('<>"').rstrip(".").lower()

    if value.startswith("@"):
        value = value[1:]

    if "@" in value:
        value = value.rsplit("@", 1)[-1]

    return value


def _aligned(domain: str, from_domain: str) -> bool | None:
    """Check relaxed organizational-domain alignment."""
    if not domain or not from_domain:
        return None

    try:
        left = registrable_domain(domain)
        right = registrable_domain(from_domain)
    except (ValueError, TypeError):
        return None

    if not left or not right:
        return None

    return left.lower() == right.lower()


def _parse_header(value: str) -> dict:
    """Parse reported results from one Authentication-Results field."""
    records = []
    matches = list(RESULT_RE.finditer(value))

    for index, match in enumerate(matches):
        start = match.end()
        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(value)
        )

        section = value[start:end]
        properties = {}

        for prop in PROPERTY_RE.finditer(section):
            key = prop.group(1).lower()
            raw = prop.group(2) or prop.group(3) or ""
            properties[key] = raw

        records.append({
            "method": match.group(1).lower(),
            "result": match.group(2).lower(),
            "properties": properties,
        })

    return {
        "authserv_id": value.split(";", 1)[0].strip(),
        "records": records,
    }


def analyze_authentication_headers(msg: Message) -> dict:
    """Interpret reported authentication without trusting it."""
    from_addresses = getaddresses([str(msg.get("From", ""))])
    sender = from_addresses[0][1] if from_addresses else ""
    from_domain = _clean_domain(sender)

    raw_headers = [
        str(value)
        for value in msg.get_all("Authentication-Results", [])
    ]

    parsed_headers = [_parse_header(value) for value in raw_headers]

    methods = {"spf": [], "dkim": [], "dmarc": []}

    for header in parsed_headers:
        for record in header["records"]:
            method = record["method"]
            props = record["properties"]

            if method == "spf":
                identity = (
                    props.get("smtp.mailfrom")
                    or props.get("smtp.helo")
                    or ""
                )
            elif method == "dkim":
                identity = (
                    props.get("header.d")
                    or props.get("header.i")
                    or ""
                )
            else:
                identity = props.get("header.from", "")

            domain = _clean_domain(identity)

            methods[method].append({
                "result": record["result"],
                "domain": domain,
                "alignment": _aligned(domain, from_domain),
                "authserv_id": header["authserv_id"],
                "trusted": False,
            })

    observations = []

    for method in ("spf", "dkim", "dmarc"):
        for entry in methods[method]:
            if entry["result"] in ("fail", "permerror", "temperror"):
                observations.append({
                    "type": f"{method}_reported_problem",
                    "detail": (
                        f"Unverified header reports {method.upper()} "
                        f"{entry['result']} for {entry['domain'] or 'unknown domain'}."
                    ),
                })

            if (
                method in ("spf", "dkim")
                and entry["result"] == "pass"
                and entry["alignment"] is False
            ):
                observations.append({
                    "type": f"{method}_reported_misalignment",
                    "detail": (
                        f"Reported {method.upper()} pass uses "
                        f"{entry['domain']}, which does not align "
                        f"with the visible From domain {from_domain}."
                    ),
                })

    return {
        "from_domain": from_domain,
        "evidence_status": "unverified_header_claims",
        "independent_verification": False,
        "spf": methods["spf"],
        "dkim": methods["dkim"],
        "dmarc": methods["dmarc"],
        "observations": observations,
        "notes": [
            "Results were extracted from message headers, not independently verified.",
            "Authentication-Results headers may be forged or inserted by untrusted systems.",
            "Alignment uses relaxed organizational-domain comparison.",
            "Missing results are unknown, not failures.",
            "Reported SPF or DKIM success alone does not establish message safety.",
        ],
    }
