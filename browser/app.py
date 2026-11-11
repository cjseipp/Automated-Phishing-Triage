
"""Streamlit interface for Automated Phishing Triage Phase 1.5."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phishing_triage.analyzer import MAX_EMAIL_BYTES, analyze_bytes
from phishing_triage.reporting import build_enhanced_report


SAMPLES = ROOT / "samples"
DEMO_ONLY = os.getenv("DEMO_ONLY", "true").lower() not in (
    "false", "0", "no"
)

SAMPLE_FILES = {
    p.name: p for p in SAMPLES.glob("*.eml")
}
SAMPLE_HASHES = {
    hashlib.sha256(p.read_bytes()).hexdigest()
    for p in SAMPLE_FILES.values()
}


st.set_page_config(
    page_title="Phishing Triage Assistant",
    page_icon="🛡️",
    layout="centered",
)

st.title("🛡️ Phishing Triage Assistant")
st.caption(
    "Cyber Ready Clinic | Automated Phishing Triage | Phase 1.5"
)

st.info(
    "Educational static analysis only. A low score does NOT "
    "mean an email is safe. No links are visited and no "
    "attachments are executed."
)

if DEMO_ONLY:
    st.warning(
        "PUBLIC DEMO MODE: Only bundled fictional sample emails "
        "are accepted. Do not upload real organizational email."
    )
else:
    st.warning(
        "PRIVATE-USE MODE: Email may contain confidential "
        "information. Submit only authorized messages. "
        "Avoid public deployments without authentication "
        "and a privacy review."
    )


# -------------------------------------------------------
# 1. Email selection
# -------------------------------------------------------

st.subheader("1. Select an email")

choice = st.radio(
    "Email source",
    ["Bundled demonstration sample", "Upload .eml file"],
    horizontal=True,
)

raw = None
filename = None

if choice == "Bundled demonstration sample":
    if SAMPLE_FILES:
        filename = st.selectbox(
            "Choose a fictional email",
            sorted(SAMPLE_FILES),
        )
        raw = SAMPLE_FILES[filename].read_bytes()
    else:
        st.error("No sample emails found in samples/.")
else:
    uploaded = st.file_uploader(
        "Choose an .eml file (10 MiB maximum)",
        type=["eml"],
    )

    if uploaded is not None:
        filename = uploaded.name

        if uploaded.size > MAX_EMAIL_BYTES:
            st.error("File exceeds the 10 MiB limit.")
        else:
            raw = uploaded.getvalue()

            if (
                DEMO_ONLY
                and hashlib.sha256(raw).hexdigest()
                not in SAMPLE_HASHES
            ):
                st.error(
                    "Public demo accepts only bundled "
                    "fictional sample emails."
                )
                raw = None


with st.expander("Download fictional sample emails"):
    for name, path in sorted(SAMPLE_FILES.items()):
        st.download_button(
            f"Download {name}",
            path.read_bytes(),
            file_name=name,
            mime="message/rfc822",
            key=f"sample_{name}",
        )


# -------------------------------------------------------
# 2. Analyze email
# -------------------------------------------------------

st.subheader("2. Analyze")

if st.button(
    "Analyze Email",
    type="primary",
    disabled=raw is None,
):
    # Clear the previous report before processing.
    st.session_state.pop("triage_result", None)
    st.session_state.pop("triage_filename", None)

    try:
        result = analyze_bytes(raw)
        st.session_state["triage_result"] = result
        st.session_state["triage_filename"] = filename

    except (ValueError, UnicodeError) as exc:
        st.error(f"Could not analyze the email: {exc}")

    except Exception:
        st.error(
            "The email could not be processed. "
            "Please use a valid .eml file."
        )


# -------------------------------------------------------
# 3. Enhanced reporting
# -------------------------------------------------------

if "triage_result" in st.session_state:

    result = st.session_state["triage_result"]
    enhanced = build_enhanced_report(result)

    headers = result.get("headers", {})
    scoring = enhanced["scoring"]

    score = scoring["score"]
    severity = str(
        scoring["severity"]
    ).replace("_", " ").title()

    st.subheader("3. Executive Summary")

    st.metric(
        "Preliminary triage score (not probability)",
        f"{score}/100",
    )

    st.progress(
        min(max(int(score), 0), 100)
    )

    st.write(f"**Priority:** {severity}")
    st.write(enhanced["executive_summary"])

    st.write(
        f"**Subject:** "
        f"{headers.get('subject') or '(none)'}"
    )

    st.write(
        f"**From:** "
        f"{headers.get('from') or '(none)'}"
    )

    st.write(
        f"**Reply-To:** "
        f"{headers.get('reply_to') or '(none)'}"
    )

    # ---------------------------------------------------
    # 4. Consolidated findings
    # ---------------------------------------------------

    st.subheader("4. Consolidated Findings")

    findings = enhanced["consolidated_findings"]

    if findings:
        for finding in findings:
            st.warning(
                f"**{finding['title']}**: "
                f"{finding['detail']}"
            )
    else:
        st.info(
            "No indicators matched the current limited "
            "detection rules. This is NOT a clean verdict."
        )

    st.write(
        f"**Unique URL entries:** "
        f"{len(result.get('links', []))} | "
        f"**Attachments:** "
        f"{len(result.get('attachments', []))}"
    )

    # ---------------------------------------------------
    # 5. Transparent scoring
    # ---------------------------------------------------

    st.subheader("5. Risk Score Breakdown")

    contributions = scoring["contributions"]

    if contributions:
        rows = []

        for item in contributions:
            rows.append({
                "Detection rule": item["type"]
                    .replace("_", " ").title(),
                "Points": item["points"],
                "Explanation": item["reason"],
            })

        st.table(rows)
    else:
        st.info(
            "No scoring rules contributed points."
        )

    st.caption(scoring["explanation"])

    # ---------------------------------------------------
    # 6. Evidence details
    # ---------------------------------------------------

    with st.expander(
        "Technical Evidence (URLs, Attachments, Raw Findings)"
    ):

        st.write("**URLs (inert text):**")

        links = result.get("links", [])

        if links:
            for link in links:
                st.code(
                    link.get("url", ""),
                    language=None,
                )
        else:
            st.write("No URLs extracted.")

        st.write("**Attachments:**")

        attachments = result.get(
            "attachments", []
        )

        if attachments:
            for attachment in attachments:
                st.write(
                    f"{attachment.get('filename')} | "
                    f"{attachment.get('size_bytes')} bytes"
                )

                st.code(
                    attachment.get("sha256", ""),
                    language=None,
                )
        else:
            st.write("No attachments extracted.")

        st.write("**Original Analyzer Findings:**")

        for finding in result.get("findings", []):
            st.write(
                f"{finding.get('type')}: "
                f"{finding.get('detail')}"
            )

        st.caption(
            "Original findings are preserved for "
            "technical investigation."
        )

    # ---------------------------------------------------
    # 7. Recommended actions
    # ---------------------------------------------------

    st.subheader("6. Recommended Actions")

    recommendations = enhanced["recommended_actions"]

    st.write("**For the Email Recipient**")

    for action in recommendations["recipient"]:
        st.write(f"- {action}")

    st.write("**For the IT / Security Provider**")

    for action in recommendations["it_provider"]:
        st.write(f"- {action}")

    # ---------------------------------------------------
    # 8. Export enhanced report
    # ---------------------------------------------------

    st.subheader("7. Export Report")

    export_data = {
        "enhanced_reporting": enhanced,
        "technical_analysis": result,
    }

    report_json = json.dumps(
        export_data,
        indent=2,
        ensure_ascii=False,
    ).encode("utf-8")

    st.download_button(
        "Download Enhanced JSON Incident Report",
        report_json,
        file_name="phishing_triage_enhanced_report.json",
        mime="application/json",
    )

    st.caption(
        "Reports are generated in memory. "
        "The application does not intentionally write "
        "uploaded messages to disk. Hosting and platform "
        "logs require a separate privacy review."
    )
