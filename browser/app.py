"""Streamlit web interface for the shared, offline phishing triage engine."""
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

SAMPLES = ROOT / 'samples'
DEMO_ONLY = os.getenv('DEMO_ONLY', 'true').lower() not in ('false', '0', 'no')
SAMPLE_FILES = {p.name: p for p in SAMPLES.glob('*.eml')}
SAMPLE_HASHES = {hashlib.sha256(p.read_bytes()).hexdigest() for p in SAMPLE_FILES.values()}

st.set_page_config(page_title='Phishing Triage Assistant', page_icon='🛡️', layout='centered')
st.title('🛡️ Phishing Triage Assistant')
st.caption('Cyber Ready Clinic | Automated Phishing Triage | Phase 1.3')
st.info('Educational static analysis only. A low score does NOT mean an email is safe. No links are visited and no attachments are executed.')
if DEMO_ONLY:
    st.warning('PUBLIC DEMO MODE: Only the bundled fictional sample emails are accepted. Do not upload real organizational email.')
else:
    st.warning('PRIVATE-USE MODE: Email content may contain confidential information. Only submit messages you are authorized to process. Avoid public deployments without authentication and a privacy review.')

st.subheader('1. Select an email')
choice = st.radio('Email source', ['Bundled demonstration sample', 'Upload .eml file'], horizontal=True)
raw = None
filename = None
if choice == 'Bundled demonstration sample':
    if SAMPLE_FILES:
        filename = st.selectbox('Choose a fictional email', sorted(SAMPLE_FILES))
        raw = SAMPLE_FILES[filename].read_bytes()
    else:
        st.error('No sample emails found in samples/.')
else:
    uploaded = st.file_uploader('Choose an .eml file (10 MiB maximum)', type=['eml'])
    if uploaded is not None:
        filename = uploaded.name
        if uploaded.size > MAX_EMAIL_BYTES:
            st.error('File exceeds the 10 MiB limit.')
        else:
            raw = uploaded.getvalue()
            if DEMO_ONLY and hashlib.sha256(raw).hexdigest() not in SAMPLE_HASHES:
                st.error('Public demo accepts only the bundled fictional samples, including copies downloaded from this app.')
                raw = None

with st.expander('Download fictional sample emails'):
    for name, path in sorted(SAMPLE_FILES.items()):
        st.download_button(f'Download {name}', path.read_bytes(), file_name=name, mime='message/rfc822', key=f'sample_{name}')

st.subheader('2. Analyze')
if st.button('Analyze Email', type='primary', disabled=raw is None):
    try:
        st.session_state['triage_result'] = analyze_bytes(raw)
        st.session_state['triage_filename'] = filename
    except (ValueError, UnicodeError) as exc:
        st.error(f'Could not analyze the email: {exc}')
        st.session_state.pop('triage_result', None)
    except Exception:
        st.error('The email could not be processed. Please use a valid .eml file.')
        st.session_state.pop('triage_result', None)

if 'triage_result' in st.session_state:
    result = st.session_state['triage_result']
    headers = result.get('headers', {})
    risk = result.get('risk', {})
    score = risk.get('score', 0)
    severity = risk.get('severity', 'unknown').replace('_', ' ').title()
    st.subheader('3. Findings')
    st.metric('Preliminary triage score (not probability)', f'{score}/100')
    st.progress(min(max(int(score), 0), 100))
    st.write(f'**Priority:** {severity}')
    st.write(f"**Subject:** {headers.get('subject') or '(none)'}")
    st.write(f"**From:** {headers.get('from') or '(none)'}")
    st.write(f"**Reply-To:** {headers.get('reply_to') or '(none)'}")
    findings = result.get('findings', [])
    if findings:
        for finding in findings:
            st.warning(f"{finding.get('type', 'Finding').replace('_', ' ').title()}: {finding.get('detail', '')}")
    else:
        st.info('No indicators matched the current limited rules. This is NOT a clean or safe verdict.')
    st.write(f"**Unique URL entries:** {len(result.get('links', []))} | **Attachments:** {len(result.get('attachments', []))}")
    with st.expander('Evidence details (links, attachments and scoring)'):
        st.write('**URLs (shown as inert text, never clickable):**')
        for link in result.get('links', []):
            st.code(link.get('url', ''), language=None)
            if link.get('display_texts'):
                st.write('Displayed text:', ', '.join(link['display_texts']))
        st.write('**Attachments:**')
        for att in result.get('attachments', []):
            st.write(f"{att.get('filename')} | {att.get('size_bytes')} bytes")
            st.code(att.get('sha256', ''), language=None)
        st.write('**Score contributions:**')
        for contribution in risk.get('contributions', []):
            st.write(f"+{contribution.get('points', 0)} — {contribution.get('reason', '')}")
        st.caption('Authentication-Results headers are unverified. Threat intelligence is not enabled.')
    st.subheader('4. Export report')
    report = json.dumps(result, indent=2, ensure_ascii=False).encode('utf-8')
    st.download_button('Download JSON Incident Report', report, file_name='phishing_triage_report.json', mime='application/json')
    st.caption('Reports are generated in memory; the application does not intentionally write uploaded messages to disk. Hosting and platform logs require separate privacy review.')
