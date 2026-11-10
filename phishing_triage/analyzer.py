"""Offline, non-executing analysis of RFC 5322 .eml messages."""
from __future__ import annotations
import hashlib
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit
import ipaddress

URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
MAX_EMAIL_BYTES = 10 * 1024 * 1024
MAX_PARTS = 100
MAX_TEXT_CHARS = 1_000_000
MAX_ATTACHMENT_SCAN_BYTES = 1_000_000
SHORTENER_HOSTS = frozenset({'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rebrand.ly', 'ow.ly', 'buff.ly'})
ACTIVE_ATTACHMENT_EXTENSIONS = {'.html', '.htm', '.js', '.jse', '.vbs', '.vbe', '.wsf', '.hta', '.lnk', '.url', '.svg', '.iso', '.img', '.exe', '.scr', '.ps1', '.bat', '.cmd', '.docm', '.xlsm', '.pptm'}


def _inspect_html_attachment(data: bytes) -> list[dict]:
    """Bounded, non-executing text inspection; never follows URLs."""
    text = data[:MAX_ATTACHMENT_SCAN_BYTES].decode('utf-8', errors='replace')
    patterns = (
        ('html_form', r'<\s*form\b', 'HTML attachment contains a form; review for credential collection.'),
        ('html_password_field', r'<\s*input\b[^>]{0,1500}\btype\s*=\s*[\"\']?password\b', 'HTML attachment contains a password input.'),
        ('html_script', r'<\s*script\b', 'HTML attachment contains script markup; content was not executed.'),
        ('html_redirect', r'http-equiv\s*=\s*[\"\']?refresh\b|\blocation\s*\.(?:href|replace|assign)\b', 'HTML attachment contains a possible redirect instruction.'),
    )
    return [{'type': kind, 'detail': detail} for kind, pattern, detail in patterns if re.search(pattern, text, flags=re.I)]


def _url_findings(url: str) -> list[dict]:
    host = _hostname(url)
    if not host:
        return []
    results = []
    if host in SHORTENER_HOSTS:
        results.append({'type': 'shortened_url', 'detail': 'URL uses a known shortening service; final destination was not resolved.'})
    try:
        ipaddress.ip_address(host.strip('[]'))
        results.append({'type': 'ip_address_url', 'detail': 'URL uses a numeric IP address instead of a domain name.'})
    except ValueError:
        pass
    return results


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.active = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'a':
            attrs = dict(attrs)
            self.active = {'url': attrs.get('href', ''), 'display_text': ''}

    def handle_data(self, data):
        if self.active is not None:
            self.active['display_text'] += data

    def handle_endtag(self, tag):
        if tag.lower() == 'a' and self.active is not None:
            self.links.append(self.active)
            self.active = None


def _domain(address):
    return address.rsplit('@', 1)[-1].lower() if '@' in address else ''


def _hostname(url):
    try:
        return (urlsplit(url).hostname or '').lower()
    except ValueError:
        return ''


def analyze_bytes(raw: bytes) -> dict:
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError('Email exceeds 10 MiB size limit')
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    from_address = getaddresses([str(msg.get('From', ''))])
    reply_address = getaddresses([str(msg.get('Reply-To', ''))])
    sender = from_address[0][1] if from_address else ''
    reply_to = reply_address[0][1] if reply_address else ''
    headers = {
        'from': str(msg.get('From', '')),
        'sender_address': sender,
        'to': str(msg.get('To', '')),
        'subject': str(msg.get('Subject', '')),
        'reply_to': str(msg.get('Reply-To', '')),
        'date': str(msg.get('Date', '')),
        'received': [str(v) for v in msg.get_all('Received', [])],
        'authentication_results_unverified': [str(v) for v in msg.get_all('Authentication-Results', [])],
    }
    findings = []
    if reply_to and sender and reply_to.lower() != sender.lower():
        findings.append({'type': 'reply_to_mismatch', 'detail': 'Reply-To differs from From; may be legitimate.'})
    links, attachments = [], []
    parts = list(msg.walk())
    if len(parts) > MAX_PARTS:
        raise ValueError('Email exceeds MIME part count limit')
    for part in parts:
        if part.is_multipart():
            continue
        data = part.get_payload(decode=True)
        if data is None:
            data = b''
        filename = part.get_filename()
        if filename is not None or part.get_content_disposition() == 'attachment':
            attachment_name = filename or '(unnamed)'
            extension = Path(attachment_name).suffix.lower()
            attachments.append({'filename': attachment_name, 'size_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'content_type': part.get_content_type()})
            if extension in ACTIVE_ATTACHMENT_EXTENSIONS:
                findings.append({'type': 'active_attachment', 'detail': f'Attachment {attachment_name} has a potentially active file type ({extension}); do not open it without review.'})
            if extension in {'.html', '.htm'} or part.get_content_type() == 'text/html':
                findings.extend(_inspect_html_attachment(data))
            continue
            continue
        if part.get_content_type() not in ('text/plain', 'text/html'):
            continue
        charset = part.get_content_charset() or 'utf-8'
        try:
            body = data.decode(charset, errors='replace')[:MAX_TEXT_CHARS]
        except LookupError:
            body = data.decode('utf-8', errors='replace')[:MAX_TEXT_CHARS]
        if part.get_content_type() == 'text/html':
            parser = LinkParser()
            parser.feed(body)
            for link in parser.links:
                url = link['url']
                if url.lower().startswith(('http://', 'https://')):
                    links.append({'url': url, 'display_text': link['display_text'].strip(), 'source': 'html_anchor'})
                    displayed = link['display_text'].strip()
                    if displayed.lower().startswith(('http://', 'https://')) and _hostname(displayed) != _hostname(url):
                        findings.append({'type': 'display_url_mismatch', 'detail': 'Visible URL hostname differs from hyperlink destination.'})
        for url in URL_RE.findall(body):
            links.append({'url': url.rstrip('.,);'), 'display_text': '', 'source': part.get_content_type()})
    # One entry per exact destination URL, retaining all observed contexts.
    unique_by_url = {}
    for link in links:
        url = link['url']
        if url not in unique_by_url:
            unique_by_url[url] = {'url': url, 'display_text': link['display_text'],
                                  'source': link['source'], 'sources': [], 'display_texts': []}
        entry = unique_by_url[url]
        if link['source'] not in entry['sources']:
            entry['sources'].append(link['source'])
        if link['display_text'] and link['display_text'] not in entry['display_texts']:
            entry['display_texts'].append(link['display_text'])
    for url in unique_by_url:
        findings.extend(_url_findings(url))
    # Repeated identical findings do not increase a score.
    findings = list({f['type']: f for f in findings}.values())
    weights = {'display_url_mismatch': 50, 'reply_to_mismatch': 15,
               'active_attachment': 25, 'shortened_url': 15, 'ip_address_url': 20,
               'html_form': 15, 'html_password_field': 25, 'html_script': 15, 'html_redirect': 20}
    contributions = [{'type': f['type'], 'points': weights.get(f['type'], 0),
                      'reason': f['detail']} for f in findings]
    score = min(100, sum(c['points'] for c in contributions))
    severity = 'high' if score >= 60 else 'medium' if score >= 30 else 'low' if score > 0 else 'no_indicators_detected'
    return {'sha256_email': hashlib.sha256(raw).hexdigest(), 'headers': headers, 'links': list(unique_by_url.values()), 'attachments': attachments, 'findings': findings, 'risk': {'score': score, 'severity': severity, 'contributions': contributions, 'method': 'heuristic_v2', 'note': 'Triage priority only; not probability of maliciousness or a clean verdict.'}, 'recommendations': _recommendations(findings), 'analysis_notes': ['Offline static analysis only; no URLs visited or attachments executed.', 'Authentication-Results headers are unverified and may be forged; trusted receiving-server context is required.', 'No threat intelligence or definitive maliciousness assessment in Phase 1.']}


def analyze_file(path: str | Path) -> dict:
    path = Path(path)
    if path.stat().st_size > MAX_EMAIL_BYTES:
        raise ValueError('Email exceeds 10 MiB size limit')
    return analyze_bytes(path.read_bytes())


def _recommendations(findings: list[dict]) -> list[str]:
    if not findings:
        return ['No current rule matched; do not treat this as proof the email is safe.', 'If unexpected, verify the request with the sender through a known independent channel.']
    advice = ['Do not click links, open attachments, or reply until the message is independently verified.', 'Forward the original email as an attachment to your IT provider or security contact for investigation.']
    types = {f['type'] for f in findings}
    if types & {'active_attachment', 'html_form', 'html_password_field', 'html_script', 'html_redirect'}:
        advice.append('Quarantine the attachment for specialist review; do not open it in a browser.')
    if types & {'shortened_url', 'display_url_mismatch', 'ip_address_url'}:
        advice.append('Verify the destination through an independently located official website; do not follow the email link.')
    return advice
