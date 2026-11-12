"""Offline, non-executing analysis of RFC 5322 .eml messages."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit
from phishing_triage.domains import is_ip_host, registrable_domain

URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
MAX_EMAIL_BYTES = 10 * 1024 * 1024
MAX_PARTS = 100
MAX_TEXT_CHARS = 1_000_000
MAX_ATTACHMENT_SCAN_BYTES = 1_000_000
SHORTENER_HOSTS = frozenset({'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rebrand.ly', 'ow.ly', 'buff.ly'})
ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img'}
DOCUMENT_EXTENSIONS = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt', '.jpg', '.png'}
ACTIVE_ATTACHMENT_EXTENSIONS = {'.html', '.htm', '.js', '.jse', '.vbs', '.vbe', '.wsf', '.hta', '.lnk', '.url', '.svg', '.iso', '.img', '.exe', '.scr', '.ps1', '.bat', '.cmd', '.docm', '.xlsm', '.pptm'}

# Small, explicit demonstration list. Not a general-purpose brand reputation system.
LOOKALIKE_LABELS = {
    'micros0ft': 'microsoft',
    'paypa1': 'paypal',
    'g00gle': 'google',
    'app1e': 'apple',
}


def _inspect_html_attachment(data: bytes) -> list[dict]:
    """Bounded, non-executing text inspection; never follows URLs."""
    text = data[:MAX_ATTACHMENT_SCAN_BYTES].decode('utf-8', errors='replace')
    patterns = (
        ('html_form', r'<\s*form\b', 'HTML attachment contains a form; review for credential collection.'),
        ('html_password_field', r'<\s*input\b[^>]{0,1500}\btype\s*=\s*["\']?password\b', 'HTML attachment contains a password input.'),
        ('html_script', r'<\s*script\b', 'HTML attachment contains script markup; content was not executed.'),
        ('html_redirect', r'http-equiv\s*=\s*["\']?refresh\b|\blocation\s*\.(?:href|replace|assign)\b', 'HTML attachment contains a possible redirect instruction.'),
    )
    return [{'type': kind, 'detail': detail} for kind, pattern, detail in patterns if re.search(pattern, text, flags=re.I)]


def _domain(address: str) -> str:
    return address.rsplit('@', 1)[-1].lower() if '@' in address else ''


def _hostname(url: str) -> str:
    try:
        return (urlsplit(url).hostname or '').lower()
    except ValueError:
        return ''


def _lookalike_findings(host: str) -> list[dict]:
    """Match only explicitly configured suspicious labels; no network lookups."""
    labels = host.lower().rstrip('.').split('.')
    for label in labels:
        for suspicious, intended in LOOKALIKE_LABELS.items():
            if label == suspicious or label.startswith(suspicious + '-'):
                return [{'type': 'lookalike_domain', 'detail':
                         f'Domain label {label!r} resembles {intended!r} using character substitution; verify ownership independently.'}]
    return []


def _url_findings(url: str, sender_domain: str = '') -> list[dict]:
    host = _hostname(url)
    if not host:
        return []
    results = []
    if host in SHORTENER_HOSTS:
        results.append({'type': 'shortened_url', 'detail': 'Shortened URL; final destination not resolved.'})
        results.append({'type': 'url_shortener', 'detail': 'Shortened URL; final destination not resolved.'})
    if is_ip_host(host):
        results.append({'type': 'ip_address_link', 'detail': 'Link uses an IP address rather than a domain name.'})
    if any(label.startswith('xn--') for label in host.split('.')):
        results.append({'type': 'punycode_link', 'detail': 'Link contains an IDN punycode label; verify destination.'})
    try:
        if urlsplit(url).username is not None:
            results.append({'type': 'credentials_in_url', 'detail': 'URL contains a userinfo component before the host.'})
    except ValueError:
        pass
    if sender_domain and not is_ip_host(host) and registrable_domain(host) != registrable_domain(sender_domain):
        results.append({'type': 'link_domain_mismatch', 'detail': 'Link destination domain differs from sender domain; may be legitimate.'})
    results.extend(_lookalike_findings(host))
    return results


def _attachment_findings(filename: str, data: bytes) -> list[dict]:
    """Inspect filename and magic bytes without executing attachment content."""
    findings = []
    lower = filename.lower()
    ext = Path(lower).suffix
    parts = lower.split('.')
    if ext in ACTIVE_ATTACHMENT_EXTENSIONS:
        findings.append({'type': 'active_attachment', 'detail': f'Potentially active attachment: {filename}.'})
        findings.append({'type': 'risky_attachment', 'detail': f'Potentially active attachment: {filename}.'})
    if ext in ARCHIVE_EXTENSIONS:
        findings.append({'type': 'archive_attachment', 'detail': f'Archive attachment: {filename}; contents not opened.'})
    if len(parts) >= 3 and any('.' + x in DOCUMENT_EXTENSIONS for x in parts[1:-1]) and ext in ACTIVE_ATTACHMENT_EXTENSIONS:
        findings.append({'type': 'double_extension', 'detail': f'Filename uses a document extension followed by an active extension: {filename}.'})
    if any(c in filename for c in ('\u202e', '\u202d', '\u202a', '\u202b', '\u202c', '\u2066', '\u2067', '\u2068', '\u2069')):
        findings.append({'type': 'filename_obfuscation', 'detail': 'Attachment filename contains bidirectional formatting characters.'})
    if data.startswith(b'MZ') and ext not in {'.exe', '.dll', '.scr', '.com'}:
        findings.append({'type': 'disguised_executable', 'detail': f'Attachment {filename} has an executable header inconsistent with its extension.'})
    elif ext == '.pdf' and data and not data.startswith(b'%PDF-'):
        findings.append({'type': 'attachment_type_mismatch', 'detail': f'Attachment {filename} does not begin with a PDF signature.'})
    return findings

def _brand_impersonation_findings(
    from_header: str, subject: str, sender_domain: str
) -> list[dict]:
    """Flag Norton branding in the sender display name from unrelated domains."""
    parsed = getaddresses([from_header])
    display_name = parsed[0][0] if parsed else ''

    claimed_brand = bool(
        re.search(r'\bnorton\b', display_name, re.IGNORECASE)
    )
    if not claimed_brand:
        return []

    domain = sender_domain.lower().strip().rstrip('.')
    if domain == 'norton.com' or domain.endswith('.norton.com'):
        return []

    return [{
        'type': 'brand_impersonation',
        'detail': (
            'Sender display name claims Norton branding, but the From '
            'address does not use norton.com. This requires independent '
            'verification; legitimate third-party senders may exist.'
        ),
    }]


def _text_findings(text: str) -> list[dict]:
    """Detect sensitive-information requests and suspicious payment changes."""
    normalized = re.sub(r'\s+', ' ', text).lower()
    findings = []

    # Existing detection: requests for sensitive information.
    sensitive = bool(re.search(
        r'\b(?:passwords?|passcodes?|bank\s+account\s+details?|'
        r'banking\s+details?|account\s+credentials?)\b',
        normalized
    ))

    request = bool(re.search(
        r'\b(?:send|provide|share|reply\s+with|email|submit)\b',
        normalized
    ))

    if sensitive and request:
        findings.append({
            'type': 'sensitive_information_request',
            'detail': (
                'Message requests sensitive credentials or banking '
                'information; independently verify the request.'
            )
        })

        if re.search(
            r'\b(?:urgent(?:ly)?|immediately|asap|right\s+away)\b',
            normalized
        ):
            findings.append({
                'type': 'urgent_sensitive_request',
                'detail': (
                    'Sensitive-information request uses urgency '
                    'or time pressure.'
                )
            })

        if re.search(
            r'\b(?:do\s+not|don\'t|never)\s+'
            r'(?:contact|call|tell|notify|inform)\b',
            normalized
        ):
            findings.append({
                'type': 'discourage_verification',
                'detail': (
                    'Sensitive-information request discourages '
                    'independent verification.'
                )
            })

    # Phase 1.7: Detect requests to change payment instructions.
    payment_change = bool(re.search(
        r'\b(?:change|update|replace|switch|redirect|use\s+(?:a\s+)?new)\b'
        r'.{0,100}\b(?:bank\s+account|banking\s+details|'
        r'payment\s+(?:details|instructions)|routing\s+number|'
        r'wire\s+instructions)\b',
        normalized
    ))

    payment_context = bool(re.search(
        r'\b(?:invoice|payment|vendor|supplier|'
        r'wire\s+transfer|accounts\s+payable)\b',
        normalized
    ))

    if payment_change and payment_context:
        findings.append({
            'type': 'payment_instruction_change',
            'detail': (
                'Message appears to request a change to banking or '
                'payment instructions. Verify the request using a '
                'previously established contact method.'
            )
        })

    return findings



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
    findings.extend(_lookalike_findings(_domain(sender)))
    findings.extend(
        _brand_impersonation_findings(
            headers['from'], headers['subject'], _domain(sender)
        )
    )    
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
            findings.extend(_attachment_findings(attachment_name, data))
            if extension in {'.html', '.htm'} or part.get_content_type() == 'text/html':
                findings.extend(_inspect_html_attachment(data))
                for attachment_url in URL_RE.findall(data[:MAX_ATTACHMENT_SCAN_BYTES].decode('utf-8', errors='replace')):
                    findings.extend(_url_findings(attachment_url.rstrip('.,);')))
            continue
        if part.get_content_type() not in ('text/plain', 'text/html'):
            continue
        charset = part.get_content_charset() or 'utf-8'
        try:
            body = data.decode(charset, errors='replace')[:MAX_TEXT_CHARS]
        except LookupError:
            body = data.decode('utf-8', errors='replace')[:MAX_TEXT_CHARS]
        findings.extend(_text_findings(body))
        if part.get_content_type() == 'text/html':
            parser = LinkParser()
            parser.feed(body)
            for link in parser.links:
                url = link['url']
                if url.lower().startswith(('http://', 'https://')):
                    links.append({'url': url, 'display_text': link['display_text'].strip(), 'source': 'html_anchor'})
                    if link['display_text'].strip().lower().startswith(('http://', 'https://')):
                        links.append({'url': link['display_text'].strip(), 'display_text': '', 'source': 'html_visible_text'})
                    displayed = link['display_text'].strip()
                    visible_host = _hostname(displayed) if displayed.lower().startswith(('http://', 'https://')) else _hostname('https://' + displayed)
                    if visible_host and '.' in visible_host and registrable_domain(visible_host) != registrable_domain(_hostname(url)):
                        findings.append({'type': 'display_url_mismatch', 'detail': 'Visible link domain differs from hyperlink destination.'})
        if part.get_content_type() == 'text/plain':
            for url in URL_RE.findall(body):
                links.append({'url': url.rstrip('.,);'), 'display_text': '', 'source': part.get_content_type()})
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
        source_contexts = unique_by_url[url]['sources']
        findings.extend(_url_findings(url, _domain(sender)))

    # Repeated identical finding types do not increase a score.
    findings = list({f['type']: f for f in findings}.values())

    # Risk scoring weights.
    weights = {
        'display_url_mismatch': 50,
        'reply_to_mismatch': 15,
        'active_attachment': 25,
        'risky_attachment': 0,
        'archive_attachment': 15,
        'double_extension': 20,
        'filename_obfuscation': 20,
        'disguised_executable': 65,
        'attachment_type_mismatch': 20,
        'shortened_url': 15,
        'url_shortener': 0,
        'ip_address_link': 20,
        'punycode_link': 20,
        'credentials_in_url': 25,
        'link_domain_mismatch': 10,
        'html_form': 15,
        'html_password_field': 25,
        'html_script': 15,
        'html_redirect': 20,
        'sensitive_information_request': 15,
        'urgent_sensitive_request': 10,
        'discourage_verification': 15,
        'lookalike_domain': 35,
        'brand_impersonation': 25,
        'payment_instruction_change': 25,
    }

    contributions = [
        {
            'type': f['type'],
            'points': weights.get(f['type'], 0),
            'reason': f['detail']
        }
        for f in findings
        if weights.get(f['type'], 0) > 0
    ]

    score = min(100, sum(c['points'] for c in contributions))

    severity = (
        'high' if score >= 60
        else 'medium' if score >= 30
        else 'low' if score > 0
        else 'no_indicators_detected'
    )

    return {
        'sha256_email': hashlib.sha256(raw).hexdigest(),
        'headers': headers,
        'links': list(unique_by_url.values()),
        'attachments': attachments,
        'findings': findings,
        'risk': {
            'score': score,
            'severity': severity,
            'contributions': contributions,
            'method': 'heuristic_v3',
            'note': (
                'Triage priority only; not probability of maliciousness '
                'or a clean verdict.'
            )
        },
        'recommendations': _recommendations(findings),
        'analysis_notes': [
            'Offline static analysis only; no URLs visited or attachments executed.',
            'Authentication-Results headers are unverified and may be forged; trusted receiving-server context is required.',
            'Lookalike detection uses a small explicit pattern list; it does not establish domain ownership or maliciousness.',
            'No threat intelligence or definitive maliciousness assessment in Phase 1.',
        ],
    }



def analyze_file(path: str | Path) -> dict:
    path = Path(path)
    if path.stat().st_size > MAX_EMAIL_BYTES:
        raise ValueError('Email exceeds 10 MiB size limit')
    return analyze_bytes(path.read_bytes())


def _recommendations(findings: list[dict]) -> list[str]:
    if not findings:
        return ['No current rule matched; do not treat this as proof the email is safe.',
                'If unexpected, verify the request with the sender through a known independent channel.']
    advice = ['Do not click links, open attachments, or reply until the message is independently verified.',
              'Forward the original email as an attachment to your IT provider or security contact for investigation.']
    types = {f['type'] for f in findings}
    if types & {'active_attachment', 'risky_attachment', 'archive_attachment', 'double_extension', 'filename_obfuscation', 'disguised_executable', 'attachment_type_mismatch', 'html_form', 'html_password_field', 'html_script', 'html_redirect'}:
        advice.append('Quarantine the attachment for specialist review; do not open it in a browser.')
    if types & {'shortened_url', 'url_shortener', 'display_url_mismatch', 'ip_address_link', 'punycode_link', 'credentials_in_url', 'link_domain_mismatch', 'lookalike_domain'}:
        advice.append('Verify the destination through an independently located official website; do not follow the email link.')
    if types & {'sensitive_information_request', 'urgent_sensitive_request', 'discourage_verification'}:
        advice.append('Never provide passwords or banking details in response to an unverified email request; contact the organization independently.')
    return advice
