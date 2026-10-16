from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html.parser import HTMLParser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TIMEOUT_SECONDS = 7
MAX_RESPONSE_BYTES = 128_000
USER_AGENT = 'AcademicSecurityResearchPlatform/1.0 (passive-checks-only)'

RESEARCH_TOPICS = {
    'identity': {
        'title': 'Authentication & identity verification',
        'description': 'Study whether identity checks are consistently enforced at sensitive actions. Public unauthenticated inspection cannot prove account-level authentication flaws.',
        'checks': ['Map the documented sign-in and recovery flows.', 'Use only test accounts you control in an approved environment.', 'Verify expected behavior for missing, expired, and invalid sessions without attempting to access another user’s account.'],
        'evidence': 'Sanitized request/response pairs from an authorized test account, expected-vs-actual behavior, and relevant application logs.',
        'fix': 'Enforce server-side authentication on every sensitive operation; expire and rotate sessions appropriately; use secure recovery flows and rate limits.',
    },
    'authorization': {
        'title': 'Authorization & access control',
        'description': 'Look for design risks where a server may rely on client-side controls instead of checking permissions for every request.',
        'checks': ['Create two test users and resources in a local or explicitly authorized test environment.', 'Document each role’s expected permissions.', 'Check server-side denial behavior using only resources created for the test.'],
        'evidence': 'Test matrix of roles, resources, expected decisions, actual status codes, and server-side audit logs.',
        'fix': 'Perform authorization checks server-side for every object and action; deny by default; add regression tests for cross-user access.',
    },
    'input': {
        'title': 'Input validation',
        'description': 'Assess whether inputs are validated by type, length, format, and business rules. The public scanner does not submit payloads to third-party sites.',
        'checks': ['Review documented input schemas and client/server validation boundaries.', 'Use harmless boundary and malformed-input cases in your own staging app.', 'Check that errors do not disclose secrets or internal traces.'],
        'evidence': 'Reproducible test case, expected validation rule, actual response, and sanitized logs.',
        'fix': 'Validate on the server with allowlists and strict schemas; encode output by context; use parameterized database queries.',
    },
    'api': {
        'title': 'API security & API key configuration',
        'description': 'Review API-key restrictions and exposure using documentation and configurations you own. A browser-visible key is not automatically a vulnerability; its restrictions and intended use matter.',
        'checks': ['Inventory keys belonging to your project without publishing their values.', 'Verify application/API restrictions and quota limits in the provider console.', 'Review logs for unexpected usage and rotate keys if exposure is confirmed.'],
        'evidence': 'Redacted configuration screenshots, restriction settings, usage logs, and the affected project/service.',
        'fix': 'Restrict keys by API and application, keep server-side secrets on the server, apply quotas and monitoring, and rotate exposed credentials.',
    },
    'business': {
        'title': 'Business Profile verification workflows',
        'description': 'Research process integrity and account security using official guidance. This platform does not attempt to bypass Google verification or alter real business profiles.',
        'checks': ['Review official ownership and verification documentation.', 'Use a profile you manage and follow the normal verification flow.', 'Record confusing or inconsistent UI behavior without submitting deceptive evidence or accessing another profile.'],
        'evidence': 'Screenshots with personal data redacted, official policy references, timestamps, and steps observed on an account you manage.',
        'fix': 'Use supported verification and recovery channels; secure account access with strong authentication; report suspected issues through official channels.',
    },
    'session': {
        'title': 'Session management',
        'description': 'Review session cookie flags and lifecycle behavior. A public response can show cookie attributes, but cannot prove all session lifecycle properties.',
        'checks': ['Inspect Set-Cookie attributes in responses that are publicly accessible.', 'In your own test app, verify logout, expiry, and session rotation behavior.', 'Avoid collecting or sharing real session tokens.'],
        'evidence': 'Cookie attribute names only, redacted response headers, and repeatable tests in an authorized environment.',
        'fix': 'Use Secure, HttpOnly, and suitable SameSite attributes; rotate session identifiers after privilege changes; invalidate sessions server-side.',
    },
    'rate': {
        'title': 'Rate limiting & abuse prevention',
        'description': 'A passive public check cannot reliably establish rate-limit behavior. Validate controls in an authorized test environment with low-volume tests.',
        'checks': ['Find documented quotas and service limits.', 'Use a staging endpoint and a pre-agreed low request budget.', 'Confirm expected throttling and retry guidance from logs and response codes.'],
        'evidence': 'Approved test window, request counts, timestamps, response codes, and server-side metrics.',
        'fix': 'Apply per-account and per-IP limits where appropriate, progressive throttling, abuse monitoring, and safe retry policies.',
    },
}

OFFICIAL_SOURCES = [
    {'title': 'OWASP Web Security Testing Guide', 'url': 'https://owasp.org/www-project-web-security-testing-guide/'},
    {'title': 'OWASP Top 10', 'url': 'https://owasp.org/www-project-top-ten/'},
    {'title': 'NIST National Vulnerability Database', 'url': 'https://nvd.nist.gov/'},
    {'title': 'Google Maps Platform Security Best Practices', 'url': 'https://developers.google.com/maps/api-security-best-practices'},
    {'title': 'Google Security', 'url': 'https://security.googleblog.com/'},
    {'title': 'Google Vulnerability Reward Program', 'url': 'https://bughunters.google.com/about/rules'},
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def validate_public_url(raw_url: str) -> tuple[str, str]:
    """Validate URL and reject local/private/reserved targets before making a passive request."""
    if not isinstance(raw_url, str) or len(raw_url) > 2048:
        raise ValueError('Enter a valid URL no longer than 2048 characters.')
    raw_url = raw_url.strip()
    parsed = urllib.parse.urlsplit(raw_url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError('Only http:// and https:// URLs are supported.')
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('URL must include a hostname and must not contain embedded credentials.')
    try:
        _ = parsed.port
    except ValueError:
        raise ValueError('URL contains an invalid port.')
    host = parsed.hostname.rstrip('.').lower()
    if not host or any(ch.isspace() for ch in host):
        raise ValueError('URL hostname is invalid.')
    if host in {'localhost', 'localhost.localdomain'} or host.endswith('.local'):
        raise ValueError('Local hostnames are blocked by the scanner.')
    try:
        literal_ip = ipaddress.ip_address(host.strip('[]'))
        if not literal_ip.is_global:
            raise ValueError('Private, local, and reserved IP addresses are blocked.')
        addresses = [str(literal_ip)]
    except ValueError as e:
        if str(e) == 'Private, local, and reserved IP addresses are blocked.':
            raise
        try:
            records = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == 'https' else 80), type=socket.SOCK_STREAM)
            addresses = list({record[4][0] for record in records})
        except socket.gaierror:
            raise ValueError('Hostname could not be resolved from this environment.')
        if not addresses:
            raise ValueError('Hostname did not resolve to an address.')
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                raise ValueError('Hostname resolved to an invalid address.')
            if not ip.is_global:
                raise ValueError('Hostnames resolving to private, local, or reserved addresses are blocked.')
    # Strip fragments; keep path/query as supplied.
    normalized = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '/', parsed.query, ''))
    return normalized, host


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_passive(url: str) -> dict[str, Any]:
    """Make one small GET request; do not follow redirects or submit test payloads."""
    request_obj = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, 'Accept': 'text/html,application/xhtml+xml,*/*;q=0.5'}, method='GET')
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request_obj, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(MAX_RESPONSE_BYTES)
            return {'status': response.status, 'headers': dict(response.headers.items()), 'body': body, 'final_url': response.geturl(), 'error': None}
    except urllib.error.HTTPError as e:
        # HTTPError also carries response headers/body. Redirects are reported, never followed.
        body = e.read(MAX_RESPONSE_BYTES) if e.fp else b''
        return {'status': e.code, 'headers': dict(e.headers.items()) if e.headers else {}, 'body': body, 'final_url': url, 'error': None}
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as e:
        raise RuntimeError(f'Connection failed: {type(e).__name__}: {e}') from e


def _finding(title: str, severity: str, status: str, evidence: str, recommendation: str,
             category: str = 'Security Misconfiguration', confidence: str = 'high') -> dict[str, Any]:
    return {'title': title, 'severity': severity, 'status': status, 'evidence': evidence,
            'recommendation': recommendation, 'category': category, 'confidence': confidence}


def analyze_headers(headers: dict[str, str], url: str, body: bytes = b'', status_code: int = 200) -> list[dict[str, Any]]:
    """Analyze observed response headers conservatively; observations are not exploit proof."""
    lowered = {str(k).lower(): str(v).strip() for k, v in headers.items()}
    findings: list[dict[str, Any]] = []
    is_https = url.lower().startswith('https://')

    if is_https:
        hsts = lowered.get('strict-transport-security')
        if not hsts:
            findings.append(_finding('Missing Strict-Transport-Security header', 'medium', 'potential_issue',
                'HTTPS response did not include Strict-Transport-Security.',
                'Consider a staged HSTS rollout after confirming all relevant hosts support HTTPS.'))
        else:
            match = re.search(r'(?:^|;)\s*max-age\s*=\s*(\d+)', hsts, re.I)
            if not match:
                findings.append(_finding('HSTS max-age directive missing or invalid', 'low', 'potential_issue',
                    f'Observed Strict-Transport-Security: {hsts[:250]}',
                    'Set a deliberate max-age after validating HTTPS coverage across the domain.'))
            elif int(match.group(1)) < 15552000:
                findings.append(_finding('HSTS max-age is relatively short', 'info', 'potential_issue',
                    f'Observed max-age={match.group(1)} seconds.',
                    'Review whether a longer max-age is appropriate; change gradually after HTTPS readiness is confirmed.'))
            else:
                findings.append(_finding('HSTS header observed', 'info', 'observed', f'Strict-Transport-Security: {hsts[:250]}',
                    'Confirm the policy matches deployment needs; includeSubDomains/preload have operational consequences.'))
    else:
        findings.append(_finding('HSTS not assessed because target used HTTP', 'info', 'not_assessed',
            'The supplied URL uses HTTP, so HSTS cannot be assessed on this response.',
            'Check the HTTPS endpoint and confirm HTTP redirects to HTTPS.'))

    checks = [
        ('content-security-policy', 'Missing Content-Security-Policy header', 'low', 'A suitable CSP can reduce the impact of some injection issues; design it for the application.'),
        ('x-content-type-options', 'Missing X-Content-Type-Options header', 'low', 'Use X-Content-Type-Options: nosniff where appropriate.'),
        ('referrer-policy', 'Missing Referrer-Policy header', 'info', 'Set a deliberate referrer policy appropriate to the application.'),
        ('permissions-policy', 'Missing Permissions-Policy header', 'info', 'Restrict browser features the application does not need.'),
    ]
    for key, title, severity, advice in checks:
        if key not in lowered:
            findings.append(_finding(title, severity, 'potential_issue', f'Response did not include the {key} header.', advice))
        else:
            value = lowered[key]
            findings.append(_finding(f'{key} header present', 'info', 'observed', f'{key}: {value[:300]}',
                'Review the value against application-specific requirements; presence alone does not prove correct configuration.'))
            if key == 'x-content-type-options' and value.lower() != 'nosniff':
                findings.append(_finding('X-Content-Type-Options has an unexpected value', 'low', 'potential_issue',
                    f'Observed value: {value[:150]}', "Use the value 'nosniff' where this header is intended."))

    csp = lowered.get('content-security-policy', '')
    if csp:
        csp_lower = csp.lower()
        risky = [x for x in ("'unsafe-inline'", "'unsafe-eval'", 'wildcard source (*)')
                 if (x == 'wildcard source (*)' and '*' in csp_lower) or (x != 'wildcard source (*)' and x in csp_lower)]
        if risky:
            findings.append(_finding('CSP contains permissive source expressions', 'low', 'potential_issue',
                'Observed CSP includes: ' + ', '.join(risky),
                'Review whether these directives are necessary; prefer nonces/hashes and narrowly scoped sources. This is not proof of XSS.',
                'Injection Prevention', 'medium'))
        directives = {part.strip().split()[0].lower() for part in csp.split(';') if part.strip()}
        missing = [d for d in ('object-src', 'base-uri') if d not in directives]
        if missing:
            findings.append(_finding('CSP hardening directives not observed', 'info', 'potential_issue',
                'Missing directives: ' + ', '.join(missing),
                "Consider object-src 'none' and a suitable base-uri directive if compatible with the app.",
                'Injection Prevention', 'medium'))

    acao = lowered.get('access-control-allow-origin', '')
    acac = lowered.get('access-control-allow-credentials', '').lower()
    if acao == '*' and acac == 'true':
        findings.append(_finding('CORS wildcard origin combined with credentials', 'medium', 'potential_issue',
            'Observed Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true.',
            'Verify actual browser behavior and intended origins; credentialed CORS should use a strict origin allowlist.',
            'Access Control', 'medium'))
    elif acao:
        findings.append(_finding('CORS response policy observed', 'info', 'observed',
            f'Access-Control-Allow-Origin: {acao[:200]}; credentials={acac or "not set"}',
            'Confirm allowed origins are intentional and are not reflected from untrusted input.', 'Access Control', 'medium'))

    if 'x-frame-options' not in lowered and 'frame-ancestors' not in csp.lower():
        findings.append(_finding('No anti-framing directive observed', 'info', 'potential_issue',
            'Neither X-Frame-Options nor CSP frame-ancestors was observed.',
            'If the application should not be embedded, configure CSP frame-ancestors and/or X-Frame-Options.',
            'Clickjacking Prevention', 'medium'))

    for key in ('server', 'x-powered-by'):
        if lowered.get(key):
            findings.append(_finding(f'{key} response header disclosed', 'info', 'observed',
                f'{key}: {lowered[key][:200]}',
                'Consider removing unnecessary product/version details. Disclosure alone is not a vulnerability.',
                'Information Disclosure'))

    cookies = lowered.get('set-cookie', '')
    if cookies:
        missing = [flag for flag in ('secure', 'httponly', 'samesite') if flag not in cookies.lower()]
        if missing:
            findings.append(_finding('Cookie attributes may need review', 'low', 'potential_issue',
                'A Set-Cookie header was observed; values are omitted. Attributes not detected in combined header: ' + ', '.join(missing),
                'Inspect each cookie separately. Apply Secure, HttpOnly, and suitable SameSite according to cookie purpose.',
                'Session Management', 'low'))
        else:
            findings.append(_finding('Expected cookie attributes observed', 'info', 'observed',
                'Set-Cookie appears to include Secure, HttpOnly, and SameSite; values are omitted.',
                'Review each cookie independently and verify session lifecycle in an authorized test environment.',
                'Session Management', 'low'))

    if 300 <= status_code < 400:
        location = lowered.get('location', '')
        findings.append(_finding('Redirect response observed (not followed)', 'info', 'observed',
            f'HTTP {status_code}; Location: {location[:300] or "(not provided)"}.',
            'Review redirect destination manually. The scanner intentionally does not follow redirects.', 'Transport Security'))

    if status_code >= 500 and body:
        sample = body[:MAX_RESPONSE_BYTES].decode('utf-8', 'ignore')
        patterns = [(r'traceback \(most recent call last\)', 'Python traceback-like text'),
                    (r'exception in thread|stack trace', 'stack trace-like text'),
                    (r'sql syntax.*mysql|postgresql.*error', 'database error-like text')]
        for pattern, label in patterns:
            if re.search(pattern, sample, re.I):
                findings.append(_finding('Possible verbose error details in server error response', 'medium', 'potential_issue',
                    f'Response body matched a heuristic for {label}; body contents are not copied into the report.',
                    'Return generic client-facing errors and keep diagnostics in protected server logs.', 'Error Handling', 'low'))
                break
    return findings

def run_scan(raw_url: str) -> dict[str, Any]:
    url, host = validate_public_url(raw_url)
    response = fetch_passive(url)
    findings = analyze_headers(response['headers'], url, response['body'], response['status'])
    parsed = urllib.parse.urlsplit(url)
    tls_result = {'status': 'not_assessed', 'details': 'TLS certificate check is only attempted for HTTPS URLs.'}
    if parsed.scheme == 'https':
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, parsed.port or 443), timeout=TIMEOUT_SECONDS) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    not_after = cert.get('notAfter')
                    days_remaining = None
                    if not_after:
                        try:
                            expiry_epoch = ssl.cert_time_to_seconds(not_after)
                            days_remaining = int((expiry_epoch - datetime.now(timezone.utc).timestamp()) // 86400)
                        except (ValueError, TypeError, OverflowError):
                            days_remaining = None
                    tls_result = {'status': 'passed', 'details': 'TLS handshake and certificate validation succeeded.',
                        'subject': str(cert.get('subject', ''))[:300], 'issuer': str(cert.get('issuer', ''))[:300],
                        'notAfter': not_after, 'days_remaining': days_remaining}
                    if days_remaining is not None and days_remaining <= 21:
                        tls_result['status'] = 'warning'
                        tls_result['details'] = f'TLS certificate validates, but its recorded expiry is in {days_remaining} day(s).'
                        findings.append(_finding('TLS certificate expires soon', 'medium' if days_remaining <= 7 else 'low',
                            'potential_issue', f'Certificate expiry is approximately {days_remaining} day(s) away.',
                            'Renew the certificate before expiry and verify automated renewal monitoring.', 'Transport Security'))
        except Exception as e:
            tls_result = {'status': 'warning', 'details': f'TLS handshake/certificate validation failed: {type(e).__name__}.'}
            findings.append({'title': 'TLS certificate validation failed during scanner check', 'severity': 'high', 'status': 'potential_issue', 'evidence': tls_result['details'], 'recommendation': 'Check certificate validity, hostname match, certificate chain, and server TLS configuration.'})
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    findings.sort(key=lambda item: severity_order.get(item.get('severity', 'info'), 4))
    counts = {level: sum(1 for item in findings if item.get('severity') == level) for level in severity_order}
    return {
        'id': f'scan-{datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")}',
        'timestamp': utc_now(), 'target': url, 'hostname': host,
        'mode': 'passive-public-checks', 'http_status': response['status'],
        'tls': tls_result,
        'summary': {'total_findings': len(findings), 'severity_counts': counts,
                    'confirmed_vulnerabilities': sum(1 for item in findings if item.get('status') == 'confirmed_vulnerability'),
                    'note': 'Passive observations are not proof of exploitability.'},
        'findings': findings,
        'limitations': ['Passive checks only; no exploit payloads were sent.', 'Only one response was inspected and redirects were not followed.', 'A missing header is a configuration observation, not proof of exploitable vulnerability.', 'Cookie headers may be combined by the HTTP client; cookie findings are heuristic.', 'This scan does not test authenticated flows, business logic, source code, JavaScript behavior, or all application endpoints.'],
        'sources': OFFICIAL_SOURCES,
    }



class LinkCollector(HTMLParser):
    """Extract only ordinary same-page navigation candidates from HTML."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() not in {'a', 'link'}:
            return
        values = dict(attrs)
        href = values.get('href')
        if href and len(href) <= 2048:
            self.links.append(href)


def extract_same_origin_links(html_bytes: bytes, current_url: str, max_links: int = 40) -> list[str]:
    """Extract deduplicated HTTP(S) links; actual origin and safety checks happen later."""
    text = html_bytes[:MAX_RESPONSE_BYTES].decode('utf-8', 'ignore')
    parser = LinkCollector()
    try:
        parser.feed(text)
    except Exception:
        return []
    current = urllib.parse.urlsplit(current_url)
    current_origin = (current.scheme.lower(), (current.hostname or '').lower(), current.port or (443 if current.scheme == 'https' else 80))
    out: list[str] = []
    seen: set[str] = set()
    for raw in parser.links:
        candidate = urllib.parse.urljoin(current_url, raw)
        try:
            parsed = urllib.parse.urlsplit(candidate)
            port = parsed.port
        except ValueError:
            continue
        if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname:
            continue
        origin = (parsed.scheme.lower(), parsed.hostname.lower(), port or (443 if parsed.scheme == 'https' else 80))
        if origin != current_origin:
            continue
        # Do not crawl fragments, query variants, or common state-changing paths.
        path = parsed.path or '/'
        if parsed.query or parsed.fragment:
            candidate = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, '', ''))
        if re.search(r'/(?:logout|log-out|signout|delete|remove|checkout|purchase|payment)(?:/|$)', path, re.I):
            continue
        candidate = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, '', ''))
        if candidate not in seen:
            seen.add(candidate)
            out.append(candidate)
        if len(out) >= max_links:
            break
    return out


def crawl_public_site(raw_url: str, max_pages: int = 8, max_depth: int = 1) -> dict[str, Any]:
    """Bounded same-origin crawl using passive GETs only; no forms, payloads, or redirects."""
    if not isinstance(max_pages, int) or max_pages < 1 or max_pages > 8:
        raise ValueError('max_pages must be between 1 and 8.')
    if not isinstance(max_depth, int) or max_depth < 0 or max_depth > 1:
        raise ValueError('max_depth must be 0 or 1.')
    start_url, host = validate_public_url(raw_url)
    start = urllib.parse.urlsplit(start_url)
    origin = (start.scheme.lower(), (start.hostname or '').lower(), start.port or (443 if start.scheme == 'https' else 80))
    queue: list[tuple[str, int]] = [(start_url, 0)]
    visited: set[str] = set()
    pages: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    while queue and len(visited) < max_pages:
        candidate, depth = queue.pop(0)
        if candidate in visited:
            continue
        # Revalidate every discovered URL to prevent private-address crawling.
        safe_url, candidate_host = validate_public_url(candidate)
        parsed = urllib.parse.urlsplit(safe_url)
        candidate_origin = (parsed.scheme.lower(), (parsed.hostname or '').lower(), parsed.port or (443 if parsed.scheme == 'https' else 80))
        if candidate_origin != origin or candidate_host.lower() != host.lower():
            continue
        visited.add(safe_url)
        response = fetch_passive(safe_url)
        page_findings = analyze_headers(response['headers'], safe_url, response['body'], response['status'])
        for finding in page_findings:
            finding = dict(finding)
            finding['page'] = safe_url
            all_findings.append(finding)
        pages.append({'url': safe_url, 'http_status': response['status'], 'content_type': response['headers'].get('Content-Type', response['headers'].get('content-type', ''))[:160], 'findings_count': len(page_findings)})
        content_type = response['headers'].get('Content-Type', response['headers'].get('content-type', '')).lower()
        if depth < max_depth and 'text/html' in content_type:
            for link in extract_same_origin_links(response['body'], safe_url):
                if link not in visited and all(link != queued[0] for queued in queue):
                    queue.append((link, depth + 1))
                    if len(queue) + len(visited) >= max_pages * 2:
                        break
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    all_findings.sort(key=lambda f: severity_order.get(f.get('severity', 'info'), 4))
    counts = {level: sum(1 for f in all_findings if f.get('severity') == level) for level in severity_order}
    return {
        'id': f'crawl-{datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")}',
        'timestamp': utc_now(), 'target': start_url, 'hostname': host,
        'mode': 'bounded-same-origin-passive-crawl', 'pages_scanned': len(pages), 'pages': pages,
        'summary': {'total_findings': len(all_findings), 'severity_counts': counts,
                    'confirmed_vulnerabilities': 0,
                    'note': 'Findings are passive configuration observations, not proof of exploitability.'},
        'findings': all_findings,
        'limitations': ['Crawl is limited to the same origin, at most 8 pages and depth 1.', 'Only GET requests are sent; forms and state-changing routes are not submitted.', 'Redirects are not followed.', 'No authenticated workflows, JavaScript-rendered routes, source code, or business logic are tested.', 'DNS rebinding protections depend on the runtime/network; use only authorized targets.'],
        'sources': OFFICIAL_SOURCES,
    }


def secure_lab_check(exercise: str, value: str = '', user_id: str = 'alice', resource_owner: str = 'alice') -> dict[str, Any]:
    """Run tiny safe demonstrations of defensive controls on synthetic data only."""
    if exercise == 'xss':
        rendered = html.escape(value[:500], quote=True)
        return {'exercise': exercise, 'passed': rendered == html.escape(value[:500], quote=True),
                'input': value[:500], 'safe_output': rendered,
                'explanation': 'The value is encoded for HTML text context; this demonstrates output encoding, not a full browser XSS test.'}
    if exercise == 'sqli':
        import sqlite3
        conn = sqlite3.connect(':memory:')
        try:
            conn.execute('CREATE TABLE demo_users (username TEXT, display_name TEXT)')
            conn.executemany('INSERT INTO demo_users VALUES (?, ?)', [('alice', 'Alice Demo'), ('bob', 'Bob Demo')])
            row = conn.execute('SELECT display_name FROM demo_users WHERE username = ?', (value[:120],)).fetchone()
            return {'exercise': exercise, 'passed': True, 'matched': bool(row),
                    'result': row[0] if row else None,
                    'explanation': 'A parameterized query treats user input as data, not SQL syntax. Only synthetic in-memory records were queried.'}
        finally:
            conn.close()
    if exercise == 'access-control':
        allowed = bool(user_id and resource_owner and user_id == resource_owner)
        return {'exercise': exercise, 'passed': (allowed if user_id == resource_owner else not allowed),
                'user_id': user_id[:80], 'resource_owner': resource_owner[:80], 'allowed': allowed,
                'explanation': 'The server-side policy allows access only when the synthetic user owns the synthetic resource.'}
    raise ValueError('Choose one of: xss, sqli, access-control.')

def build_research_plan(topic: str, target: str = 'Google Maps') -> dict[str, Any]:
    entry = RESEARCH_TOPICS.get(topic)
    if not entry:
        raise ValueError('Choose one of the supported research topics.')
    return {
        'target': target[:120], 'topic': topic, 'title': entry['title'], 'description': entry['description'],
        'status': 'research_plan_not_a_finding', 'generated_at': utc_now(),
        'checks': entry['checks'], 'evidence': entry['evidence'], 'remediation': entry['fix'],
        'sources': OFFICIAL_SOURCES,
        'notice': 'This is a research plan, not a claim that the named service has this vulnerability. Testing a live third-party service requires explicit authorization and must follow the owner’s published scope and rules.'
    }


class VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.parts=[]; self._skip=0
    def handle_starttag(self, tag, attrs):
        if tag.lower() in {'script','style','noscript','svg'}: self._skip += 1
    def handle_endtag(self, tag):
        if tag.lower() in {'script','style','noscript','svg'} and self._skip: self._skip -= 1
    def handle_data(self, data):
        if not self._skip and data.strip(): self.parts.append(data.strip())


def analyze_verification_link(data: dict[str, Any]) -> dict[str, Any]:
    """Validate a user-provided Maps URL and optionally compare supplied facts with one public business website.
    Does not access Google accounts, infer hidden verification options, or test bypasses.
    """
    maps_url = str(data.get('maps_url', '')).strip()
    if not maps_url or len(maps_url) > 2048:
        raise ValueError('أدخلي رابط Google Maps صحيحًا (بحد أقصى 2048 حرفًا).')
    parsed = urllib.parse.urlsplit(maps_url)
    if parsed.scheme not in {'https', 'http'} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('رابط Google Maps غير صالح.')
    host = parsed.hostname.lower().rstrip('.')
    valid_maps_host = host in {'maps.app.goo.gl', 'goo.gl', 'maps.google.com', 'google.com', 'www.google.com'}
    valid_maps_path = host in {'maps.app.goo.gl', 'goo.gl', 'maps.google.com'} or parsed.path.startswith('/maps')
    if not (valid_maps_host and valid_maps_path):
        raise ValueError('الرابط لا يبدو رابط Google Maps معروفًا. استخدمي رابط مشاركة الملف من خرائط Google.')

    name = str(data.get('business_name', '')).strip()[:160]
    neighborhood = str(data.get('neighborhood', '')).strip()[:120]
    phone = re.sub(r'\D', '', str(data.get('phone', '')))[:24]
    website_url = str(data.get('website_url', '')).strip()
    findings = []
    findings.append({
        'severity':'info', 'status':'not_assessed', 'title':'رابط الخرائط تم التعرّف عليه',
        'evidence':'تم التحقق من شكل الرابط فقط؛ لم يتم تسجيل الدخول إلى Google أو قراءة لوحة إدارة الملف.',
        'recommendation':'قارني حالة الملف وخيارات التحقق من داخل حساب المالك نفسه. رابط الخرائط العام لا يكشف طريقة التحقق المعروضة.'
    })
    findings.append({
        'severity':'info', 'status':'not_testable_from_public_link', 'title':'طرق التحقق المخفية غير قابلة للاستنتاج من الرابط',
        'evidence':'الرابط العام وحده لا يبيّن هل Google ستعرض SMS أو مكالمة أو فيديو أو تحققًا تلقائيًا.',
        'recommendation':'سجّلي الخيارات الظاهرة فعلًا في شاشة Get verified. لا يمكن إثبات ثغرة تحقق أو إجبار ظهور الهاتف من رابط Maps وحده.'
    })
    site_result = None
    if website_url:
        if not data.get('authorized_website'):
            raise ValueError('أكّدي أن الموقع الإلكتروني عام وأن لديك إذنًا لفحصه قراءةً فقط.')
        normalized, site_host = validate_public_url(website_url)
        try:
            response = fetch_passive(normalized)
        except RuntimeError as e:
            raise ValueError(str(e)) from e
        content_type = str(response['headers'].get('Content-Type', response['headers'].get('content-type',''))).lower()
        if 'html' not in content_type and response['body'][:100].lower().find(b'<html') < 0:
            raise ValueError('الموقع المُدخل لا يبدو صفحة HTML قابلة للفحص النصي.')
        parser = VisibleTextParser()
        try: parser.feed(response['body'].decode('utf-8', errors='replace'))
        except Exception: pass
        text_content = re.sub(r'\s+', ' ', ' '.join(parser.parts)).casefold()
        checks=[]
        def add_check(label, value, matched, advice):
            if value:
                checks.append({'field':label,'status':'present' if matched else 'not_found','provided_value':value,
                               'recommendation':advice if not matched else 'ظهرت هذه المعلومة في النص العام للصفحة؛ قارنيها يدويًا ببيانات الملف.'})
        add_check('اسم النشاط', name, name.casefold() in text_content if name else False,
                  'إذا كان الاسم الحقيقي غير موجود، أضيفيه إلى صفحة الاتصال أو نبذة النشاط فقط إذا كان صحيحًا ومستخدمًا فعليًا؛ لا تضيفي كلمات أو مواقع غير دقيقة لاستدراج طريقة تحقق.')
        add_check('الحي', neighborhood, neighborhood.casefold() in text_content if neighborhood else False,
                  'عدم ظهور الحي ليس ثغرة. اذكري منطقة الخدمة بدقة إذا كانت ذات صلة وصحيحة، ولا تدّعي وجود مقر فعلي غير موجود.')
        normalized_phone = re.sub(r'\D','',text_content)
        add_check('رقم الهاتف', phone, phone in normalized_phone if phone else False,
                  'إذا كان رقم النشاط الصحيح غير ظاهر، أضيفيه لصفحة الاتصال فقط إن كان رقمًا فعليًا تحت سيطرة النشاط. ظهوره لا يضمن تفعيل SMS أو المكالمة.')
        site_result={'url':normalized,'host':site_host,'http_status':response['status'],'checks':checks,
                     'note':'فحص GET واحد للصفحة العامة فقط؛ قد تكون المعلومات في صفحة أخرى أو تُعرض عبر JavaScript، لذلك عدم العثور عليها ليس دليل مخالفة.'}
        for check in checks:
            if check['status']=='not_found':
                findings.append({'severity':'low','status':'possible_consistency_gap','title':f"لم يُعثر على {check['field']} في الصفحة العامة",
                                 'evidence':'القيمة المقدمة لم تظهر في نص HTML الذي استُرجع من الصفحة المحددة.',
                                 'recommendation':check['recommendation']})
            else:
                findings.append({'severity':'info','status':'observed','title':f"ظهور {check['field']} في الصفحة العامة",
                                 'evidence':'تم العثور على القيمة في النص المسترجع من الصفحة المحددة.',
                                 'recommendation':check['recommendation']})
    else:
        findings.append({'severity':'info','status':'website_not_supplied','title':'لم يُفحص الموقع الإلكتروني',
                         'evidence':'لم يتم إدخال رابط الموقع الرسمي للنشاط.',
                         'recommendation':'لتحليل اتساق المعلومات العامة، أضيفي رابط الموقع الرسمي للنشاط واسم النشاط والحي ورقم الهاتف الصحيح؛ لن يؤدي ذلك إلى اختبار أو تجاوز تحقق Google.'})
    return {'title':'تحليل رابط Google Maps ومؤشرات اتساق المعلومات',
            'classification':'public-consistency-review-not-a-verification-bypass-test',
            'maps_url':maps_url,'website_analysis':site_result,'findings':findings,
            'limits':['هذا ليس فحصًا داخليًا لخوادم Google ولا يثبت وجود ثغرة في التحقق.',
                      'لا توجد قاعدة موثوقة تضمن ظهور SMS أو المكالمة بسبب إضافة سطر للحي أو لأن الرقم قديم.',
                      'التوصيات تخص معلومات صحيحة لنشاط حقيقي؛ لا تستخدم بيانات مضللة أو مستندات مصطنعة.'],
            'sources':[{'title':'Verify your business on Google','url':'https://support.google.com/business/answer/7107242?hl=en'},
                       {'title':'Guidelines for representing your business on Google','url':'https://support.google.com/business/answer/3038177?hl=en'},
                       {'title':'Verify your business with a video recording','url':'https://support.google.com/business/answer/14271705?hl=en'}]}


def render_home() -> str:
    with open(os.path.join(BASE_DIR, 'templates', 'index.html'), encoding='utf-8') as f:
        page = f.read()
    page = page.replace("{{ url_for('static', filename='style.css') }}", '/static/style.css')
    page = page.replace("{{ url_for('static', filename='app.js') }}", '/static/app.js')
    topic_options = ''.join(f'<option value="{html.escape(key)}">{html.escape(value["title"])}</option>' for key, value in RESEARCH_TOPICS.items())
    page = page.replace('{% for key, topic in topics.items() %}<option value="{{ key }}">{{ topic.title }}</option>{% endfor %}', topic_options)
    source_links = ''.join(f'<a href="{html.escape(source["url"], quote=True)}" target="_blank" rel="noopener noreferrer"><span>{html.escape(source["title"])}</span><b>↗</b></a>' for source in OFFICIAL_SOURCES)
    page = page.replace('{% for source in sources %}<a href="{{ source.url }}" target="_blank" rel="noopener noreferrer"><span>{{ source.title }}</span><b>↗</b></a>{% endfor %}', source_links)
    return page


def advise_google_verification(data: dict[str, Any]) -> dict[str, Any]:
    """Rule-based guidance using official GBP verification documentation; no Google account access."""
    allowed = {
        'method': {'unknown', 'phone', 'sms', 'email', 'video', 'postcard', 'auto', 'none'},
        'status': {'not-started', 'pending', 'failed', 'suspended', 'verified', 'review-issues'},
        'business_type': {'storefront', 'service-area', 'hybrid'},
        'phone_access': {'yes', 'no', 'unsure'},
        'website_match': {'yes', 'no', 'none', 'unsure'},
        'video_issue': {'none', 'location', 'business-proof', 'management-proof', 'name-mismatch', 'other'},
    }
    normalized = {}
    defaults = {'method':'unknown','status':'not-started','business_type':'service-area','phone_access':'unsure','website_match':'unsure','video_issue':'none'}
    for key, options in allowed.items():
        value = str(data.get(key, defaults[key])).strip().lower()
        if value not in options:
            raise ValueError(f'Invalid value for {key}.')
        normalized[key] = value

    steps = []
    flags = []
    method = normalized['method']; status = normalized['status']
    if status == 'verified':
        steps.append({'priority':'info','title':'التحقق مكتمل','action':'لا تغيّري بيانات النشاط لمجرد تجربة طريقة أخرى. احتفظي ببيانات صحيحة ومتسقة، وأجري تعديلات حقيقية فقط.','basis':'إرشاد عام'})
    if method in {'phone','sms'}:
        if normalized['phone_access'] == 'yes':
            steps.append({'priority':'recommended','title':'استخدمي خيار الهاتف الظاهر','action':'اختاري Phone أو SMS من شاشة التحقق نفسها، وتأكدي أنك تستطيعين الرد على مكالمة النشاط أو استقبال الرسالة.','basis':'رسمي'})
        elif normalized['phone_access'] == 'no':
            steps.append({'priority':'recommended','title':'حلّي مشكلة الوصول للرقم أولًا','action':'لا تطلبي رمزًا لرقم لا يمكنك الوصول إليه. استخدمي وسيلة أخرى فقط إذا كانت معروضة في الحساب، وإلا تواصلي مع دعم الملف التجاري.','basis':'رسمي'})
        else:
            steps.append({'priority':'recommended','title':'تحققي من إمكانية استقبال الرمز','action':'اختبري أن الرقم الصحيح تحت سيطرتك ويستقبل المكالمات أو الرسائل. لا توجد قاعدة رسمية منشورة تقول إن قِدم الرقم وحده يفعّل التحقق.','basis':'رسمي + توضيح حدود'})
    elif method == 'video':
        issue_map = {
            'location': 'أعيدي التسجيل بلقطة متصلة تُظهر لافتات الشارع أو معالم قريبة تثبت الموقع الصحيح.',
            'business-proof': 'أظهري أدلة حقيقية على النشاط مثل اللافتة الدائمة للواجهة أو أدوات العمل المناسبة لنوع النشاط.',
            'management-proof': 'أظهري دليلًا حقيقيًا أنك تديرين النشاط، مثل الوصول إلى معدات أو مساحة عمل خاصة بالنشاط أو مستند مناسب.',
            'name-mismatch': 'اجعلي الاسم الظاهر في الفيديو مطابقًا للاسم الحقيقي على الملف واللافتة، وصححي التناقضات الفعلية قبل إعادة التسجيل.',
            'other': 'افتحي Review issues واقرئي سبب الرفض المحدد، ثم أعيدي التسجيل مع معالجة العناصر الناقصة فقط.',
        }
        if normalized['video_issue'] != 'none':
            steps.append({'priority':'recommended','title':'علاج سبب رفض الفيديو','action':issue_map[normalized['video_issue']], 'basis':'رسمي'})
        else:
            steps.append({'priority':'recommended','title':'جهّزي فيديو إثبات صحيح','action':'سجّلي فيديو فريدًا ومتصلًا من الجهاز المحمول، وأظهري أدلة الموقع والنشاط والإدارة المناسبة لنوع النشاط. اتبعي قائمة المتطلبات التي تظهر في حسابك.','basis':'رسمي'})
    elif method == 'postcard':
        steps.append({'priority':'important','title':'راجعي العنوان قبل طلب الرمز','action':'تأكدي من صحة العنوان البريدي. بعد طلب البطاقة، لا تغيّري الاسم أو العنوان أو الفئة أثناء انتظار الرمز ولا تطلبي رمزًا جديدًا إلا إذا اتبعتِ تعليمات Google.','basis':'رسمي'})
    elif method == 'email':
        steps.append({'priority':'recommended','title':'استخدمي البريد المعروض','action':'تأكدي من الوصول إلى صندوق البريد الذي تعرضه شاشة التحقق، ثم اتبعي التعليمات المرسلة إليه.','basis':'رسمي'})
    elif method == 'auto':
        steps.append({'priority':'info','title':'اتّبعي التحقق التلقائي إن ظهر رسميًا','action':'إذا كان الخيار ظاهرًا داخل حساب النشاط، اتبعي التعليمات المعروضة. لا يمكن تشغيله يدويًا أو ضمان توفره بتغيير بلد الحساب أو بيانات الموقع.','basis':'رسمي'})
    elif method == 'none':
        steps.append({'priority':'important','title':'لا توجد وسيلة ظاهرة حاليًا','action':'راجعي حالة الملف وأي طلبات معلّقة، ثم تواصلي مع دعم Google Business Profile إذا لم يعرض الحساب وسيلة تحقق. لا تنشئي تعديلات وهمية لاستدراج خيار مختلف.','basis':'رسمي'})
    else:
        steps.append({'priority':'recommended','title':'ابدئي من شاشة التحقق نفسها','action':'افتحي Get verified وسجّلي كل الخيارات التي يعرضها Google لهذا الملف. اختيار الوسائل يتم تلقائيًا بحسب عوامل منها نوع النشاط والمنطقة والمعلومات العامة وساعات العمل.','basis':'رسمي'})

    if status == 'pending':
        steps.append({'priority':'info','title':'الطلب قيد المراجعة','action':'تجنّبي التعديلات غير الضرورية وانتظري نتيجة المراجعة؛ إذا تجاوزت المدة الموضحة في الحساب، تواصلي مع الدعم.','basis':'إرشاد عام'})
    elif status == 'failed' or status == 'review-issues':
        steps.append({'priority':'recommended','title':'راجعي سبب الفشل قبل المحاولة التالية','action':'استخدمي رسالة الخطأ أو Review issues لتحديد النقص بدقة، ثم أعيدي المحاولة بعد تصحيحه. لا تكرري محاولات عشوائية.','basis':'رسمي'})
    elif status == 'suspended':
        steps.append({'priority':'important','title':'التعليق ليس مشكلة اختيار وسيلة تحقق فقط','action':'راجعي إرشادات الأهلية والسياسات، وصححي المخالفات الحقيقية، ثم استخدمي مسار الاستئناف الرسمي. لا تنشئي ملفات بديلة لتجاوز التعليق.','basis':'رسمي'})

    if normalized['website_match'] == 'no':
        steps.append({'priority':'recommended','title':'وحّدي المعلومات غير المتطابقة','action':'صححي فقط الاختلافات الحقيقية بين الموقع والملف، مثل الاسم أو الهاتف أو العنوان أو الخدمات. إضافة سطر باسم حي لا تضمن ظهور SMS أو تغيير طريقة التحقق.','basis':'توصية اتساق'})
    elif normalized['website_match'] == 'none':
        steps.append({'priority':'info','title':'لا يوجد موقع للنشاط','action':'الموقع الإلكتروني ليس شرطًا عامًا لكل نشاط. استخدمي وسيلة التحقق التي يعرضها الملف وقدّمي أدلة النشاط الفعلية.','basis':'إرشاد عام'})

    flags.append('الموقع لا يتصل بحساب Google ولا يستطيع رؤية خيارات التحقق الحقيقية؛ النصائح مبنية فقط على إجاباتك وعلى الإرشادات الرسمية.')
    flags.append('لا يوجد دليل رسمي أن إضافة سطر باسم الحي، أو أن الرقم القديم، يفرض ظهور التحقق بالهاتف. لا يمكن ضمان وسيلة تحقق بعينها.')
    return {'title':'مساعد تشخيص التحقق في Google Business Profile','classification':'rule-based-guidance-not-a-vulnerability-finding','inputs':normalized,'steps':steps,'limitations':flags,'sources':[{'title':'Verify your business on Google','url':'https://support.google.com/business/answer/7107242?hl=en'},{'title':'Verify your business with a video recording','url':'https://support.google.com/business/answer/14271705?hl=en'}]}


def build_verification_readiness_plan(data: dict[str, Any]) -> dict[str, Any]:
    """Recommend legitimate evidence preparation based only on methods the user says Google displayed."""
    allowed_methods = {'phone_sms', 'email', 'recorded_video', 'live_video', 'postcard', 'automatic'}
    allowed_types = {'storefront', 'service-area', 'hybrid'}
    business_type = str(data.get('business_type', 'service-area')).strip().lower()
    if business_type not in allowed_types:
        raise ValueError('اختاري نوع نشاط صحيحًا.')
    raw_methods = data.get('available_methods', [])
    if not isinstance(raw_methods, list) or any(str(m) not in allowed_methods for m in raw_methods):
        raise ValueError('اختيارات طرق التحقق غير صحيحة.')
    methods = list(dict.fromkeys(str(m) for m in raw_methods))
    evidence_keys = ('signage', 'tools', 'management_proof', 'address_match', 'phone_access', 'email_access', 'mail_access', 'website_consistent')
    evidence = {k: bool(data.get(k, False)) for k in evidence_keys}
    status = str(data.get('status', 'not-started')).strip().lower()
    if status not in {'not-started', 'pending', 'failed', 'review-issues', 'suspended', 'verified'}:
        raise ValueError('حالة الملف غير صحيحة.')
    recs = []
    method_labels = {'phone_sms':'الهاتف أو SMS', 'email':'البريد الإلكتروني', 'recorded_video':'فيديو مسجّل', 'live_video':'مكالمة فيديو مباشرة', 'postcard':'بطاقة بريدية', 'automatic':'التحقق التلقائي'}
    if status == 'verified':
        recs.append({'priority':'info','title':'الملف تم التحقق منه بالفعل','action':'احتفظي بأدلة النشاط الصحيحة ولا تغيّري بياناته لمجرد تجربة وسيلة أخرى.','method':'general'})
    elif status == 'suspended':
        recs.append({'priority':'important','title':'ابدئي بمراجعة التعليق','action':'راجعي سبب التعليق والسياسات ثم اتبعي مسار الاستئناف الرسمي. تغيير طريقة التحقق وحده لا يعالج التعليق.','method':'general'})
    elif status in {'failed', 'review-issues'}:
        recs.append({'priority':'important','title':'عالجي سبب الرفض المحدد أولًا','action':'افتحي Review issues واقرئي الملاحظة الظاهرة، ثم جهّزي الدليل الذي يعالجها مباشرة قبل إعادة المحاولة.','method':'general'})

    if not methods:
        recs.append({'priority':'important','title':'لا توجد طريقة مؤكدة من المدخلات','action':'افتحي Get verified من حساب المالك وسجّلي الخيارات الظاهرة حرفيًا. إذا لم يظهر أي خيار، تواصلي مع دعم Google Business Profile. لا يمكن استنتاج الخيارات من رابط Maps أو فرضها بتعديل الموقع.','method':'none'})
    else:
        if 'phone_sms' in methods:
            recs.append({'priority':'recommended' if evidence['phone_access'] else 'check','title':'الهاتف أو SMS متاح ضمن الخيارات التي سجلتيها','action':'اختاريه فقط إذا ظهر فعلًا في شاشة Google وكان رقم النشاط الصحيح تحت سيطرتك ويستقبل مكالمة أو رسالة. إذا لم تستطيعي الوصول للرقم، لا تطلبي الرمز؛ اختاري خيارًا آخر ظاهرًا إن وُجد.','method':'phone_sms'})
        if 'email' in methods:
            recs.append({'priority':'recommended' if evidence['email_access'] else 'check','title':'البريد الإلكتروني متاح ضمن الخيارات التي سجلتيها','action':'تأكدي أنك تستطيعين فتح البريد المحدد في شاشة التحقق، ثم اتبعي تعليمات Google. لا تفترضي أن أي بريد جديد سيصبح مؤهلًا.','method':'email'})
        if 'recorded_video' in methods:
            video_steps = []
            if business_type in {'storefront', 'hybrid'}:
                video_steps.append('أظهري الموقع الفعلي واللافتة الدائمة إن كانت موجودة، مع معالم محيطة تساعد على تحديد المكان.')
            if business_type in {'service-area', 'hybrid'}:
                video_steps.append('أظهري أدوات العمل أو المعدات أو مواد العمل الفعلية المناسبة للخدمة؛ لا تدّعي وجود محل يستقبل العملاء إذا كان النشاط متنقلًا فقط.')
            if not evidence['tools']:
                video_steps.append('جهّزي أدوات أو معدات حقيقية مرتبطة بالنشاط قبل التسجيل.')
            if not evidence['management_proof']:
                video_steps.append('جهّزي دليلًا حقيقيًا على إدارتك للنشاط، مثل الوصول إلى معدات أو مساحة عمل أو مستند غير حساس.')
            video_steps.append('اتبعي تعليمات الشاشة: الفيديو يجب أن يكون مباشرًا وفريدًا ومتصلًا، ولا تضيفي لقطات أو معلومات مصطنعة.')
            recs.append({'priority':'recommended','title':'الفيديو المسجّل متاح ضمن الخيارات التي سجلتيها','action':' '.join(video_steps),'method':'recorded_video'})
        if 'live_video' in methods:
            recs.append({'priority':'recommended','title':'مكالمة فيديو مباشرة متاحة ضمن الخيارات التي سجلتيها','action':'جهّزي هاتفًا بكاميرا واتصالًا مناسبًا، وكوني في موقع النشاط أو مكان العمل الحقيقي خلال ساعات العمل المعروضة. استعدّي لإظهار الموقع والأدوات ودليل الإدارة الحقيقي للممثل.','method':'live_video'})
        if 'postcard' in methods:
            recs.append({'priority':'check','title':'البطاقة البريدية متاحة ضمن الخيارات التي سجلتيها','action':'استخدمي العنوان البريدي الحقيقي الذي يستطيع النشاط استلام البريد عليه. بعد طلب الرمز، لا تغيّري الاسم أو العنوان أو الفئة ولا تطلبي رمزًا جديدًا أثناء الانتظار إلا وفق تعليمات Google.','method':'postcard'})
        if 'automatic' in methods:
            recs.append({'priority':'info','title':'التحقق التلقائي متاح ضمن الخيارات التي سجلتيها','action':'اتبعي الخطوات الظاهرة في الحساب. لا توجد خطوة يدوية مضمونة لتشغيله إذا لم يعرضه Google.','method':'automatic'})

    if not evidence['address_match']:
        recs.append({'priority':'check','title':'راجعي بيانات الموقع أو منطقة الخدمة','action':'تأكدي من صحة العنوان أو منطقة الخدمة وفق طبيعة النشاط. لا تضيفي عنوانًا لمقر غير موجود ولا تغيّري الموقع لاستدراج طريقة تحقق مختلفة.','method':'evidence'})
    if not evidence['website_consistent']:
        recs.append({'priority':'check','title':'راجعي اتساق المعلومات العامة','action':'قارني الاسم والهاتف والخدمات والموقع بين الملف والموقع الرسمي إن وُجد. صححي الاختلافات الحقيقية فقط؛ وجود الحي في نص الموقع لا يضمن إتاحة الهاتف.','method':'evidence'})

    return {
        'title':'خطة تجهيز إثبات النشاط التجاري',
        'classification':'official-method-readiness-guidance-not-a-prediction-or-bypass',
        'generated_at': utc_now(),
        'business_type': business_type,
        'profile_status': status,
        'methods_user_observed': methods,
        'recommendations': recs,
        'decision_rule':'التوصيات الخاصة بوسائل التحقق تُبنى فقط على الخيارات التي أدخلها الباحث باعتبارها ظاهرة في حساب Google. الأداة لا تستنتج خيارًا مخفيًا ولا تغيّر أهلية الملف.',
        'limitations':['هذه الخطة لا تتصل بحساب Google ولا تتحقق من صحة لقطات الشاشة أو الخيارات المدخلة.', 'Google يحدد وسائل التحقق تلقائيًا؛ لا يمكن ضمان ظهور الهاتف أو تبديل الفيديو به عبر تعديل سطر أو بيانات الموقع.', 'لا تسجلي رموز التحقق أو بيانات الهوية أو المستندات الحساسة في هذا التقرير.'],
        'sources':[{'title':'Verify your business on Google','url':'https://support.google.com/business/answer/7107242?hl=en'}, {'title':'Verify your business with a video recording','url':'https://support.google.com/business/answer/14271705?hl=en'}]
    }


class SecurityLabHandler(BaseHTTPRequestHandler):
    server_version = 'SecurityResearchLab/1.1'

    def _send(self, status: int, body: bytes, content_type: str = 'application/json; charset=utf-8', extra_headers: dict[str, str] | None = None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header('Cache-Control', 'no-store')
        if extra_headers:
            for key, value in extra_headers.items(): self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: dict[str, Any], headers: dict[str, str] | None = None):
        self._send(status, json.dumps(data, ensure_ascii=False).encode('utf-8'), 'application/json; charset=utf-8', headers)

    def _read_json(self) -> dict[str, Any]:
        try: length = int(self.headers.get('Content-Length', '0'))
        except ValueError: raise ValueError('Invalid Content-Length.')
        if length < 0 or length > 32 * 1024: raise ValueError('Request body is too large.')
        raw = self.rfile.read(length)
        if not raw: return {}
        try: data = json.loads(raw.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError): raise ValueError('Request body must be valid JSON.')
        if not isinstance(data, dict): raise ValueError('JSON body must be an object.')
        return data

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == '/':
            self._send(200, render_home().encode('utf-8'), 'text/html; charset=utf-8')
            return
        if path.startswith('/static/') and path.count('/') == 2:
            name = path.rsplit('/', 1)[-1]
            if name not in {'style.css', 'app.js'}:
                self._json(404, {'error': 'Not found.'}); return
            full = os.path.join(BASE_DIR, 'static', name)
            ctype = 'text/css; charset=utf-8' if name.endswith('.css') else 'text/javascript; charset=utf-8'
            with open(full, 'rb') as f: body = f.read()
            self._send(200, body, ctype); return
        if path == '/api/health':
            self._json(200, {'status': 'ok', 'scanner_mode': 'passive-public-checks',
                'python_version': __import__('sys').version.split()[0],
                'external_ai_configured': bool(os.environ.get('OPENAI_API_KEY')),
                'notice': 'Health check does not contact external targets.'})
            return
        if path == '/api/lab':
            self._json(200, {'title': 'Local educational lab', 'status': 'executable-local-demonstrations', 'exercises': [
                {'name': 'XSS output encoding', 'scenario': 'A local demo renders a user-supplied string as text.', 'test': 'Enter harmless text such as <hello> and confirm it is rendered as text, not interpreted markup.', 'fix': 'Use context-aware output encoding and a restrictive Content Security Policy.'},
                {'name': 'SQL injection prevention', 'scenario': 'A toy login query is contrasted with a parameterized query.', 'test': 'Inspect the unit test to verify user input is passed as a parameter rather than concatenated into SQL.', 'fix': 'Use parameterized queries and least-privilege database accounts.'},
                {'name': 'Broken access control', 'scenario': 'Two synthetic users and synthetic resources are used to demonstrate server-side ownership checks.', 'test': 'Run the included tests and verify a user cannot access another synthetic user’s resource.', 'fix': 'Check authorization on the server for every resource and action.'}], 'notice': 'These are local learning scenarios, not tests against Google or any external target.'})
            return
        self._json(404, {'error': 'Not found.'})

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        try: data = self._read_json()
        except ValueError as e: self._json(400, {'error': str(e)}); return
        if path == '/api/crawl':
            if not data.get('authorized'):
                self._json(400, {'error': 'Confirm that you own the target or have permission to crawl it.'}); return
            try:
                self._json(200, crawl_public_site(str(data.get('url', '')), max_pages=8, max_depth=1))
            except ValueError as e: self._json(400, {'error': str(e)})
            except RuntimeError as e: self._json(502, {'error': str(e)})
            return
        if path == '/api/verification/readiness-plan':
            try: self._json(200, build_verification_readiness_plan(data))
            except ValueError as e: self._json(400, {'error': str(e)})
            return
        if path == '/api/verification/advice':
            try: self._json(200, advise_google_verification(data))
            except ValueError as e: self._json(400, {'error': str(e)})
            return
        if path == '/api/verification/link-analysis':
            try: self._json(200, analyze_verification_link(data))
            except ValueError as e: self._json(400, {'error': str(e)})
            return
        if path == '/api/lab/check':
            try:
                exercise = str(data.get('exercise', ''))
                value = str(data.get('value', ''))
                user_id = str(data.get('user_id', 'alice'))
                owner = str(data.get('resource_owner', 'alice'))
                self._json(200, secure_lab_check(exercise, value, user_id, owner))
            except ValueError as e: self._json(400, {'error': str(e)})
            return
        if path == '/api/scan':
            if not data.get('authorized'):
                self._json(400, {'error': 'Confirm that you own the target or have permission to run passive checks.'}); return
            try: self._json(200, run_scan(str(data.get('url', ''))))
            except ValueError as e: self._json(400, {'error': str(e)})
            except RuntimeError as e: self._json(502, {'error': str(e)})
            return
        if path == '/api/research':
            try: self._json(200, build_research_plan(str(data.get('topic', '')), str(data.get('target', 'Google Maps'))))
            except ValueError as e: self._json(400, {'error': str(e)})
            return
        if path == '/api/export':
            result, fmt = data.get('result'), data.get('format', 'json')
            if not isinstance(result, dict) or fmt not in ('json', 'html'):
                self._json(400, {'error': 'Provide a result object and format json or html.'}); return
            if fmt == 'json':
                body = json.dumps(result, indent=2, ensure_ascii=False).encode('utf-8')
                self._send(200, body, 'application/json; charset=utf-8', {'Content-Disposition': 'attachment; filename=security-scan-report.json'}); return
            safe_target = html.escape(str(result.get('target', 'Unknown target')))
            rows = []
            for finding in result.get('findings', []):
                rows.append('<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(html.escape(str(finding.get('title', ''))), html.escape(str(finding.get('severity', ''))), html.escape(str(finding.get('status', ''))), html.escape(str(finding.get('evidence', ''))), html.escape(str(finding.get('recommendation', '')))))
            report = ('<!doctype html><html lang="en"><meta charset="utf-8"><title>Security Scan Report</title>'
                      '<style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#172033}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccd2df;padding:.6rem;text-align:left;vertical-align:top}th{background:#eef2f8}</style>'
                      '<h1>Security Scan Report</h1><p><b>Target:</b> ' + safe_target + '</p><p><b>Timestamp:</b> ' + html.escape(str(result.get('timestamp', ''))) + '</p>'
                      '<p><b>Mode:</b> Passive public checks. Findings require context and are not a guarantee of vulnerability.</p>'
                      '<table><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table>'
                      '<h2>Limitations</h2><ul>' + ''.join('<li>' + html.escape(str(x)) + '</li>' for x in result.get('limitations', [])) + '</ul></html>')
            self._send(200, report.encode('utf-8'), 'text/html; charset=utf-8', {'Content-Disposition': 'attachment; filename=security-scan-report.html'}); return
        self._json(404, {'error': 'Not found.'})

    def log_message(self, format, *args):
        print('%s - %s' % (self.address_string(), format % args))


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '5000'))
    server = ThreadingHTTPServer(('127.0.0.1', port), SecurityLabHandler)
    print(f'Security Research Lab running at http://127.0.0.1:{port}')
    print('Bound to localhost only. Press Ctrl+C to stop.')
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
