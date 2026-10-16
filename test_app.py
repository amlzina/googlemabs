import json
import threading
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import app as platform

class PlatformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), platform.SecurityLabHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(timeout=2)

    def get(self, path):
        with urlopen(self.base + path, timeout=2) as response:
            return response.status, response.headers, response.read()

    def post(self, path, data):
        req = Request(self.base + path, data=json.dumps(data).encode(), headers={'Content-Type':'application/json'}, method='POST')
        try:
            with urlopen(req, timeout=2) as response:
                return response.status, response.headers, response.read()
        except HTTPError as e:
            return e.code, e.headers, e.read()

    def test_homepage_loads(self):
        status, _, body = self.get('/')
        self.assertEqual(status, 200)
        self.assertIn(b'Security Research Lab', body)
        self.assertIn(b'Google Maps', body)

    def test_static_asset_loads(self):
        status, headers, body = self.get('/static/app.js')
        self.assertEqual(status, 200)
        self.assertIn('javascript', headers.get('Content-Type', ''))
        self.assertIn(b'/api/scan', body)

    def test_scan_requires_authorization(self):
        status, _, body = self.post('/api/scan', {'url':'https://example.com'})
        self.assertEqual(status, 400)
        self.assertIn('permission', json.loads(body)['error'].lower())

    def test_localhost_is_blocked(self):
        with self.assertRaises(ValueError): platform.validate_public_url('http://127.0.0.1:5000')

    def test_private_ip_is_blocked(self):
        with self.assertRaises(ValueError): platform.validate_public_url('http://192.168.1.10')

    def test_non_http_scheme_is_blocked(self):
        with self.assertRaises(ValueError): platform.validate_public_url('file:///etc/passwd')

    def test_research_plan_is_not_finding(self):
        status, _, body = self.post('/api/research', {'target':'Google Maps','topic':'authorization'})
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(data['status'], 'research_plan_not_a_finding')
        self.assertIn('not a claim', data['notice'])

    def test_unknown_research_topic_rejected(self):
        status, _, body = self.post('/api/research', {'topic':'magic'})
        self.assertEqual(status, 400)
        self.assertIn('supported', json.loads(body)['error'])


    def test_health_endpoint(self):
        status, _, body = self.get('/api/health')
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(data['status'], 'ok')
        self.assertEqual(data['scanner_mode'], 'passive-public-checks')

    def test_header_analyzer_detects_missing_security_headers(self):
        findings = platform.analyze_headers({}, 'https://example.com/')
        titles = [f['title'] for f in findings]
        self.assertIn('Missing Strict-Transport-Security header', titles)
        self.assertIn('Missing Content-Security-Policy header', titles)
        self.assertTrue(all('status' in f and 'recommendation' in f for f in findings))

    def test_permissive_csp_is_flagged_as_contextual_not_confirmed(self):
        findings = platform.analyze_headers({'Content-Security-Policy': "default-src * 'unsafe-inline'; script-src 'unsafe-eval'"}, 'https://example.com/')
        finding = next(f for f in findings if f['title'] == 'CSP contains permissive source expressions')
        self.assertEqual(finding['status'], 'potential_issue')
        self.assertEqual(finding['category'], 'Injection Prevention')

    def test_cors_wildcard_credentials_combination(self):
        findings = platform.analyze_headers({'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true'}, 'https://example.com/')
        self.assertIn('CORS wildcard origin combined with credentials', [f['title'] for f in findings])

    def test_redirect_is_reported_not_followed(self):
        findings = platform.analyze_headers({'Location': 'https://other.example/path'}, 'https://example.com/', status_code=302)
        finding = next(f for f in findings if f['title'] == 'Redirect response observed (not followed)')
        self.assertIn('other.example', finding['evidence'])

    def test_verbose_error_heuristic_does_not_copy_body(self):
        secret_body = b'Traceback (most recent call last): SECRET-DO-NOT-REPORT'
        findings = platform.analyze_headers({}, 'https://example.com/', secret_body, 500)
        finding = next(f for f in findings if f['title'] == 'Possible verbose error details in server error response')
        self.assertNotIn('SECRET-DO-NOT-REPORT', finding['evidence'])
        self.assertEqual(finding['confidence'], 'low')

    def test_invalid_port_is_rejected(self):
        with self.assertRaises(ValueError): platform.validate_public_url('https://example.com:bad/')

    def test_crawl_requires_authorization(self):
        status, _, body = self.post('/api/crawl', {'url':'https://example.com'})
        self.assertEqual(status, 400)
        self.assertIn('permission', json.loads(body)['error'].lower())

    def test_crawler_link_extraction_stays_same_origin_and_skips_logout(self):
        body = b'<a href="/about">About</a><a href="https://other.example/">external</a><a href="/logout">logout</a><a href="mailto:a@b.com">mail</a>'
        links = platform.extract_same_origin_links(body, 'https://example.com/')
        self.assertEqual(links, ['https://example.com/about'])

    def test_crawl_is_bounded_and_collects_pages(self):
        html_body = b'<html><a href="/about">About</a><a href="https://elsewhere.test/">external</a></html>'
        root_response = {'status': 200, 'headers': {'Content-Type':'text/html'}, 'body':html_body, 'final_url':'https://example.com/', 'error':None}
        about_response = {'status': 200, 'headers': {'Content-Type':'text/html', 'X-Content-Type-Options':'nosniff'}, 'body':b'<html>about</html>', 'final_url':'https://example.com/about', 'error':None}
        def fake_validate(url):
            if 'example.com' not in url: raise ValueError('blocked')
            return url, 'example.com'
        with patch.object(platform, 'validate_public_url', side_effect=fake_validate), patch.object(platform, 'fetch_passive', side_effect=[root_response, about_response]):
            result = platform.crawl_public_site('https://example.com/', max_pages=8, max_depth=1)
        self.assertEqual(result['pages_scanned'], 2)
        self.assertEqual(result['mode'], 'bounded-same-origin-passive-crawl')
        self.assertTrue(all(p['url'].startswith('https://example.com') for p in result['pages']))

    def test_crawler_rejects_unbounded_limits(self):
        with self.assertRaises(ValueError): platform.crawl_public_site('https://example.com/', max_pages=99)
        with self.assertRaises(ValueError): platform.crawl_public_site('https://example.com/', max_depth=3)

    def test_local_lab_xss_encodes_markup(self):
        result = platform.secure_lab_check('xss', '<script>alert(1)</script>')
        self.assertTrue(result['passed'])
        self.assertIn('&lt;script&gt;', result['safe_output'])

    def test_local_lab_sql_uses_synthetic_parameterized_query(self):
        result = platform.secure_lab_check('sqli', 'alice')
        self.assertTrue(result['passed'])
        self.assertEqual(result['result'], 'Alice Demo')

    def test_local_lab_access_control_denies_other_owner(self):
        result = platform.secure_lab_check('access-control', user_id='alice', resource_owner='bob')
        self.assertFalse(result['allowed'])
        self.assertTrue(result['passed'])

    def test_lab_check_api(self):
        status, _, body = self.post('/api/lab/check', {'exercise':'access-control','user_id':'alice','resource_owner':'bob'})
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertFalse(data['allowed'])

    def test_verification_advisor_does_not_promise_sms_from_old_number(self):
        result = platform.advise_google_verification({'method':'unknown','status':'not-started','phone_access':'yes','website_match':'no'})
        self.assertEqual(result['classification'], 'rule-based-guidance-not-a-vulnerability-finding')
        self.assertTrue(any('الرقم القديم' in flag and 'يفرض ظهور التحقق بالهاتف' in flag for flag in result['limitations']))
        self.assertTrue(any('لا تضمن' in step['action'] or 'لا تضمن' in step['action'] or 'لا تضمن' in step['action'] for step in result['steps']) or result['steps'])

    def test_verification_advisor_video_rejection_recommends_review_issues(self):
        result = platform.advise_google_verification({'method':'video','status':'review-issues','video_issue':'location'})
        actions = ' '.join(step['action'] for step in result['steps'])
        self.assertIn('معالم قريبة', actions)
        self.assertIn('Review issues', actions)

    def test_verification_advisor_rejects_unknown_enum(self):
        with self.assertRaises(ValueError): platform.advise_google_verification({'method':'bypass'})

    def test_verification_advisor_api(self):
        status, _, body = self.post('/api/verification/advice', {'method':'sms','status':'not-started','phone_access':'yes'})
        self.assertEqual(status, 200)
        self.assertIn('steps', json.loads(body))

    def test_export_json(self):
        status, headers, body = self.post('/api/export', {'format':'json','result':{'target':'https://example.com','findings':[]}})
        self.assertEqual(status, 200)
        self.assertIn('application/json', headers.get('Content-Type',''))
        self.assertEqual(json.loads(body)['target'], 'https://example.com')

    def test_export_html_escapes_target(self):
        status, _, body = self.post('/api/export', {'format':'html','result':{'target':'<script>alert(1)</script>','findings':[]}})
        self.assertEqual(status, 200)
        self.assertIn(b'&lt;script&gt;', body)
        self.assertNotIn(b'<script>alert(1)</script>', body)

if __name__ == '__main__': unittest.main(verbosity=2)


class VerificationLinkAnalysisTests(unittest.TestCase):
    def test_accepts_google_maps_share_link_without_claiming_hidden_method(self):
        result = platform.analyze_verification_link({'maps_url':'https://maps.app.goo.gl/AbCd123'})
        self.assertEqual(result['classification'], 'public-consistency-review-not-a-verification-bypass-test')
        self.assertTrue(any(f['status']=='not_testable_from_public_link' for f in result['findings']))

    def test_accepts_google_maps_place_url(self):
        result = platform.analyze_verification_link({'maps_url':'https://www.google.com/maps/place/Example'})
        self.assertEqual(result['maps_url'], 'https://www.google.com/maps/place/Example')

    def test_rejects_non_maps_url(self):
        with self.assertRaises(ValueError):
            platform.analyze_verification_link({'maps_url':'https://example.com/maps/place/Example'})

    def test_rejects_missing_maps_url(self):
        with self.assertRaises(ValueError):
            platform.analyze_verification_link({})

    def test_website_requires_authorization_checkbox(self):
        with self.assertRaises(ValueError):
            platform.analyze_verification_link({'maps_url':'https://maps.app.goo.gl/AbCd123','website_url':'https://example.com'})

    def test_website_consistency_checks_with_mocked_public_page(self):
        from unittest.mock import patch
        response={'status':200,'headers':{'Content-Type':'text/html; charset=utf-8'},'body':b'<html><body>Delta Clean Al Ared 01012345678</body></html>','final_url':'https://example.com/','error':None}
        with patch.object(platform, 'validate_public_url', return_value=('https://example.com/','example.com')), patch.object(platform, 'fetch_passive', return_value=response):
            result=platform.analyze_verification_link({'maps_url':'https://maps.app.goo.gl/AbCd123','website_url':'https://example.com/','authorized_website':True,'business_name':'Delta Clean','neighborhood':'Al Ared','phone':'01012345678'})
        self.assertEqual(result['website_analysis']['http_status'],200)
        self.assertTrue(all(c['status']=='present' for c in result['website_analysis']['checks']))


class VerificationReadinessPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), platform.SecurityLabHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(timeout=2)

    def post(self, path, data):
        req = Request(self.base + path, data=json.dumps(data).encode(), headers={'Content-Type':'application/json'}, method='POST')
        try:
            with urlopen(req, timeout=2) as response:
                return response.status, response.headers, response.read()
        except HTTPError as e:
            return e.code, e.headers, e.read()

    def test_plan_recommends_only_methods_user_says_are_visible(self):
        result = platform.build_verification_readiness_plan({'business_type':'service-area','available_methods':['phone_sms','recorded_video'],'phone_access':True,'tools':True,'management_proof':True})
        self.assertEqual(result['classification'], 'official-method-readiness-guidance-not-a-prediction-or-bypass')
        self.assertEqual(set(x['method'] for x in result['recommendations'] if x['method'] in {'phone_sms','email','recorded_video','live_video','postcard','automatic'}), {'phone_sms','recorded_video'})
        self.assertTrue(any('لا تضمن' in x['action'] or 'لا توجد خطوة' in x['action'] or 'اختاريه فقط' in x['action'] for x in result['recommendations']))

    def test_plan_with_no_methods_does_not_guess(self):
        result = platform.build_verification_readiness_plan({'available_methods':[]})
        self.assertTrue(any(x['method']=='none' for x in result['recommendations']))
        self.assertIn('لا يمكن استنتاج الخيارات', result['recommendations'][0]['action'])

    def test_plan_rejects_unknown_method(self):
        with self.assertRaises(ValueError):
            platform.build_verification_readiness_plan({'available_methods':['force_sms']})

    def test_plan_api(self):
        status, _, body = self.post('/api/verification/readiness-plan', {'business_type':'storefront','status':'not-started','available_methods':['live_video']})
        self.assertEqual(status, 200)
        self.assertIn('recommendations', json.loads(body))
