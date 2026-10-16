# Security Research Lab v2

A small local-first academic project for passive web security observations and safe training demonstrations.

## Features
- Single-response passive scanner for HTTP security headers and TLS certificate validation.
- Bounded same-origin crawler: maximum 8 pages, depth 1, GET-only, no redirects followed, no forms or payloads submitted.
- JSON and HTML report export.
- Research plans with official references; plans are not vulnerability findings.
- Executable local defensive demos for HTML output encoding, parameterized SQL queries against an in-memory database, and synthetic resource ownership checks.
- Localhost-only web server by default.

## Requirements
Python 3.10+ (the application uses only the Python standard library).

## Run
```bash
python app.py
```
Then open http://127.0.0.1:5000. Stop with Ctrl+C.

## Tests
From this folder run:
```bash
python -m unittest discover -s tests -v
```

## Safety and limitations
- Only scan/crawl systems you own or are explicitly authorized to test.
- The scanner makes passive GET requests and does not submit exploit payloads, authenticate, follow redirects, submit forms, or test business logic.
- Crawler scope is limited to the same origin, 8 pages maximum, depth 1. Query strings are removed from discovered links; common state-changing paths are skipped.
- Private, local, and reserved IP targets are rejected by URL validation. Do not expose this service publicly. DNS-based targets can still involve infrastructure-specific risks; use authorized targets and a controlled environment.
- Missing headers or heuristic matches are observations/potential issues, not confirmed exploitable vulnerabilities.
- The local lab uses synthetic data only and does not contact external sites.
- Google Maps research output is planning/reference material; it does not test Google internal systems or claim Google has a vulnerability.

## Suggested demonstration
1. Open the dashboard and run the passive check against a public site you are authorized to assess.
2. Run the bounded crawl and review the page list and per-page observations.
3. Export a report as JSON or HTML.
4. In the local lab, select XSS and enter `<script>alert(1)</script>` to see encoded output; select SQLi and enter `alice`; then select access control and set user `alice`, owner `bob` to see the access decision denied.

## Future work
For a production-grade scanner, add robust DNS pinning, an explicit allowlist, authenticated test-environment support, stronger request budgeting, per-cookie parsing, persistent scan history, and independently reviewed SSRF protections.


## Google Business Profile verification advisor

The app includes a rule-based advisor at **مساعد تشخيص التحقق**. It uses user-entered state (available method, profile status, phone access, website consistency, and video-review issue) to suggest next steps grounded in official Google help pages. It does not connect to a Google account, predict hidden eligibility, force a verification method, or identify a real vulnerability. It explicitly warns that changing website text or using an old phone number does not guarantee SMS/phone verification.

Official references: https://support.google.com/business/answer/7107242?hl=en and https://support.google.com/business/answer/14271705?hl=en


## Google Maps link analyzer (v5)

The new **حلّل رابط ملف النشاط** panel accepts a Google Maps share URL and can optionally make one bounded passive GET request to a public business website you are authorized to inspect. It compares the provided real business name, neighborhood, and phone against the retrieved HTML text and reports whether each value was found.

Important limits: a Maps share URL does not expose private verification eligibility or the available verification method. The analyzer does not log into Google, enumerate hidden methods, test or bypass phone/video verification, or claim a vulnerability from missing public text. A missing string can be caused by JavaScript rendering or another page. Website inspection requires an explicit checkbox and is limited to one public page request; redirects are not followed.

## Evidence notebook (v6)

The dashboard now includes a local **دفتر اختبار الفرضيات** form for documenting authorized before/after observations. It creates a downloadable JSON record with the declared scope, repeat count, evidence notes, interpretation, and limitations. A repeated difference is classified only as a *repeatable association*, never as a confirmed Google vulnerability. The notebook does not contact Google or change any Business Profile settings; researchers must preserve genuine evidence and work within a written authorization scope.


## Verification readiness planner (v7)

The new **مخطط تجهيز إثبات النشاط** takes the verification methods the user actually sees in their Google Business Profile and evidence readiness (real business tools, management proof, correct address/service area, and access to displayed contact channels). It returns a prioritized, downloadable JSON checklist for only those observed methods. It never predicts hidden options or recommends manipulating profile details to force phone verification. Official guidance: https://support.google.com/business/answer/7107242?hl=en and https://support.google.com/business/answer/14271705?hl=en.
