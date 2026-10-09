# Automated Web Security Assessment Tool

A Python-based scanner that performs passive security checks on a web application and generates a report with severity, impact, and remediation for each finding.

## Features
- HTTPS usage check
- Security header analysis (CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy)
- Cookie flag checks (Secure, HttpOnly, SameSite)
- Server information disclosure (Server, X-Powered-By, and similar headers)
- Risky HTTP methods via OPTIONS (PUT, DELETE, TRACE, CONNECT)
- Severity-sorted Markdown and HTML reports

## Setup
    git clone <your-repo-url>
    cd web-security-scanner
    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt

## Usage
    python scanner.py http://localhost:8080
    python scanner.py https://example.com --no-report

## Testing safely
`test_server.py` starts a deliberately weak local server (insecure cookies, leaky headers, risky methods) so you can try the scanner without touching anyone else's systems:

    python test_server.py

## Sample output
See `sample_reports/sample_report.html`.

## Disclaimer
Use only on systems you own or have written permission to test. This tool sends only normal GET and OPTIONS requests and does not exploit anything.

## Limitations
Checks are passive and based on response headers. Results can include false positives and should be verified manually.