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
    python scanner.py http://localhost:8080 --no-report

## Testing safely
`test_server.py` starts a simple local server on port 8080, so you can try the scanner without touching anyone else's systems. It is served over plain HTTP, sends no security headers, and reveals technology details in its response headers.

Start it in one terminal:

    python test_server.py

Then scan it from a second terminal:

    python scanner.py http://localhost:8080

Expected result: 8 findings (High: 1, Medium: 3, Low: 4).

## Sample output

    [+] Final URL: http://localhost:8080/
    [+] Status code: 200

    [High] Site not served over HTTPS
    [Medium] Missing header: Content-Security-Policy
    [Medium] Missing header: X-Frame-Options
    [Medium] Missing header: Strict-Transport-Security
    [Low] Missing header: X-Content-Type-Options
    [Low] Missing header: Referrer-Policy
    [Low] Server header discloses version: BaseHTTP/0.6 Python/3.13.0
    [Low] X-Powered-By header discloses technology: PHP/5.6.40

    [+] Total findings: 8 (High: 1, Medium: 3, Low: 4)

A full HTML report from this scan is in `sample_reports/sample_report.html`.

## Disclaimer
Use only on systems you own or have written permission to test. This tool sends only normal GET and OPTIONS requests and does not exploit anything.

## Limitations
Checks are passive and based on response headers. Results can include false positives and should be verified manually.