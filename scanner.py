import argparse
import requests
import sys
import re
from report import save_reports, sort_findings, summary

# header name: (severity, impact, fix)
HEADERS = {
    "Content-Security-Policy": ("Medium", "Helps prevent XSS and data injection.", "Add a restrictive CSP header."),
    "X-Frame-Options": ("Medium", "Page can be framed, enabling clickjacking.", "Set X-Frame-Options: DENY or SAMEORIGIN."),
    "Strict-Transport-Security": ("Medium", "Browsers may allow HTTP downgrade.", "Add HSTS with a long max-age."),
    "X-Content-Type-Options": ("Low", "Browser may MIME-sniff responses.", "Set X-Content-Type-Options: nosniff."),
    "Referrer-Policy": ("Low", "URLs may leak to third parties.", "Set Referrer-Policy: strict-origin-when-cross-origin."),
}

def fetch(url):
    try:
        return requests.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException as e:
        print(f"[!] Could not reach {url}: {e}")
        sys.exit(1)

def check_https(response):
    findings = []
    if not response.url.startswith("https://"):
        findings.append({
            "title": "Site not served over HTTPS",
            "severity": "High",
            "impact": "Traffic can be intercepted or modified (MITM).",
            "fix": "Enable TLS and redirect all HTTP traffic to HTTPS."
        })
    return findings

def check_headers(response):
    findings = []
    for name, (sev, impact, fix) in HEADERS.items():
        if name not in response.headers:
            findings.append({
                "title": f"Missing header: {name}",
                "severity": sev,
                "impact": impact,
                "fix": fix
            })
    return findings
def parse_cookie(cookie):
    # split "name=value; Path=/; HttpOnly" into the name and a set of flag names
    parts = [p.strip() for p in cookie.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    flags = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
    return name, flags

def check_cookies(response):
    findings = []
    # include cookies set during redirects too
    for r in response.history + [response]:
        for cookie in r.raw.headers.getlist("Set-Cookie"):
            name, flags = parse_cookie(cookie)

            if "secure" not in flags:
                findings.append({
                    "title": f"Cookie '{name}' missing Secure flag",
                    "severity": "Medium",
                    "impact": "Cookie can be sent over unencrypted HTTP.",
                    "fix": "Add the Secure attribute to the cookie."
                })
            if "httponly" not in flags:
                findings.append({
                    "title": f"Cookie '{name}' missing HttpOnly flag",
                    "severity": "Medium",
                    "impact": "JavaScript can read the cookie, so XSS could steal it.",
                    "fix": "Add the HttpOnly attribute to the cookie."
                })
            if "samesite" not in flags:
                findings.append({
                    "title": f"Cookie '{name}' missing SameSite attribute",
                    "severity": "Low",
                    "impact": "Cookie may be sent on cross-site requests (CSRF risk).",
                    "fix": "Set SameSite=Lax or SameSite=Strict."
                })
    return findings
LEAKY_HEADERS = ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"]
def check_info_disclosure(response):
    findings = []

    # Server header: only flag it if it reveals a version number
    server = response.headers.get("Server")
    if server and re.search(r"\d", server):
        findings.append({
            "title": f"Server header discloses version: {server}",
            "severity": "Low",
            "impact": "Attackers can look up known vulnerabilities for this exact version.",
            "fix": "Remove or genericize the Server header in the web server config."
        })

    # Headers that reveal the technology stack
    for name in LEAKY_HEADERS:
        value = response.headers.get(name)
        if value:
            findings.append({
                "title": f"{name} header discloses technology: {value}",
                "severity": "Low",
                "impact": "Reveals the backend technology, which helps attackers target it.",
                "fix": f"Remove the {name} header from responses."
            })
    return findings
RISKY_METHODS = {
    "PUT": ("Medium", "Attackers may upload or overwrite files on the server."),
    "DELETE": ("Medium", "Attackers may delete resources on the server."),
    "TRACE": ("Low", "Can be abused in cross-site tracing attacks to expose headers."),
    "CONNECT": ("Medium", "Server may be abused as a proxy."),
}

def check_http_methods(url):
    findings = []
    try:
        r = requests.options(url, timeout=10)
    except requests.RequestException:
        return findings

    allow = r.headers.get("Allow", "")
    allowed = [m.strip().upper() for m in allow.split(",") if m.strip()]

    for method, (sev, impact) in RISKY_METHODS.items():
        if method in allowed:
            findings.append({
                "title": f"Risky HTTP method enabled: {method}",
                "severity": sev,
                "impact": impact,
                "fix": f"Disable the {method} method unless it is required."
            })
    return findings
def normalize(url):
    # allow "example.com" without a scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Passive web security assessment tool. Scan only targets you own or have permission to test."
    )
    parser.add_argument("url", help="Target URL, e.g. http://localhost:8080")
    parser.add_argument("--no-report", action="store_true",
                        help="Print findings only, do not save report files")
    args = parser.parse_args()

    target = normalize(args.url)
    response = fetch(target)
    print(f"[+] Final URL: {response.url}")
    print(f"[+] Status code: {response.status_code}\n")

    findings = (check_https(response) + check_headers(response) + check_cookies(response)
                + check_info_disclosure(response) + check_http_methods(response.url))
    findings = sort_findings(findings)

    for f in findings:
        print(f"[{f['severity']}] {f['title']}")

    counts = summary(findings)
    print(f"\n[+] Total findings: {len(findings)} "
          f"(High: {counts['High']}, Medium: {counts['Medium']}, Low: {counts['Low']})")

    if not args.no_report:
        md_path, html_path = save_reports(target, findings)
        print(f"[+] Reports saved: {md_path}, {html_path}") 