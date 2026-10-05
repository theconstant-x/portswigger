# OAuth Authentication

PortSwigger Web Security Academy module: [OAuth authentication](https://portswigger.net/web-security/oauth)

## 📝 Core concepts

- **Two roles, two hosts.** The **client application** (e.g. a blog site) delegates login to an
  **OAuth/OpenID provider** (e.g. a social media site). Attacks usually abuse the handoff
  *between* these two hosts, not a bug in either one alone.
- **Grant types matter.**
  - `response_type=code` (authorization code flow) — provider returns a short-lived `code`,
    which the client exchanges server-to-server for a token. Safer, but still breakable if
    `redirect_uri` validation is weak.
  - `response_type=token` (implicit flow) — provider returns the access token directly in the
    browser URL fragment (`#access_token=...`). No server-to-server step, so the client has to
    trust whatever the browser hands it — easy to tamper with via Burp Repeater.
- **`redirect_uri` is the main attack surface.** If the provider doesn't strictly validate it
  (exact match vs. prefix/substring match), an attacker can redirect the code/token to a
  server they control.
- **`state` parameter** should be a per-session random value tied to CSRF protection on the
  login flow itself (forced profile linking abuses its absence).
- **Dynamic client registration** (OpenID) lets a client self-register a `client_uri` /
  `logo_uri` with the provider — if the provider fetches that URI server-side, that's SSRF.

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [Authentication bypass via OAuth implicit flow](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow) | Apprentice | ⬜ |
| 2 | [Forced OAuth profile linking](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking) | Practitioner | ⬜ |
| 3 | [OAuth account hijacking via redirect_uri](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri) | Practitioner | ⬜ |
| 4 | [Stealing OAuth access tokens via an open redirect](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect) | Practitioner | ⬜ |
| 5 | [Stealing OAuth access tokens via a proxy page](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page) | Practitioner | ⬜ |
| 6 | [SSRF via OpenID dynamic client registration](https://portswigger.net/web-security/oauth/openid/lab-oauth-ssrf-via-openid-dynamic-client-registration) | Expert | ⬜ |

## Per-lab notes

### Lab 1 — Authentication bypass via OAuth implicit flow
📝 The client app trusts an `email` field sent in its own `POST /authenticate` request instead
of validating the access token server-side. Swap the email in Repeater → replay the request
in-browser → logged in as another user.

### Lab 2 — Forced OAuth profile linking
📝 The "link your social account" flow has no CSRF token and no `state` check. Build a
malicious page that auto-submits the victim's OAuth link request with the attacker's own
`code`/`email` — victim's account gets linked to the attacker's social profile.

### Lab 3 — OAuth account hijacking via redirect_uri
📝 `redirect_uri` is checked with a loose match (e.g. allows any path on the registered host,
or trusts an open redirect on that host). Craft an auth request whose `redirect_uri` leaks the
`code` to an attacker-controlled endpoint.

### Lab 4 — Stealing OAuth access tokens via an open redirect
📝 Implicit flow + a `post-login` open redirect on the client app. Point `redirect_uri` at the
open redirect, which then forwards the browser (fragment and all) to an attacker server's
access log.

### Lab 5 — Stealing OAuth access tokens via a proxy page
📝 Similar idea, but the leak happens via a page on the client app that makes an outbound
request using `window.location` / an `<img>`-style reference, dragging the fragment along in
the `Referer` header to an attacker-controlled resource.

### Lab 6 — SSRF via OpenID dynamic client registration
📝 The provider fetches `client_uri`/`logo_uri`/`jwks_uri` supplied at dynamic registration
time. Register a client with those pointed at an internal-only endpoint (e.g. cloud metadata)
to pivot into SSRF.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
