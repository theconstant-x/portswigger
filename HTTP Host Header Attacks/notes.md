# HTTP Host Header Attacks

PortSwigger Web Security Academy module: [HTTP Host header attacks](https://portswigger.net/web-security/host-header)

## 📝 Core concepts

- **The Host header is just another user-controlled input.** Apps often
  implicitly trust it to generate absolute URLs (password reset links,
  canonical tags), decide routing, or even gate access (treating a
  specific Host value as "this must be an internal/trusted caller") — all
  without realizing an external attacker can set it to anything.
- **Testing methodology:**
  1. **Supply an arbitrary Host header** — does the app still respond
     normally (200, not rejected)? If so, it's probably not validating it.
  2. **Check for reflection** — does the value show up anywhere in the
     response (a link, a redirect target, a cache-control hint)?
  3. **Send ambiguous requests** — duplicate Host headers, a Host header
     plus an absolute URL in the request line that disagrees with it,
     whitespace tricks — different components in the chain (CDN vs origin)
     can disagree about which one "wins," and that disagreement is
     exploitable the same way CL/TE disagreement is in request smuggling.
  4. **Try override headers** — `X-Forwarded-Host`, `X-Host`,
     `X-Forwarded-Server` — often trusted MORE than the real Host header by
     a backend expecting them from a legitimate reverse proxy in front of
     it, with no verification that the actual caller is that proxy.
- **Password reset poisoning** — if the password-reset email's link is
  built from the (attacker-controlled) Host header, point it at a domain
  you control and harvest the victim's reset token when they click it (or,
  in the middleware variant, when the SERVER itself makes an outbound
  request using the poisoned host — no victim click needed at all).
- **Routing-based SSRF** — if a front-end/load balancer routes purely
  based on the Host header's value (common in cloud/CDN setups), supplying
  an internal IP/hostname as Host can make the FRONT-END itself connect to
  that internal target on your behalf — distinct from classic SSRF, which
  usually needs a dedicated "fetch this URL" feature; here the Host header
  alone is the SSRF vector.
- **Connection state attacks** — some setups validate the Host header only
  on the FIRST request of a reused (keep-alive) connection, then trust
  every subsequent request on that same connection implicitly. Smuggle a
  malicious request down a connection that already passed validation on
  request #1, and it skips the check entirely — needs Burp's "send group
  in sequence (single connection)" feature or equivalent raw-socket control
  to land both requests on the literal same TCP connection.
- **SSRF via flawed request parsing** — rather than validating the Host
  HEADER, some setups validate the absolute URL in the REQUEST LINE
  instead (`GET https://target.com/ HTTP/1.1`) — meaning the Host header
  itself goes completely unchecked once you switch to that request form,
  even though it's still what routing/internal logic actually uses.

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [Basic password reset poisoning](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning) | Apprentice | ⬜ |
| 2 | [Host header authentication bypass](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass) | Apprentice | ⬜ |
| 3 | [Web cache poisoning via ambiguous requests](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests) | Practitioner | ⬜ |
| 4 | [Routing-based SSRF](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf) | Practitioner | ⬜ |
| 5 | [Password reset poisoning via middleware](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning) | Practitioner | ⬜ |
| 6 | [Host validation bypass via connection state attack](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-host-validation-bypass-via-connection-state-attack) | Practitioner | ⬜ |
| 7 | [SSRF via flawed request parsing](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-ssrf-via-flawed-request-parsing) | Expert | ⬜ |

## Per-lab notes

### Lab 1 — Basic password reset poisoning
📝 The reset-link email is built from the Host header. Trigger a reset for
the victim with Host set to the exploit server, harvest the token from the
exploit server's access log once the victim's reset request lands there.

### Lab 2 — Host header authentication bypass
📝 `/admin` checks the Host header for `localhost` and grants access on
that basis alone — no real auth. Just set `Host: localhost` on the request.

### Lab 3 — Web cache poisoning via ambiguous requests
📝 Send duplicate Host headers (one real, one malicious) — the cache and
the origin can parse/key on DIFFERENT ones, letting you poison a cached
response under the real hostname using content influenced by the fake one.

### Lab 4 — Routing-based SSRF
📝 Point the Host header at an internal IP — the front-end's OWN routing
logic connects there directly, no app feature needed as the pivot.

### Lab 5 — Password reset poisoning via middleware
📝 Same core flaw as Lab 1, but delivered via `X-Forwarded-Host` (not the
primary Host header) — and the poisoned request happens SERVER-SIDE via
middleware, no victim click required at all.

### Lab 6 — Host validation bypass via connection state attack
📝 Needs two requests landing on the literal SAME TCP connection: a first
request with a valid Host (passes validation), immediately followed by a
second request with a malicious Host down that SAME connection — the
app trusts the connection-level validation from request #1 and skips
re-checking request #2.

### Lab 7 — SSRF via flawed request parsing
📝 Validation targets the absolute URL in the request LINE, not the Host
header. Switch to `GET https://target/ HTTP/1.1` form with a real-looking
request-line URL, then set Host to whatever internal target you actually
want reached — it sails through unchecked.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
