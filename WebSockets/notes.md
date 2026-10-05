# WebSockets

PortSwigger Web Security Academy module: [WebSockets](https://portswigger.net/web-security/websockets)

## 📝 Core concepts

- **It's still just HTTP at the start.** A WebSocket connection opens with
  a normal HTTP request carrying `Upgrade: websocket` — all the usual web
  vulnerability thinking still applies to that handshake (cookies, CSRF,
  Origin checks) before the connection switches to the framed binary
  protocol.
- **Message content is still user input.** Once connected, whatever the
  client sends over the socket often ends up processed server-side exactly
  like a normal form field — if it's not validated, you get the same
  injection classes (XSS, SQLi, etc.) just delivered over a different
  transport. `send_ws_text()`/`recv_ws_text()` in `utils.py` are the
  equivalent of `requests.post()` for this module.
- **The handshake is where auth/origin issues live.** Two common flaws:
  - The server doesn't validate **`Origin`** on the handshake at all —
    meaning ANY website can open a WebSocket connection to it from a
    victim's browser, carrying the victim's cookies automatically (this is
    **Cross-Site WebSocket Hijacking**, CSWSH — the WebSocket equivalent of
    CSRF, except because it's a live bidirectional channel, a successful
    hijack can both SEND actions as the victim AND READ the server's
    responses back, unlike classic CSRF which is blind).
  - The server trusts a **session/auth token only at handshake time** and
    never re-checks it per-message — so a connection opened while
    authenticated keeps working even after that session should've been
    invalidated, or headers set only on the initial handshake (not
    re-validated) can be manipulated to escalate privilege for the whole
    session's duration.
- **CSWSH delivery is a browser exploit, not a Python request** — like
  Clickjacking, confirming/exploiting it means getting the VICTIM's browser
  to open the connection (so it carries their cookies), via a page hosted
  on the exploit server. `utils.py` gives you message/handshake primitives
  for labs 1–2; lab 3's "exploit" is an HTML/JS PoC page, same shape as the
  Clickjacking module.

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [Manipulating WebSocket messages to exploit vulnerabilities](https://portswigger.net/web-security/websockets/lab-manipulating-messages-to-exploit-vulnerabilities) | Apprentice | ⬜ |
| 2 | [Manipulating the WebSocket handshake to exploit vulnerabilities](https://portswigger.net/web-security/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities) | Practitioner | ⬜ |
| 3 | [Cross-site WebSocket hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab-websocket-hijacking-via-cross-site-websocket-hijacking) | Practitioner | ⬜ |

## Per-lab notes

### Lab 1 — Manipulating WebSocket messages
📝 A live chat feature sends messages over the socket with no server-side
sanitization. Same reflected-XSS mindset as the XSS module, just delivered
via `send_ws_text()` instead of a form POST — the payload shows up for
other users viewing the chat.

### Lab 2 — Manipulating the handshake
📝 The server reads an auth-relevant header (e.g. a custom header
indicating "admin" status, or trusts a cookie that's checked loosely) only
during the handshake. Tamper with handshake headers to reach functionality
that should require real authentication.

### Lab 3 — Cross-site WebSocket hijacking
📝 No `Origin` validation on the handshake. Host a page that opens a
WebSocket connection to the target FROM the victim's browser (carrying
their session cookie automatically), then exfiltrate whatever the server
sends back over that channel (e.g. their live chat history containing
sensitive data) to our own exploit-server endpoint.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
