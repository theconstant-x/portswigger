# HTTP Request Smuggling

PortSwigger Web Security Academy module: [HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)

## 📝 Core concepts

- **The root cause:** two chained servers (front-end proxy/CDN, back-end
  app) disagree about where one HTTP request ends and the next begins.
  Smuggle a second, hidden request inside the body of the first, and the
  back-end processes it as a separate request from the NEXT real user's
  connection — desyncing the two servers' view of the traffic stream.
- **CL vs TE — the two ways to say "this is where the body ends":**
  `Content-Length: N` (exact byte count) and `Transfer-Encoding: chunked`
  (self-terminating, ends on a `0\r\n\r\n` chunk). The spec says TE wins if
  both are present — but not every server agrees, and that disagreement
  *is* the vulnerability.
  - **CL.TE** — front-end uses `Content-Length`, back-end uses
    `Transfer-Encoding`. Smuggle by sending a small `Content-Length` that
    covers only part of the body (so the front-end forwards the rest as the
    START of the next request), while the body itself is valid chunked
    data that the BACK-END fully consumes as one chunked message — the
    leftover bytes sit in the back-end's buffer waiting to be prepended to
    whatever request comes down the pipe next.
  - **TE.CL** — reverse: front-end honors `Transfer-Encoding`, back-end
    uses `Content-Length`. Send a chunked body ending in a real `0`
    terminator, but give a `Content-Length` that's smaller than the full
    chunked encoding — the back-end stops reading early, leaving the
    trailing bytes (which we've crafted as a full extra request) for the
    next read.
  - **TE.TE** — both support `Transfer-Encoding`, but one can be tricked
    into NOT recognizing the header via obfuscation (odd casing, a bad
    whitespace/tab, a duplicate header) — effectively downgrading it to a
    CL.TE or TE.CL scenario for that specific request.
- **Detection:** time-delay probing. Send a request engineered so that a
  vulnerable server will sit waiting for bytes that never come (because the
  OTHER server already considered the request complete). A consistent,
  significant response delay (without an obvious server-side reason) is the
  classic smuggling tell — `utils.send_raw()`'s `elapsed` return value is
  built for exactly this.
- **Confirming via differential responses:** send two requests back to
  back where the smuggled prefix would alter how the SECOND, legitimate-
  looking request gets interpreted (e.g. forcing it to 404 by prepending a
  bogus method/path) — a clean way to prove impact without relying on
  timing alone.
- **CL.0 / 0.CL** — variants where one side ignores the body/Content-Length
  entirely for certain request types (e.g. the back-end treats a GET's body
  as nonexistent regardless of a Content-Length header present) — same
  underlying desync, different specific trigger condition.
- **H2.CL / H2.TE / HTTP-2 CRLF injection/splitting** — when a front-end
  speaks HTTP/2 to the browser but downgrades to HTTP/1.1 to talk to the
  back-end, the conversion step can reintroduce exactly these CL/TE
  ambiguities (HTTP/2 doesn't use either header the same way at the wire
  level) — plus HTTP/2 has its own new injection surface: a `\r\n` smuggled
  into a header VALUE (illegal in HTTP/2, but not always validated) gets
  reinterpreted as a header/request boundary once downgraded to HTTP/1.1
  text.
- **Server-side pause-based smuggling** — some servers process a request
  in distinct stages with a pause between (e.g. waiting on an auth check)
  during which a partially-sent request can still have more appended — a
  timing-dependent variant that needs splitting a single raw send into two
  writes with a deliberate pause between them.
- **Client-side desync (CSD)** — flips the whole model: instead of
  desyncing two SERVERS, trick the VICTIM'S BROWSER into desyncing its own
  connection to a site (via a server that under some condition ignores
  Content-Length), so a later real request the browser sends over that same
  reused connection gets captured/hijacked by an attacker page's `fetch()`
  call. No front-end/back-end pair needed — the user's own browser does
  the smuggling for you once a vector is identified.
- **Why this module uses raw sockets, not `requests`:** `requests` (and
  every normal HTTP client) refuses to send duplicate/conflicting headers,
  malformed chunk sizes, or deliberately-wrong Content-Lengths — exactly
  the things these attacks need. `utils.send_raw()` tunnels a genuinely raw
  byte stream through Burp via `CONNECT`, matching what you'd otherwise do
  by hand-crafting requests in Burp Repeater.

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [Basic CL.TE vulnerability](https://portswigger.net/web-security/request-smuggling/finding/lab-finding-basic) | Practitioner | ⬜ |
| 2 | [Basic TE.CL vulnerability](https://portswigger.net/web-security/request-smuggling/finding/lab-finding-basic-te-cl) | Practitioner | ⬜ |
| 3 | [Obfuscating the TE header](https://portswigger.net/web-security/request-smuggling/finding/lab-obfuscating-te-header) | Practitioner | ⬜ |
| 4 | [Confirming CL.TE via differential responses](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-clte-via-differential-responses) | Practitioner | ⬜ |
| 5 | [Confirming TE.CL via differential responses](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-tecl-via-differential-responses) | Practitioner | ⬜ |
| 6 | [Bypass front-end controls, CL.TE](https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-clte) | Practitioner | ⬜ |
| 7 | [Bypass front-end controls, TE.CL](https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-tecl) | Practitioner | ⬜ |
| 8 | [Reveal front-end request rewriting](https://portswigger.net/web-security/request-smuggling/exploiting/lab-reveal-front-end-request-rewriting) | Practitioner | ⬜ |
| 9 | [Capture other users' requests](https://portswigger.net/web-security/request-smuggling/exploiting/lab-capture-other-users-requests) | Practitioner | ⬜ |
| 10 | [Deliver reflected XSS](https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss) | Practitioner | ⬜ |
| 11 | [Perform web cache poisoning](https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-poisoning) | Expert | ⬜ |
| 12 | [Perform web cache deception](https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-deception) | Expert | ⬜ |
| 13 | [H2.CL request smuggling](https://portswigger.net/web-security/request-smuggling/advanced/h2-cl-request-smuggling) | Practitioner | ⬜ |
| 14 | [Response queue poisoning via H2.TE](https://portswigger.net/web-security/request-smuggling/advanced/h2-te-request-smuggling) | Practitioner | ⬜ |
| 15 | [HTTP/2 request smuggling via CRLF injection](https://portswigger.net/web-security/request-smuggling/advanced/h2-request-smuggling-crlf-injection) | Practitioner | ⬜ |
| 16 | [HTTP/2 request splitting via CRLF injection](https://portswigger.net/web-security/request-smuggling/advanced/h2-request-splitting-crlf-injection) | Practitioner | ⬜ |
| 17 | [CL.0 request smuggling](https://portswigger.net/web-security/request-smuggling/browser/cl-0) | Practitioner | ⬜ |
| 18 | [0.CL request smuggling](https://portswigger.net/web-security/request-smuggling/advanced/0-cl-request-smuggling) | Expert | ⬜ |
| 19 | [Web cache poisoning via HTTP/2 request tunnelling](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-cache-poisoning-via-http2-request-tunnelling) | Expert | ⬜ |
| 20 | [Server-side pause-based request smuggling](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-server-side-pause-based) | Expert | ⬜ |
| 21 | [Client-side desync](https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-client-side-desync) | Practitioner | ⬜ |
| 22 | [Browser cache poisoning via client-side desync](https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-browser-cache-poisoning-via-client-side-desync) | Practitioner | ⬜ |

## Per-lab notes

### Labs 1–2 — Basic CL.TE / TE.CL
📝 Pure detection via time delay — no exploitation yet. Send the classic
probe shape, measure response time, compare against a baseline.

### Lab 3 — Obfuscating the TE header
📝 The front-end only recognizes a strictly-formed `Transfer-Encoding:
chunked` header and ignores a slightly mangled one, while the back-end
still honors the mangled version — cycle through casing/whitespace/
duplicate-header variants.

### Labs 4–5 — Confirming via differential responses
📝 Instead of relying on timing, smuggle a prefix that makes the NEXT
request on the connection get a visibly different (e.g. 404) response than
normal — proof the smuggled bytes were processed as a separate request.

### Labs 6–7 — Bypass front-end security controls
📝 The front-end blocks direct access to some path (e.g. `/admin`) but the
BACK-END doesn't care how it got the request. Smuggle a request to the
blocked path as the "hidden second request" — the front-end's filter never
even sees it as a distinct request to check.

### Lab 8 — Reveal front-end request rewriting
📝 Smuggle a request whose response (via the back-end echoing headers back)
reveals what headers/values the front-end ADDS or rewrites before
forwarding (e.g. `X-Forwarded-For`) — useful recon for other attacks.

### Lab 9 — Capture other users' requests
📝 Smuggle a request ending in an incomplete body — the NEXT real user's
request on that connection gets appended as the "body" of our smuggled
request, and gets reflected back to US in that response (e.g. via a
comment form that echoes submitted data).

### Lab 10 — Deliver reflected XSS
📝 Smuggle a request that rewrites what the next user's browser receives —
e.g. forcing a 301 redirect with an XSS payload in it, so the NEXT visitor
(not us) gets the payload delivered via a response that was meant for them.

### Labs 11–12 — Web cache poisoning / deception via smuggling
📝 Smuggle a request whose RESPONSE gets cached under a victim's innocent-
looking request path — poisoning (bad content served to everyone after) or
deception (a private response cached and served to others) depending on
which direction the mismatch goes.

### Lab 13 — H2.CL
📝 HTTP/2 front-end downgrades to HTTP/1.1 for the back-end; craft a
request where the DATA frame's actual length disagrees with an injected
`Content-Length: 0`-style header surviving the downgrade.

### Lab 14 — H2.TE (response queue poisoning)
📝 A `Transfer-Encoding` header illegally smuggled through an HTTP/2
request (TE is forbidden in HTTP/2 itself) survives the downgrade and
desyncs the back-end's response queue — later responses get misattributed
to the wrong request on the connection.

### Lab 15 — HTTP/2 CRLF injection (smuggling)
📝 A raw `\r\n` inside an HTTP/2 header VALUE (should be rejected, isn't)
gets reinterpreted as a literal line break once downgraded to HTTP/1.1
text — inject an entire second request's worth of headers this way.

### Lab 16 — HTTP/2 CRLF injection (splitting)
📝 Same injection primitive as Lab 15, but used to split the single
downgraded request into two complete HTTP/1.1 requests on the wire instead
of just adding headers to one.

### Lab 17 — CL.0
📝 Back-end ignores Content-Length entirely for a given request type
(commonly POST-without-body-expected paths) while front-end still uses it
— causing the same forwarding-boundary mismatch as classic CL.TE.

### Lab 18 — 0.CL
📝 The mirror case — front-end disregards Content-Length under specific
conditions (e.g. for a particular verb) while the back-end still uses it.

### Lab 19 — Cache poisoning via HTTP/2 request tunnelling
📝 Combines the H2-downgrade CRLF-injection primitive with classic cache-
key/unkeyed-input poisoning — smuggle a header through the downgrade that
the cache treats as unkeyed but the origin treats as significant.

### Lab 20 — Server-side pause-based smuggling
📝 Needs a genuine TWO-STAGE socket write: send the request headers +
partial body, deliberately PAUSE (the server begins some async step, e.g.
an auth lookup), then send the rest including the smuggled suffix — timing
the second write to land while the server's mid-request state is exploitable.

### Lab 21 — Client-side desync
📝 No front-end/back-end pair — the VICTIM'S BROWSER gets tricked into
desyncing its own connection via a request/response pair that causes
Content-Length to be ignored, then a same-connection follow-up (crafted via
`fetch()` from our exploit-server page) gets misrouted. See
`lab21_client_side_desync.py` for the generated exploit-server JS.

### Lab 22 — Browser cache poisoning via client-side desync
📝 Same CSD vector as Lab 21, but the hijacked follow-up poisons the
browser's OWN HTTP cache (not a shared server-side cache) with
attacker-controlled content for a legitimate-looking URL.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
