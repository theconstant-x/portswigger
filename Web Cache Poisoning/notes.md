# Web Cache Poisoning

PortSwigger Web Security Academy module: [Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)

## 📝 Core concepts

- **The cache key** is whatever subset of a request (usually just method +
  path, sometimes + a few specific headers) the cache uses to decide "have
  I seen this exact request before?" Anything NOT in the key is
  **unkeyed** — the cache will treat two requests that differ only in an
  unkeyed part as identical, serving whichever response it cached first to
  everyone, regardless of what they actually sent for that part.
- **The attack shape, every lab:**
  1. Find a **cache oracle** — a response that reliably tells you hit vs.
     miss (an `X-Cache` header, a timing difference, or anything similarly
     observable).
  2. Find something **unkeyed but still reflected/influential** in the
     response — a header, cookie, or query param the cache ignores for
     keying purposes but the ORIGIN server still reads and acts on.
  3. Get a **cache miss** with your malicious unkeyed input (often via a
     cache-buster query param that forces a fresh fetch), confirm the
     malicious response gets cached (`X-Cache: hit` on replay).
  4. Remove your cache-buster, re-send the malicious unkeyed input — now
     the NEXT real visitor's normal-looking request serves your poisoned,
     cached response instead of the real page.
- **Design flaws vs. implementation flaws** — early labs (1-5ish) exploit
  straightforward unkeyed-input cases (a header/cookie/query string the
  cache was just never configured to key on). Later labs exploit quirks in
  a SPECIFIC cache implementation's own key-generation logic — parsing
  discrepancies between the cache and the origin, parameter-delimiter
  confusion, path normalization differences — turning things that look
  "safe" (e.g. a parameter the cache DOES key on) into exploitable cracks
  once you understand exactly how that cache's parser actually behaves.
- **Fat GET requests** — some caches only consider the URL for GET keying
  and silently accept (and the origin processes) a request BODY on a GET
  too — letting you smuggle unkeyed data in via the body instead of a
  header/param.
- **Param Miner** (a free Burp extension) automates a lot of this
  module's "which header/param is unkeyed" discovery — these scripts
  reimplement the probing manually in Python, but the extension is worth
  knowing about for faster real-world recon.

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [Web cache poisoning with an unkeyed header](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header) | Practitioner | ⬜ |
| 2 | [Web cache poisoning with an unkeyed cookie](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-cookie) | Practitioner | ⬜ |
| 3 | [Web cache poisoning with multiple headers](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-multiple-headers) | Practitioner | ⬜ |
| 4 | [Targeted web cache poisoning using an unknown header](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-targeted-using-an-unknown-header) | Practitioner | ⬜ |
| 5 | [Web cache poisoning via an unkeyed query string](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query) | Practitioner | ⬜ |
| 6 | [Web cache poisoning via an unkeyed query parameter](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-param) | Practitioner | ⬜ |
| 7 | [Web cache poisoning via a fat GET request](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get) | Practitioner | ⬜ |
| 8 | [Web cache poisoning via ambiguous requests](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests) | Practitioner | ⬜ |
| 9 | [Parameter cloaking](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking) | Expert | ⬜ |
| 10 | [URL normalization](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-normalization) | Expert | ⬜ |
| 11 | [Internal cache poisoning](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-internal) | Expert | ⬜ |

Note: Lab 8 is cross-listed under the Host Header Attacks topic too (same
lab, same vulnerability) — if you already solved it there, it's done here.
Two more labs ("Exploiting HTTP request smuggling to perform web cache
poisoning/deception") are cache-poisoning-FLAVORED but belong to, and are
covered by, the HTTP Request Smuggling module (labs 11-12 there) — not
duplicated here to avoid overlap.

## Per-lab notes

### Lab 1 — Unkeyed header
📝 `X-Forwarded-Host` is reflected into an absolute URL/canonical link but
not part of the cache key — poison it with the exploit server's hostname.

### Lab 2 — Unkeyed cookie
📝 Same idea, a cookie value instead of a header — the cache ignores
cookies for keying by default in many configs, but the origin may still
read and reflect one (e.g. a `fehost`-style tracking cookie).

### Lab 3 — Multiple headers
📝 Needs TWO unkeyed headers working together (one alone isn't enough to
reach the dangerous sink) — find both via probing before combining them.

### Lab 4 — Targeted poisoning using an unknown header
📝 The twist: you must poison the cache ONLY for a specific subset of
users (identified by `User-Agent`, which IS keyed) — discover the right
unkeyed header via brute-force/Param Miner-style guessing rather than it
being hinted directly, then target your specific victim's cache segment.

### Lab 5 — Unkeyed query string
📝 The ENTIRE query string is unkeyed (not just one param) — any
parameter name you invent gets ignored by the cache key but still
reflected by the origin.

### Lab 6 — Unkeyed query parameter
📝 Narrower than Lab 5 — most of the query string IS keyed, but one
specific param (commonly a UTM analytics param) is excluded.

### Lab 7 — Fat GET request
📝 The cache keys only on the URL; the origin still reads and reflects a
request BODY sent with a GET — smuggle the payload there instead of in
any header/param.

### Lab 8 — Ambiguous requests
📝 Duplicate Host headers (see the Host Header Attacks module's version of
this lab for the full writeup) — cache and origin can disagree on which
one is authoritative.

### Lab 9 — Parameter cloaking
📝 A `;`-delimited parameter (`utm_content=1;callback=x`) gets parsed by
the ORIGIN as two separate params but treated by the CACHE as one single
(and excluded) value — smuggle a keyed param's effective value through an
unkeyed one this way.

### Lab 10 — URL normalization
📝 The cache URL-decodes the request line before keying; the browser does
NOT url-decode an already-encoded payload the same way — poison using an
encoded payload the cache normalizes into a working XSS, then deliver the
STILL-encoded URL to the victim (whose browser won't encode it further,
landing exactly on the poisoned cache entry).

### Lab 11 — Internal cache poisoning
📝 Multiple LAYERS of caching (external CDN-style + an internal
application-level cache) with DIFFERENT, disagreeing key rules — bypass
the external layer's keying with a cache-buster, discover the internal
layer caches a narrower fragment with its own separate (and more
permissive) key rules, and poison that inner layer directly.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
