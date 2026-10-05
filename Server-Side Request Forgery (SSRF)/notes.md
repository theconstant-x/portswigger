# Server-Side Request Forgery (SSRF)

PortSwigger Web Security Academy module: [SSRF](https://portswigger.net/web-security/ssrf)

## 📝 Core concepts

- **The core idea:** any feature where the server itself fetches a
  URL/host you partly or fully control (webhook config, PDF generator,
  "check stock at this store", image-from-URL, SSO metadata fetch) is a
  potential pivot into the internal network — the request appears to
  originate from the trusted server, bypassing network-level access
  controls that would normally block an external attacker.
- **In-band vs blind**, same distinction as XXE: in-band means the response
  (or part of it) is reflected back; blind means you only get a generic
  response and have to prove impact via OOB interaction (Collaborator) or
  side effects (timing, error differences).
- **Filter bypass categories:**
  - **Blacklist-based** — blocks known-bad strings (`127.0.0.1`,
    `localhost`, `169.254.169.254`). Beaten by alternate representations:
    decimal/octal IP encodings, `[::1]`, DNS names that resolve to the
    blocked IP (`127.0.0.1.nip.io`), redundant characters a naive regex
    doesn't expect.
  - **Open-redirect chaining** — if the filter only allows URLs on the
    app's OWN trusted hostname, but that hostname has an unrelated open
    redirect, point the SSRF parameter at
    `https://trusted-host/redirect?path=http://internal-target` — the
    filter sees the trusted host, the server ends up fetching wherever the
    redirect actually goes.
  - **Whitelist-based** — only allows URLs matching an expected pattern
    (e.g. must start with `https://trusted-host/`). Beaten via URL parser
    inconsistencies: embedding credentials (`https://trusted-host@evil.com`),
    using `#` to make everything after it look like a fragment to one
    parser but not another, or abusing how the SERVER's HTTP client parses
    the URL differently than whatever regex validated it first.
- **Shellshock as an SSRF payload destination** — if the internal system
  SSRF reaches is an old CGI-based service vulnerable to Shellshock
  (CVE-2014-6271), you can smuggle a malicious `User-Agent` (or similar
  header) THROUGH the SSRF request to achieve blind RCE on that internal
  host, not just read its response.
- **Cloud metadata endpoints** (`http://169.254.169.254/...`) are a
  favorite internal SSRF target in the wild — not this module's main focus,
  but the same localhost/internal-pivot pattern applies.

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [Basic SSRF against the local server](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost) | Apprentice | ⬜ |
| 2 | [Basic SSRF against another back-end system](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system) | Apprentice | ⬜ |
| 3 | [Blind SSRF with out-of-band detection](https://portswigger.net/web-security/ssrf/blind/lab-blind-ssrf-with-out-of-band-detection) | Practitioner | ⬜ |
| 4 | [SSRF with blacklist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter) | Practitioner | ⬜ |
| 5 | [SSRF with filter bypass via open redirection vulnerability](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection) | Practitioner | ⬜ |
| 6 | [Blind SSRF with Shellshock exploitation](https://portswigger.net/web-security/ssrf/blind/lab-blind-ssrf-with-shellshock-exploitation) | Expert | ⬜ |
| 7 | [SSRF with whitelist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter) | Expert | ⬜ |

## Per-lab notes

### Lab 1 — Basic SSRF against the local server
📝 Point the `storeId` URL at `http://localhost/admin` to reach an
internal-only admin panel the app itself can see but a direct external
request can't.

### Lab 2 — Basic SSRF against another back-end system
📝 Same primitive, but the internal target is a DIFFERENT host on the
internal network (a private IP range, e.g. `192.168.0.x`) rather than
localhost — usually needs a quick IP range guess/scan.

### Lab 3 — Blind SSRF, OOB detection
📝 No reflection. A request header (often `Referer`) silently triggers a
server-side fetch to that URL. Confirm via Collaborator interaction only.

### Lab 4 — Blacklist-based filter
📝 Direct `localhost`/`127.0.0.1` gets blocked by string matching. Cycle
through `utils.localhost_variants()` until one slips past the blacklist but
still resolves to the loopback interface.

### Lab 5 — Filter bypass via open redirection
📝 The filter only allows URLs on the app's own trusted hostname — but that
hostname has an unrelated open redirect. Chain through it.

### Lab 6 — Blind SSRF with Shellshock exploitation
📝 The internal system reached via SSRF is an old CGI script vulnerable to
Shellshock. Smuggle the Shellshock payload into a header (commonly
`User-Agent`) of the SSRF'd request to get blind command execution on that
internal host (used here to trigger an OOB interaction from the RCE itself).

### Lab 7 — Whitelist-based filter
📝 Only URLs matching `https://stock.weliketoshop.net/...`-style patterns
pass. Exploit URL-parsing ambiguity — e.g.
`https://stock.weliketoshop.net@192.168.0.X/` (userinfo trick: the
VALIDATOR may read the hostname as `stock.weliketoshop.net` while the HTTP
CLIENT that actually makes the request treats `192.168.0.X` as the host).

## Status key
⬜ not started · 🟨 in progress · ✅ solved
