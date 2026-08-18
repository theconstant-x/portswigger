# Access Control Notes — PortSwigger Web Security Academy

---

## WHAT IS ACCESS CONTROL?

Access control determines **whether a user is allowed to do what they're trying to do.**
It's a different layer from authentication and session management:

```
Authentication      → "Who are you?"            (login, password, MFA)
Session management   → "Is this still you?"      (cookies, tokens, every request)
Access control        → "Are you ALLOWED to do this?"  (the actual permission check)
```

> 📝 You can nail authentication and session management perfectly and still have
> a critical vulnerability if access control is missing. A user can be 100%
> proven to be "wiener" and still successfully view admin-only data if the
> server never checks whether wiener is ALLOWED to see it.

Broken access control is consistently one of the most common — and most severe —
web vulnerability classes. It's also often the **easiest** to find: there's no
encoding to bypass, no payload to craft. You just try a request you shouldn't
be allowed to make, and see if it works.

---

## TYPES OF ACCESS CONTROL

### Vertical Access Control
Restricts access based on **privilege level** — different types of users get
different functionality. A regular user shouldn't reach admin functions.

```
Regular user  → /my-account              (allowed)
Regular user  → /admin/delete-user       (should be blocked — vertical escalation if not)
```

### Horizontal Access Control
Restricts access based on **ownership** — users of the same privilege level
should only access their own data, not each other's.

```
wiener → /my-account?id=wiener   (allowed — it's their own account)
wiener → /my-account?id=carlos   (should be blocked — horizontal escalation if not)
```

### Context-Dependent Access Control
Restricts access based on **application state** — actions must happen in the
correct order or sequence.

```
Step 1: Confirm role change request
Step 2: Submit confirmation
        ↑ Step 2 should fail if Step 1 was never completed.
          If you can jump straight to Step 2, that's a context-dependent flaw.
```

---

## PRIVILEGE ESCALATION — VERTICAL VS HORIZONTAL

| | Vertical Escalation | Horizontal Escalation |
|---|---|---|
| **What changes** | User gains a HIGHER privilege level | User accesses ANOTHER user's data at the SAME level |
| **Example** | Regular user reaches an admin panel | wiener views carlos's account page |
| **Common cause** | Admin functionality not gated by role check | Object ID directly user-controlled with no ownership check |
| **Worse outcome** | Can lead to full application compromise | Can chain into vertical escalation (target an admin's account) |

> 📝 Horizontal and vertical escalation are not mutually exclusive. If you can
> horizontally escalate into the ACCOUNT of an administrator (e.g. by guessing
> their user ID), you've now also vertically escalated — you have admin
> privileges through someone else's identity. This chaining is extremely common
> in real bug bounty reports.

---

## INSECURE DIRECT OBJECT REFERENCES (IDOR)

IDOR is a specific, very common pattern within access control vulnerabilities.
It happens when an application uses a user-supplied value (an ID, filename, key)
to directly reference an object — without checking whether the current user is
actually allowed to access that object.

```
GET /my-account?id=123        → wiener's own account
GET /my-account?id=456        → carlos's account — IDOR if this just... works
GET /download-transcript/1.txt → chat transcript #1 — IDOR if no ownership check
```

**Why it's so common:** IDs are often sequential integers, predictable GUIDs,
or filenames. An attacker doesn't even need creativity — incrementing a number
is often enough.

**Where IDOR hides:**
- URL query parameters (`?id=`, `?userId=`)
- URL path segments (`/user/123`)
- POST body parameters
- Hidden form fields
- JSON API request/response bodies
- File paths and filenames

> 📝 IDOR is "just" an access control bug, but the term exists because the
> pattern is SO common it earned its own name. Don't think of IDOR as a separate
> category from access control — it's the most frequent manifestation of it.

---

## COMMON ACCESS CONTROL FAILURE PATTERNS

### 1. Unprotected functionality (security by obscurity)
The functionality has no access control AT ALL — it's just not linked from the
UI. The developer assumed "if they can't see the link, they can't reach it."

```
Admin page exists at /admin — never linked anywhere, but loads for ANYONE who
guesses or finds the URL.
```

> 📝 This is the textbook definition of "security through obscurity" — and
> it's not security at all. Hiding a URL is not the same as protecting it.
> Burp's content discovery, robots.txt, JS source comments, and sitemap files
> are all common ways the "hidden" URL leaks anyway.

### 2. Parameter-based access control
The user's role or ID is read from a value the CLIENT controls — a parameter,
cookie, or hidden field — rather than being derived server-side from the
authenticated session.

```
Cookie: Admin=false        ← client can just change this to true
?role=user                 ← client can just change this to admin
<input type="hidden" name="roleid" value="1">  ← client can edit before submit
```

### 3. Referer-based access control
The server trusts the `Referer` header to decide whether a request came from
an authorized page (e.g. "this request must have come FROM the admin panel").
The Referer header is fully attacker-controlled and trivially forged.

### 4. Method-based access control
Access control is enforced for one HTTP method (e.g. POST) but not for others
(GET, PUT, PATCH) that reach the same underlying function.

```
POST /admin/delete-user   → 401 Unauthorized (checked)
GET  /admin/delete-user   → 200 OK            (not checked — same handler, different verb)
```

### 5. Platform/path-based access control bypass
URL-based access rules (e.g. "block everything under /admin/*") can be
bypassed using path manipulation that the access-control layer doesn't
normalise the same way the application backend does.

```
/admin/deleteUser           → blocked
/ADMIN/deleteUser           → bypass (case mismatch)
/admin/../admin/deleteUser  → bypass (path traversal normalises differently)
/;/admin/deleteUser         → bypass (path parameter confusion)
/admin/deleteUser/.         → bypass (trailing segment confusion)
```

### 6. Multi-step process flaws
A sensitive action is split into several steps (e.g. "request role change" →
"confirm role change"). Access control is only checked on step 1. If an
attacker can jump directly to a later step, the check never runs.

### 7. Data leakage despite the access control "working"
The server correctly redirects an unauthorized user away — but the REDIRECT
RESPONSE BODY itself still contains the sensitive data before the redirect
takes effect. The access control "worked" at the HTTP status level but failed
at the data level.

---

## ACCESS CONTROL TESTING SOP

### Step 1 — Map Every Role and Privilege Level
- What roles exist? (anonymous, regular user, admin, etc.)
- Log in as each available role/account if possible (`wiener:peter`,
  `administrator:admin` provided in many labs)
- List every endpoint and function each role can reach via the UI

### Step 2 — Identify Object References
- Any URL, parameter, or body field that references a specific user, account,
  document, or resource by ID
- Note whether the ID is predictable (sequential int) or unpredictable (GUID)

### Step 3 — Test Vertical Escalation
- As a low-privilege user, directly request URLs only shown to admins
- Check `robots.txt`, JS source, sitemap, and comments for hidden admin paths
- Try common admin paths: `/admin`, `/administrator`, `/admin-panel`, `/manage`

### Step 4 — Test Horizontal Escalation (IDOR)
- Log in as User A, capture a request referencing User A's own data
- Replace the ID/reference with User B's value
- Does the server return User B's data? → IDOR confirmed

### Step 5 — Test Parameter Tampering
- Look for role/permission values in: cookies, hidden fields, JSON body,
  query parameters
- Change `role=user` → `role=admin`, `isAdmin=false` → `isAdmin=true`, etc.

### Step 6 — Test Method Tampering
- Take any access-controlled POST/PUT/DELETE request
- Right-click in Burp Repeater → "Change request method"
- Try GET, PUT, PATCH, even malformed/lowercase methods
- Does the access check still apply?

### Step 7 — Test Referer-Based Checks
- If a request appears to validate the Referer header, try:
  - Omitting it
  - Forging it to match the expected admin page URL

### Step 8 — Test Multi-Step Processes
- Walk through a sensitive multi-step flow once normally (e.g. role upgrade)
- Capture EVERY request in the sequence
- Try replaying only the LAST step directly, skipping the earlier
  confirmation/validation steps

### Step 9 — Test for Data Leakage in Redirects
- When access is denied and a redirect occurs (3xx, or even a 200 with a
  client-side redirect), inspect the FULL response body
- Sensitive data may be present in the body even though the user is redirected
  away before they'd normally see it rendered

### Step 10 — Test Path Normalisation Bypass (URL-based access control)
- If an access rule blocks `/admin/*`, try:
  - Case variation: `/ADMIN/x`
  - Trailing slash/dot: `/admin/x/`, `/admin/x/.`
  - Path traversal: `/public/../admin/x`
  - Null/encoded characters, double-encoding
  - Different HTTP method on the same path

---

## QUICK BURP WORKFLOW

1. Log in as the LOW-privilege account → capture every sensitive request in
   **Proxy History**
2. Send each to **Repeater**
3. For each one, systematically test:
   - Swap any ID/reference parameter → check for IDOR
   - Remove session cookie entirely → check for unauthenticated access
   - Change HTTP method → check for method-based bypass
   - Strip or forge Referer → check for Referer-based bypass
4. Use **Burp's "Compare site map"** (Pro) or manually diff site maps captured
   as different users to spot admin-only paths a lower-privilege user can
   still load directly
5. For multi-step flows, capture the FULL sequence, then replay steps out of
   order in Repeater

> 📝 A genuinely useful manual technique: log in as the admin account FIRST and
> walk the whole admin UI once. Burp's Proxy History now has every admin URL
> recorded. Log out, log back in as the low-privilege user, and try hitting
> those same captured URLs directly. This is faster than guessing paths.

---
---

## PORTSWIGGER LABS

---

### #01 — Unprotected admin functionality

**URL:** https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality
**Vulnerability:** Admin panel has no access control checks whatsoever
**Aim:** Delete the user `carlos` via the admin panel

**Background:**
The admin panel exists at a simple, guessable path. It's never linked anywhere
in the UI, but nothing stops you from just navigating there directly — no
login check, no role check.

**Analysis:**
```
GET /robots.txt
→ Disallow: /administrator-panel
   (robots.txt is meant to tell search engines not to index a path —
    but it ALSO tells an attacker that path exists)

GET /administrator-panel
→ 200 OK — loads fully, no auth required at all
```

**Steps:**
1. Visit `/robots.txt` — find the disallowed admin path
2. Navigate directly to that path
3. Use the "Delete user" button/link next to `carlos`

> 📝 `robots.txt` is a goldmine during recon. Developers often list sensitive
> paths there specifically to keep search engines from indexing them — without
> realising they're handing the path straight to anyone who checks the file.
> Always check `robots.txt` first when looking for hidden admin functionality.

---

### #02 — Unprotected admin functionality with unpredictable URL

**URL:** https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url
**Vulnerability:** Admin panel at a random, unguessable path — but the path leaks elsewhere
**Aim:** Find the admin panel and delete `carlos`

**Background:**
This time the admin path is genuinely unpredictable (e.g. `/admin-a1b2c3`) —
brute-forcing it directly isn't realistic. But the path is disclosed somewhere
else in the application that a regular user CAN access — usually the page
source or a linked JS file.

**Analysis:**
```
View page source of the homepage:
  <!-- a comment, or a <script> tag referencing the admin path -->
  e.g. <a style="display:none" href="/admin-a8s9d2">Admin panel</a>

→ Navigate directly to the leaked path
→ No access control there either — just unguessable, not protected
```

**Steps:**
1. View page source (Ctrl+U) on the home page
2. Search for "admin" in the HTML/JS comments
3. Navigate to the disclosed path
4. Delete `carlos`

> 📝 An unpredictable URL is NOT access control — it's obscurity, and
> obscurity fails the moment the URL leaks anywhere (page source, JS bundle,
> error message, support documentation, git history). The fix is an actual
> server-side role check, not a harder-to-guess path.

---

### #03 — User role controlled by request parameter

**URL:** https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter
**Vulnerability:** Admin status is determined by a cookie the client can freely modify
**Aim:** Access the admin panel and delete `carlos`

**Background:**
After logging in, the application sets a cookie like `Admin=false`. The server
trusts this cookie to decide whether to show admin functionality — but nothing
stops the client from simply changing it.

**Analysis:**
```
Cookie: Admin=false   → /admin returns 401/redirect

Change to:
Cookie: Admin=true    → /admin loads fully
```

**Steps:**
1. Log in as `wiener:peter`
2. In Burp, intercept any request and find `Cookie: Admin=false`
3. Use Proxy → **Match and Replace** (or just edit in Repeater) to change it to `Admin=true`
4. Reload `/admin` → access granted → delete `carlos`

> 📝 Burp's **Match and Replace** rule is genuinely useful here — set it once
> to rewrite `Admin=false` → `Admin=true` on every outgoing request, and you
> don't have to manually edit the cookie every time you browse the app in
> Burp's browser.

---

### #04 — User role can be modified in user profile

**URL:** https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile
**Vulnerability:** Profile update endpoint accepts a `roleid` field the client shouldn't control
**Aim:** Escalate your own account to admin via the profile update form

**Background:**
The "update profile" feature (e.g. updating your email) actually accepts and
processes a hidden `roleid` parameter in the request body. The UI never shows
this field for editing — but the server still accepts it if you add it
yourself.

**Analysis:**
```
Normal request:
  POST /my-account/change-email
  email=wiener@test.com&roleid=1     ← roleid sent, but normally unchanged

Tampered request:
  email=wiener@test.com&roleid=2     ← roleid 2 happens to mean admin
```

**Steps:**
1. Submit a normal profile update, intercept it in Burp
2. Notice a `roleid` (or similar) parameter in the body
3. Try different integer values for `roleid`
4. Find the value that grants admin → resubmit → confirm escalation

> 📝 This is a classic example of trusting client input for something that
> should ONLY ever be set server-side. Even though the UI never shows a way
> to edit this field, the backend still processes it blindly if it's present
> in the request — always inspect the FULL request body, not just what the
> form visibly contains.

---

### #05 — URL-based access control can be circumvented

**URL:** https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented
**Vulnerability:** Access control is enforced by a front-end proxy/gateway based on URL path matching, which differs from how the back-end interprets the path
**Aim:** Access `/admin/deleteUser` as a non-admin and delete `carlos`

**Background:**
A reverse proxy in front of the app blocks requests to `/admin/*` for
non-admin users — by inspecting the literal URL path. But the actual backend
application server might interpret certain crafted paths differently (case
sensitivity, extra segments, encoding) such that the SAME resource is reached
via a path the proxy doesn't recognise as `/admin/*`.

**Analysis:**
```
GET /admin/deleteUser?username=carlos     → blocked by front-end proxy (401)

Try bypasses:
GET /ADMIN/deleteUser?username=carlos                → case mismatch may bypass proxy rule
GET /admin/deleteUser/anything?username=carlos       → trailing segment may confuse rule matching
GET /admin/deleteUser%2F..%2FdeleteUser?username=carlos  → encoded traversal

A working bypass for this lab is typically adding a non-matching path segment:
GET /admin/deleteUser/..%2fdeleteUser?username=carlos
```

The key technique: the proxy and the backend app server can disagree about
where a path "ends" — exploiting that disagreement reaches the protected
endpoint through a path the proxy's rule doesn't match, while the backend
still routes it to the same handler.

**Steps:**
1. Confirm direct access to `/admin/deleteUser` is blocked
2. Try path variations (case, trailing segments, traversal sequences) in
   Burp Repeater until one returns the admin page/functionality instead of a block
3. Use the working path to delete `carlos`

> 📝 This class of bug is sometimes called **path confusion** or **access
> control bypass via path normalisation mismatch**. It happens whenever two
> different systems (a proxy/WAF/gateway and the actual app server) parse the
> same URL differently. Whoever does the LEAST normalisation is usually the
> one that gets bypassed.

---

### #06 — Method-based access control can be circumvented

**URL:** https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented
**Vulnerability:** Access control checks only the HTTP method, not the underlying action
**Aim:** Use a different HTTP method to perform an admin action as a non-admin user

**Background:**
The admin panel correctly blocks a regular user from `POST`ing to the
role-upgrade endpoint (`401 Unauthorized`). But the application is built on a
framework that still routes other HTTP methods (like `GET`) to the SAME
underlying handler — and the access check was only applied to the `POST` case.

**Analysis:**
```
POST /admin-roles
action=upgrade&username=wiener
(as wiener, non-admin)
→ 401 Unauthorized

GET /admin-roles?action=upgrade&username=wiener
(as wiener, non-admin)
→ 200 OK — role upgraded!
```

**Steps:**
1. As admin, observe the role-upgrade request (likely `POST /admin-roles`)
2. As `wiener`, replay the same `POST` → confirm `401`
3. In Repeater, right-click → **Change request method** → convert to `GET`
   with the same parameters in the query string
4. Send → confirm `200 OK` → role upgraded

> 📝 Many web frameworks map a URL path to a handler function regardless of
> HTTP method, unless the developer explicitly restricts which methods that
> route accepts. If the access-control middleware only runs for specific
> methods (a common but flawed shortcut), switching methods skips it entirely.

---

### #07 — User ID controlled by request parameter

**URL:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter
**Vulnerability:** Account page reads a user ID straight from a URL parameter, no ownership check
**Aim:** Find and submit `carlos`'s API key

**Background:**
The simplest, most direct IDOR. Your own account page is:
`/my-account?id=wiener`. The server has no check confirming the LOGGED-IN
user actually owns the `id` being requested.

**Analysis:**
```
GET /my-account?id=wiener   (logged in as wiener)
→ 200 OK — your own account, API key shown

GET /my-account?id=carlos   (still logged in as wiener)
→ 200 OK — carlos's account, INCLUDING HIS API key
```

**Steps:**
1. Log in as `wiener:peter`
2. Note the `id=wiener` parameter on `/my-account`
3. Change it to `id=carlos`
4. Read carlos's API key directly from the page

> 📝 This is THE canonical IDOR — there's no obfuscation, no encoding, just a
> raw value the server should have validated against the session but didn't.
> If you remember nothing else about IDOR, remember this lab.

---

### #08 — User ID controlled by request parameter, with unpredictable user IDs

**URL:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-id
**Vulnerability:** Same IDOR as Lab 07, but the ID is a GUID instead of a username — except the GUID leaks elsewhere
**Aim:** Find carlos's GUID, then access his account and submit his API key

**Background:**
The developer "fixed" the previous lab's predictability problem by switching
to GUIDs (e.g. `7b...-...-...`) instead of plain usernames. This SEEMS safer —
you can't just guess `carlos`. But the ownership check is STILL missing, and
the GUID is disclosed elsewhere in the app (commonly: blog post authorship,
comments, or a user listing endpoint).

**Analysis:**
```
GET /my-account?id=7b69d2b4-...   (your own GUID — works fine)

Find carlos's GUID:
  Browse blog posts → carlos has commented/authored a post
  GET /blogs?userId=a62ef538-3744-46cd-813f-3355c5ae6d55   ← his GUID leaks here

GET /my-account?id=a62ef538-3744-46cd-813f-3355c5ae6d55
→ 200 OK — carlos's account, API key exposed
```

**Steps:**
1. Browse the blog/comments section, find a post or comment by `carlos`
2. Note the `userId` GUID associated with his content
3. Substitute that GUID into `/my-account?id=`
4. Submit his API key

> 📝 Unpredictability is not the same as access control. A GUID stops casual
> guessing but does nothing if the value is exposed ANYWHERE else in the app —
> comments, profile links, API responses, even error messages. Always check
> if a "random" identifier appears somewhere a user can browse to.

---

### #09 — User ID controlled by request parameter with data leakage in redirect

**URL:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect
**Vulnerability:** The access check correctly redirects unauthorized users — but the redirect response BODY still contains the sensitive data
**Aim:** Find and submit carlos's API key, despite the access control appearing to work

**Background:**
This one looks "fixed" at first glance: requesting `?id=carlos` as `wiener`
results in a redirect (e.g. `302 → /my-account`) instead of showing the page.
But if you inspect the FULL raw response (not just where the browser
navigates to), the redirect response body STILL contains carlos's account
HTML — the server built the page, then decided to redirect, but already sent
the data.

**Analysis:**
```
GET /my-account?id=carlos   (as wiener)
→ HTTP/1.1 302 Found
   Location: /my-account
   <!-- but the response BODY still contains: -->
   <p>API Key: carlos_actual_api_key_here</p>
```

A browser would just follow the redirect and never show you the body — you
need to inspect the raw HTTP response (Burp Repeater shows this directly).

**Steps:**
1. Request `/my-account?id=carlos` as `wiener` in Burp Repeater
2. Look at the FULL raw response, not just the status code
3. The API key is sitting right there in the body of the 302 response
4. Submit it

> 📝 This is an important lesson: a redirect is not the same as "no data was
> sent." The server-side logic likely rendered the page, found the API key,
> embedded it, and only THEN decided "actually, redirect this user." The data
> already left the server. Always inspect full responses in a proxy — never
> trust what the browser chooses to render.

---

### #10 — User ID controlled by request parameter with password disclosure

**URL:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure
**Vulnerability:** Account page pre-fills a password field with the real (masked) password value in the HTML
**Aim:** Access the administrator's account page and find their actual password

**Background:**
The account page includes a password change form. For UX convenience, the
form pre-fills the current password into the input field's `value` attribute
— masked visually with `type="password"`, but the RAW value is still sitting
in the HTML source.

Combined with the same IDOR as Lab 07 (`?id=`), you can load the
administrator's account page and read their actual password straight out of
the page source.

**Analysis:**
```
GET /my-account?id=administrator
→ 200 OK
   <input type="password" value="actual_admin_password_here">
   ↑ Looks masked in the rendered page (dots), but View Source shows it plainly
```

**Steps:**
1. Request `/my-account?id=administrator`
2. View page source (Ctrl+U) — find the password input's `value` attribute
3. Copy the password
4. Log in as `administrator` using the disclosed password

> 📝 `type="password"` only masks the value VISUALLY in the rendered browser
> UI — it does absolutely nothing to protect the value in the underlying HTML.
> Anyone who views source, intercepts the response, or runs simple JS can read
> it. Never pre-fill a real secret into any form field, masked or not.

---

### #11 — Insecure direct object references

**URL:** https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references
**Vulnerability:** Chat transcripts are stored as sequentially-named static files with no ownership check
**Aim:** Find carlos's password via a leaked chat transcript

**Background:**
The live chat feature saves transcripts to disk with predictable, incrementing
filenames (`1.txt`, `2.txt`, `3.txt`...). Your own transcript download link
references one of these files directly — and nothing stops you from changing
the number to access someone else's transcript.

**Analysis:**
```
Send a chat message → "View transcript" link appears:
  GET /download-transcript/12.txt   ← your transcript

Try other numbers:
  GET /download-transcript/1.txt
  GET /download-transcript/2.txt
  ...
  → One of these belongs to carlos and contains:
    "You: Ok so my password is ssicu9unbdutm328j85t. Is that right?"
```

**Steps:**
1. Use the live chat, send any message, get your own transcript link
2. Note the numeric filename pattern
3. Iterate through lower numbers (earlier transcripts)
4. Find carlos's transcript containing his password
5. Log in as carlos

> 📝 This is IDOR applied to FILES rather than database records or URL
> parameters — same underlying flaw, different storage mechanism. Any time an
> app uses a predictable filename or path to store user-specific files
> (transcripts, invoices, exports, uploads), check whether ownership is
> actually verified before serving the file.

---

### #12 — Multi-step process with no access control on one step

**URL:** https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step
**Vulnerability:** The role-upgrade flow has 2 steps; only step 1 checks admin permissions
**Aim:** Upgrade your own account to admin by skipping straight to step 2

**Background:**
The role upgrade feature works in two stages:
1. `POST /admin-roles` with `action=upgrade&username=X` → shows a confirmation prompt (THIS step checks if you're an admin)
2. `POST /admin-roles` with `action=upgrade&confirmed=true&username=X` → actually performs the upgrade

The developer correctly checks admin permission on step 1 — but forgot to
re-check it on step 2, assuming a user could only reach step 2 BY GOING
THROUGH step 1 first. That assumption is wrong; nothing stops you from sending
step 2's request directly.

**Analysis:**
```
As admin, the full flow:
  POST /admin-roles
  action=upgrade&username=wiener
  → 200 OK, shows "Are you sure?" confirmation

  POST /admin-roles
  action=upgrade&confirmed=true&username=wiener
  → 200 OK, wiener is now an admin

As wiener (non-admin), trying step 1:
  POST /admin-roles
  action=upgrade&username=wiener
  → 401 Unauthorized   (correctly blocked)

As wiener, skipping straight to step 2:
  POST /admin-roles
  action=upgrade&confirmed=true&username=wiener
  → 200 OK — upgraded anyway! Step 2 never checked permissions.
```

**Steps:**
1. Log in as admin, walk through the role-upgrade flow once, capture BOTH requests in Burp
2. Log in as `wiener`, confirm step 1 alone is blocked
3. Send step 2's request directly (with `confirmed=true`) using your own session
4. Confirm your own account is now admin

> 📝 This is a textbook **context-dependent access control** failure. The
> developer protected the entry point of a workflow but assumed later steps
> were unreachable without it — a dangerous assumption in HTTP, where every
> request is independent and nothing enforces "you must have come from step 1."
> Each step in a multi-step process needs its OWN access check.

---

### #13 — Referer-based access control

**URL:** https://portswigger.net/web-security/access-control/lab-referer-based-access-control
**Vulnerability:** Admin functionality is gated by checking the `Referer` header instead of verifying the session's actual role
**Aim:** Use the forgeable Referer header to promote yourself to admin

**Background:**
The role-upgrade endpoint checks whether the request's `Referer` header points
to `/admin` — the assumption being "only someone who was just ON the admin
page would be making this request." But the Referer header is just something
the CLIENT sends; there's nothing stopping you from setting it to whatever
you want.

**Analysis:**
```
As admin, the role-upgrade request includes:
  GET /admin-roles?username=wiener&action=upgrade
  Referer: https://TARGET/admin
  → 200 OK, role upgraded

As wiener (non-admin), same request but with the browser's NATURAL Referer
(e.g. /my-account):
  GET /admin-roles?username=wiener&action=upgrade
  Referer: https://TARGET/my-account
  → 401 Unauthorized — blocked because Referer doesn't match /admin

Forge the Referer header in Burp Repeater:
  GET /admin-roles?username=wiener&action=upgrade
  Referer: https://TARGET/admin          ← manually set, even though you never visited /admin
  → 200 OK — upgraded! The server trusted a header the client fully controls.
```

**Steps:**
1. As admin, capture the role-upgrade request and note the `Referer` value it carries
2. As `wiener`, send the same request in Burp Repeater
3. Manually edit the `Referer` header to match the expected admin page URL
4. Send → confirm role upgrade succeeds despite never having visited `/admin`

> 📝 The Referer header is fundamentally a CLIENT-SUPPLIED value — like a
> cookie or any other request header, it's just text the browser sends, and a
> proxy like Burp (or `requests` in Python) can set it to literally anything.
> Using it as a security control is equivalent to asking someone "are you an
> admin?" and trusting whatever they answer.

---

## REFERENCE — ACCESS CONTROL VULNERABILITY QUICK MAP

| Lab pattern | What's broken | Fix |
|---|---|---|
| Unprotected admin path | No check at all | Server-side role check on every request |
| Hidden but unprotected path | Obscurity mistaken for security | Same — explicit role check, not a hard-to-guess URL |
| Role in client-controlled cookie | Trusting client state for authorization | Derive role server-side from the session, never from client input |
| Role editable via hidden form field | Trusting client input blindly | Strip/ignore any client-submitted role/permission fields |
| Proxy/backend path mismatch | Two systems disagree on URL meaning | Normalise paths identically across all layers, deny by default |
| Method-only access check | Check tied to HTTP verb, not the action | Apply the SAME check regardless of HTTP method |
| ID directly trusted (IDOR) | No ownership verification | Check: does THIS session own THIS resource? |
| GUID "security" | Unpredictability mistaken for access control | Same — GUIDs reduce guessing, not bypass-by-leak |
| Sensitive data in redirect body | Data sent before the redirect decision | Don't render sensitive data until AFTER the access check passes |
| Password pre-filled in HTML | Secret value exposed in markup, just visually masked | Never embed real secrets in HTML, masked or not |
| Predictable file naming (IDOR on files) | No per-file ownership check | Map files to users server-side; verify ownership before serving |
| Multi-step check only on step 1 | Assuming earlier steps are mandatory gatekeepers | Re-verify permissions on EVERY step independently |
| Referer-based authorization | Trusting a fully client-controlled header | Never use Referer for security decisions |

---

## REFERENCE — DEFENCE PRINCIPLES (HOW TO FIX WHAT YOU JUST BROKE)

1. **Deny by default** — access should be explicitly granted, never implicitly assumed
2. **Enforce server-side, every time** — never trust a role, ID, or permission value sent by the client
3. **One consistent mechanism** — apply the same access-control logic across the whole app, not ad-hoc checks per page
4. **Check on every request** — not just "step 1" of a flow, not just for one HTTP method
5. **Never rely on obscurity** — hidden URLs, GUIDs, and unlisted paths are not access control
6. **Log and alert on access control failures** — repeated 401/403s from one session is a strong signal of probing
