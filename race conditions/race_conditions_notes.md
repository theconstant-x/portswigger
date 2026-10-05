# Race Conditions Notes — PortSwigger Web Security Academy

---

## WHAT IS A RACE CONDITION?

A race condition occurs when a web application processes multiple
requests CONCURRENTLY without adequate safeguards, allowing two or more
threads to interact with the same data at the same time — resulting in
unintended behavior. This "collision" happens because the app checks a
condition (e.g. "has this coupon been used?"), and then acts on that
check (e.g. "apply the discount"), with a gap in between where another
identical request can sneak in and see the SAME stale, pre-check state.

```
Thread A: check "coupon used?" → NO → apply discount → mark coupon as used
Thread B: check "coupon used?" → NO  (A hasn't marked it yet!) → apply discount too

Result: the discount is applied TWICE, even though the code correctly
        checked "has this been used" every single time.
```

> 📝 This is closely related to Business Logic vulnerabilities — the code
> is often not "wrong" in any single-threaded sense. Read the logic
> top-to-bottom and it looks completely correct. The vulnerability only
> exists in the GAP between a check and the action that follows it, which
> is invisible unless you're specifically thinking about concurrency.

The window during which a collision is possible is called the **race
window**. Race windows can be as generous as several seconds or as brutal
as a few milliseconds — the narrower the window, the more precisely
timed your requests need to be to land inside it.

---

## THE CORE TECHNIQUE: SENDING REQUESTS IN PARALLEL

To exploit a race condition, you need multiple identical (or related)
requests to arrive at the server and be PROCESSED essentially
simultaneously — landing inside the same race window.

### The problem with "just send requests fast"

Simply firing off several HTTP requests one after another isn't good
enough. Standard sequential requests (even sent quickly) are subject to
**network jitter** — small, unpredictable delays introduced by DNS
resolution, TCP handshakes, TLS negotiation, and routing — that can
easily be LARGER than the race window itself. Two requests sent
"quickly" might still land tens of milliseconds apart, comfortably
missing a five-millisecond window.

### Burp's solution: the single-packet attack

Modern Burp Suite exploits **HTTP/2's multiplexing** capability to place
MULTIPLE complete HTTP requests inside a single TCP packet, then release
them all at once. Because they share ONE packet, there's no network
jitter between them at all — the server receives all requests at
virtually the exact same instant.

```
Burp Repeater: select multiple tabs/requests → right-click →
"Send group in parallel (single-packet attack)"
```

> 📝 This technique was directly inspired by academic research on
> "Timeless Timing Attacks" (USENIX 2020) — the insight that HTTP/2
> allows genuinely concurrent request delivery over a single connection,
> something HTTP/1.1 cannot do (it forces sequential processing per
> connection). This is why solving several of these labs explicitly
> requires a modern Burp Suite version with single-packet attack support.

### Connection warming

Even with single-packet delivery, the VERY FIRST request on a fresh
connection is often slower than subsequent ones (TLS handshake overhead,
connection setup). Sending a throwaway "warm-up" request over the same
connection first, before the real race attempt, reduces this outlier
delay for your actual attack requests.

### When Burp Pro's "Trigger race condition" isn't available

Burp Community Edition lacks the one-click "Trigger race condition"
custom action available in Pro. The manual equivalent: select multiple
request tabs in Repeater, group them, and use "Send group in parallel
(single-packet attack)" — this feature IS available in Community
Edition as of recent versions.

---

## SESSION-BASED LOCKING — A COMMON OBSTACLE

Some frameworks defend against accidental data corruption using a form
of REQUEST LOCKING. PHP's native session handler is a classic example —
if you send PHP two requests using the SAME session token at the same
time, the server processes them ONE AT A TIME, not concurrently, because
PHP's session module locks the session file for the duration of each
request.

**Why this matters:** if all your race-condition requests are being
processed strictly sequentially despite being sent in parallel, this
kind of locking may be the reason — and it can mask an otherwise
genuinely exploitable vulnerability.

**The bypass:** if you notice serialized (non-concurrent) processing,
try sending each request using a DIFFERENT session token that's
otherwise still valid for the same underlying account/data — this can
sidestep session-level locking while still targeting the same shared
resource.

---

## CATEGORIES OF RACE CONDITION ATTACKS

### 1. Limit overrun
The classic case: exceeding some limit the business logic imposes —
using a one-time discount code multiple times, redeeming a gift card
more than once, submitting more votes than allowed. Send many identical
requests in parallel; if the limit-check-then-apply logic isn't atomic,
several will succeed when only one should have.

### 2. Bypassing rate limits
Rate limiters typically count requests SEQUENTIALLY as they complete,
incrementing a counter after each one. If many requests are submitted
in the SAME race window, the rate limiter may not have finished
incrementing its counter for earlier requests before later ones are
already past the check — letting far more attempts through than the
limit should allow. This is a powerful technique against login
brute-force protections specifically.

### 3. Multi-endpoint race conditions
Race conditions aren't limited to a SINGLE endpoint. Two or more
DIFFERENT endpoints that operate on the SAME underlying record (e.g. a
payment-validation endpoint and an order-checkout endpoint) can collide
if their operations aren't properly synchronized against each other.

### 4. Single-endpoint race conditions with different parameter values
Sending PARALLEL requests to the SAME endpoint but with DIFFERENT
parameter values can trigger a collision where data from one request
gets mixed into the processing of another — e.g. one request's
generated token ends up being associated with a completely different
request's target user.

### 5. Exploiting time-sensitive vulnerabilities (no classic race condition needed)
Sometimes you won't find a genuine race condition in the traditional
sense — but the SAME precise-timing techniques reveal a DIFFERENT class
of flaw: security tokens generated from a HIGH-RESOLUTION TIMESTAMP
instead of a cryptographically secure random value. If two requests can
be timed to land within the same timestamp "tick," they may receive the
IDENTICAL token — letting you steal a token intended for someone else
simply by triggering your own request at the right moment.

### 6. Partial construction race conditions
Many multi-step object-creation workflows (like user registration with
email verification) have a brief TEMPORARY MIDDLE STATE where the object
exists but isn't fully "complete" yet. If you can interact with the
object DURING that partial-construction window — before the final
verification/completion step would normally occur — you may be able to
skip requirements that were only meant to be enforced at that final step.

---

## HIDDEN SUB-STATES — GOING BEYOND SIMPLE LIMIT OVERRUNS

A single HTTP request can internally transition an application through
several invisible SUB-STATES before the response is returned — entering
and exiting states the client never directly sees. If you can identify
requests that interact with the SAME underlying data, you can sometimes
abuse these hidden sub-states to expose time-sensitive variations of
classic logic flaws.

**Example — racing a 2FA bypass:** rather than the classic "complete
step 1, then forced-browse past step 2" MFA bypass, a race variant sends
the step-1 credentials request MANY times in parallel. If the session
briefly enters a "logged in, MFA not yet enforced" sub-state before the
MFA requirement is fully applied, a parallel request racing into that
window might complete an authenticated action before MFA was ever
checked.

### A practical methodology for finding sub-state races (from PortSwigger's research)
1. Map the target site normally, noting every endpoint
2. For each candidate endpoint, ask: **is this security-critical?** —
   most endpoints aren't worth testing
3. Ask: **is there collision potential?** — do two or more requests
   plausibly touch the SAME underlying record?
4. Test with the single-packet attack, watching for behavioral
   differences vs. sequential (one-at-a-time) requests

---

## RACE CONDITIONS TESTING SOP

### Step 1 — Identify candidate endpoints
Focus on anything security-critical with a plausible collision target:
discount/coupon application, balance/credit changes, login attempts,
password resets, account creation/verification, item purchasing.

### Step 2 — Establish a baseline
Send the SAME request sequence one-at-a-time (normally) first, to
understand expected, correct behavior before attempting to break it.

### Step 3 — Check for collision potential
Does the endpoint operate on data tied to your session/account? Would
two simultaneous copies of this request plausibly touch the same
record? If removing your session cookie changes behavior significantly
(e.g. "empty cart" vs "your cart"), that confirms server-side,
session-keyed state — a strong signal of collision potential.

### Step 4 — Send requests in parallel
Use Burp's "Send group in parallel (single-packet attack)" on multiple
identical (or related) requests. Start with request COUNT reasonably
high (10-20) to maximise the chance of landing inside the race window.

### Step 5 — Watch for session-based locking
If parallel requests appear to complete strictly sequentially, try
using different (but still valid) session tokens for each request to
rule out request-locking masking the vulnerability.

### Step 6 — For narrow windows, escalate tooling
If single-packet attacks in Repeater aren't landing hits reliably,
move to **Turbo Intruder** — it offers finer control over timing via its
`gate`/`openGate` mechanism and can queue far more requests than
Repeater's grouped tabs comfortably support.

### Step 7 — Confirm and exploit
Once a collision is confirmed, work out the maximum achievable impact —
how many times can the limit be overrun, how much value can be
extracted, what escalation does the collision enable.

---

## QUICK BURP WORKFLOW

1. Map the target normally, identify security-critical endpoints with
   collision potential
2. Send a candidate request to **Repeater**, duplicate the tab several
   times (Ctrl+R repeatedly, or drag-duplicate)
3. Select all the duplicate tabs → right-click → **group tabs** → then
   right-click the group → **Send group in parallel (single-packet
   attack)**
4. Compare against **Send group in sequence** to establish what
   "normal" (non-racing) behavior looks like for contrast
5. If session locking masks results, regenerate a fresh session token
   for each request in the group before sending
6. For extremely narrow windows or high-volume attacks (e.g. brute-force
   via rate-limit bypass), switch to the **Turbo Intruder** extension
   (BApp Store) using its `gate`/`openGate` request-queueing mechanism
7. For Burp Pro users: right-click a request → **Trigger race condition**
   custom action automatically fires it 20 times in parallel — the
   fastest path for a simple limit-overrun test

> 📝 **"Send group in parallel (single-packet attack)"** is the single
> most important tool introduced by this module. Every other technique
> — Turbo Intruder scripting, connection warming, session token rotation
> — exists to handle cases where the basic single-packet attack alone
> isn't quite enough (narrower windows, higher request volumes, or
> masking locking behavior).

---
---

## PORTSWIGGER LABS

---

### #01 — Limit overrun race conditions

**URL:** https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun
**Vulnerability:** A one-time discount code can be applied to the SAME order multiple times if the "has this code been used" check and "apply the discount" action aren't atomic
**Aim:** Successfully purchase the "Lightweight l33t Leather Jacket" using the resulting stacked discount

**Background:**
Applying the `PROMO20` discount code once gives 20% off — nowhere near
enough to afford the jacket on the available store credit. But the
apply-coupon endpoint checks whether the code was already used, THEN
applies the discount — two separate steps with a gap between them.

**Analysis:**
```
Normal (sequential): apply PROMO20 → 20% off → apply PROMO20 again → rejected (already used)

Race attack: send the SAME "apply PROMO20" POST request 20 times in
parallel using "Send group in parallel (single-packet attack)"

→ Multiple copies of the request each check "has PROMO20 been used?"
  before ANY of them have finished marking it as used
→ Several of them succeed, each independently applying the 20% discount
→ The discount effectively STACKS (e.g. 20% × several successful
  applications), driving the order total down far more than intended
```

**Steps:**
1. Log in as `wiener:peter`, add a cheap item, apply `PROMO20` once,
   capture the `POST /cart/coupon` request
2. Send it to Repeater, duplicate the tab ~20 times
3. Group the tabs, select **Send group in parallel (single-packet attack)**
4. Refresh the cart — confirm the discount was applied more than once
5. Remove the discounts and cheap item, add the leather jacket instead
6. Re-apply the coupon race attack against the jacket in the cart
7. If the total is still too high, repeat; once affordable, checkout

> 📝 This is the canonical, simplest race condition — a single endpoint,
> a single check-then-act gap, exploited by simply flooding it with
> parallel copies of the exact same request.

---

### #02 — Bypassing rate limits via race conditions

**URL:** https://portswigger.net/web-security/race-conditions/lab-race-conditions-bypassing-rate-limits
**Vulnerability:** The login rate limiter locks out an account after 3 failed attempts — but the lockout counter isn't incremented atomically, so many parallel attempts can all be checked BEFORE any of them register as a "failure"
**Aim:** Brute-force `carlos`'s password from a provided wordlist, then delete `carlos` via the admin panel

**Background:**
Sequential login attempts correctly lock out after 3 failures. But
submitting many login attempts in the SAME race window means the
rate-limiter's "have they failed 3 times yet?" check runs for all of
them essentially simultaneously — before any single failure has been
recorded — letting far more than 3 real password attempts through in
one burst.

**Analysis:**
```
Normal: 3 sequential wrong passwords → 4th attempt → "60 second lockout"

Race attack: submit the ENTIRE candidate password list as parallel
requests in one single-packet burst

→ The lockout counter can't keep up with genuinely concurrent requests
→ EVERY password in the burst gets checked against the real password,
  not just the first 3
→ If the correct password is anywhere in the wordlist, it succeeds —
  visible as a 302 redirect (successful login) amid the flood of 200s
  (failed attempts)
```

**Steps:**
1. Capture the `POST /login` request for `carlos` with any wrong password
2. Send to Repeater, right-click → **Send to Turbo Intruder** (or build
   a group of ~20-40 duplicate tabs, one per candidate password, for a
   pure-Repeater approach)
3. In Turbo Intruder, use the provided password wordlist as the
   `%s` payload position, with a script using the `gate` mechanism to
   release all requests simultaneously
4. Identify the one response with a 302 status (successful login) —
   that password is correct
5. Log in as `carlos` with the identified password, delete `carlos` via
   the admin panel

> 📝 This lab demonstrates that a race condition doesn't need to defeat
> the TARGET action's own logic — here, we're not making the login check
> itself lie, we're defeating the RATE LIMITER protecting it. The login
> logic is completely correct; the ANTI-BRUTE-FORCE mechanism is what has
> the race condition.

---

### #03 — Multi-endpoint race conditions

**URL:** https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint
**Vulnerability:** Redeeming a gift card and completing a checkout both touch the same store-credit balance, but via DIFFERENT endpoints that don't synchronize against each other
**Aim:** Successfully purchase the "Lightweight l33t Leather Jacket" despite insufficient funds

**Background:**
Buying a $10 gift card, then redeeming it, adds $10 credit — a
single-endpoint action with no obvious race potential on its own. But
the checkout process (validating payment, THEN confirming the order) is
a SEPARATE endpoint that also reads/writes the same credit balance.
Racing a gift-card redemption against a checkout can create a window
where the checkout's payment validation passes against a STALE
(higher) balance that a concurrent redemption hasn't actually
finalized yet.

**Analysis:**
```
Setup: cart contains the leather jacket (unaffordable alone);
        also purchase and hold a gift card ready to redeem

Race: send the "redeem gift card" request AND the "checkout" request
      in the SAME parallel single-packet burst

→ The checkout's balance-sufficiency check may run against balance
  state from BEFORE the gift card redemption fully completes, OR the
  redemption may complete in a way that briefly double-counts credit
→ If timed correctly, checkout validates successfully against credit
  that either hasn't been deducted yet or has been counted twice
→ Jacket is purchased despite insufficient real funds
```

**Steps:**
1. Log in, buy a gift card first (to have something to redeem for credit)
2. Add the leather jacket to the cart
3. Identify the exact endpoints involved: `POST /gift-card` (redemption)
   and `POST /cart/checkout` (order finalisation)
4. "Warm" the connection by sending all three requests (a throwaway,
   the redemption, the checkout) in sequence over ONE connection first
5. Group the redemption and checkout requests, send as a single-packet
   parallel attack
6. Check whether the order succeeded despite insufficient standalone credit

> 📝 Multi-endpoint races are harder to find than single-endpoint ones
> because the vulnerability doesn't live in any ONE request's logic —
> it's in the RELATIONSHIP between two separate code paths that happen
> to share underlying data. Always ask: "what ELSE touches this same
> record?" not just "does THIS endpoint have a race condition?"

---

### #04 — Single-endpoint race conditions

**URL:** https://portswigger.net/web-security/race-conditions/lab-race-conditions-single-endpoint
**Vulnerability:** The email-change confirmation flow stores state in the session in a way that parallel requests with DIFFERENT email values can cause a mismatch — the confirmation TOKEN generated for one address ends up validating a DIFFERENT address
**Aim:** Claim the `carlos@ginandjuice.shop` email address (which has a pending admin invite) to inherit admin privileges, then delete `carlos`

**Background:**
Changing your email triggers a confirmation email containing a token.
The session likely stores something like `session['pending-email'] = X`
and `session['confirm-token'] = Y` as two SEPARATE writes. Racing two
parallel change-email requests — one for a throwaway address, one for
`carlos@ginandjuice.shop` — can interleave these writes such that the
FINAL session state ends up with `pending-email = carlos@ginandjuice.shop`
paired with a token that was actually generated (and emailed) for the
OTHER, throwaway address.

**Analysis:**
```
Request A: email = test1@exploit-<ID>.exploit-server.net
Request B: email = carlos@ginandjuice.shop

Send both in parallel (single-packet attack). Possible interleaving:
  session['pending-email'] = test1@...      (A writes first)
  session['confirm-token'] = TOKEN_A         (A writes its token)
  session['pending-email'] = carlos@...      (B overwrites with its email)
  session['confirm-token'] = TOKEN_A         (B's token write hasn't
                                               landed yet, OR collides)

Final state: pending-email = carlos@ginandjuice.shop
             confirm-token = TOKEN_A (received in the test1@... inbox)

→ Check the exploit-server email client: if the confirmation email's
  BODY references carlos@ginandjuice.shop instead of your own test
  address, the collision worked — click that link to confirm the email
  change to carlos's address using YOUR received token
```

**Steps:**
1. Log in, attempt to change email to `anything@exploit-<ID>.exploit-server.net`
   to confirm the mechanism and check the email client for the
   confirmation format
2. Capture the `POST /my-account/change-email` request, create ~5 tabs
   in Repeater, each with a slightly different email local-part
   (`test1@...`, `test2@...`, etc.) and ONE tab set to
   `carlos@ginandjuice.shop`
3. Group and send in parallel (single-packet attack)
4. Check the exploit-server email client — look for a confirmation
   email whose BODY references `carlos@ginandjuice.shop` but which was
   delivered to one of YOUR OWN test addresses
5. If found, click that confirmation link — your account's email is now
   `carlos@ginandjuice.shop`
6. Refresh your account page — an admin panel link should now appear
   (the pending admin invite was tied to that email address)
7. Access the admin panel, delete `carlos`

> 📝 This is a genuinely subtle collision — you're not overrunning a
> limit, you're exploiting how MULTIPLE writes to session state, spread
> across a request's processing, can interleave with a DIFFERENT parallel
> request's writes. Repeat the parallel send several times if the first
> attempt doesn't produce the desired mismatch — the exact interleaving
> that occurs isn't fully deterministic.

---

### #05 — Exploiting time-sensitive vulnerabilities

**URL:** https://portswigger.net/web-security/race-conditions/lab-race-conditions-exploiting-time-sensitive-vulnerabilities
**Vulnerability:** Password reset tokens are generated using a HIGH-RESOLUTION TIMESTAMP instead of a cryptographically secure random value — two requests timed to generate their tokens within the same instant receive the IDENTICAL token
**Aim:** Obtain a valid password reset token for `carlos`, log in as him, delete `carlos`

**Background:**
This lab contains NO classic race condition in the traditional
check-then-act sense. Instead, the password reset TOKEN itself is weak:
it appears to be derived from a timestamp (confirmed by recognising the
token's format, e.g. via a hash-identifying tool). If you can trigger a
password reset for YOUR OWN account and for `carlos`'s account at
EXACTLY the same moment, both tokens may be generated from the identical
timestamp — meaning your own (known) token is ALSO valid for `carlos`.

**Analysis:**
```
Trigger a password reset for your own account → receive token_yours
Identify the token's likely composition (e.g. hash of a timestamp +
  username, confirmed via a hash-identifying tool like `hashid`)

Race: send TWO parallel password reset requests in the SAME single-packet
      burst — one for your own username, one for carlos

→ If both requests are processed within the same timestamp "tick" (the
  resolution of whatever clock source generates the token), the
  resulting tokens will be IDENTICAL — because the only "randomness"
  in the token generation was time-based, and both requests shared
  the same timestamp
→ Your own reset email now contains a token that ALSO validates for
  carlos's account, because his token generation collided with yours
```

**Steps:**
1. Trigger a password reset for `wiener`, inspect the resulting token —
   identify its format/algorithm (e.g. via `hashid` on the token string)
2. Confirm (or hypothesize) that the token derivation includes a
   high-resolution timestamp rather than a secure random value
3. Craft two parallel `POST /forgot-password` requests — one for
   `wiener`, one for `carlos` — using the single-packet attack
4. Check your own email client for the reset token received for `wiener`
5. Attempt to use THAT SAME token against `carlos`'s reset flow:
   `POST /forgot-password` with `username=carlos&temp-forgot-password-token=<wiener's token>`
6. If it validates, set a new password for `carlos`, log in, delete `carlos`

> 📝 This lab is included specifically to broaden your definition of
> "race condition techniques" — the PRECISE TIMING skill you've built up
> across this module is useful even when there's no genuine
> check-then-act collision to exploit. Weak, timestamp-derived
> "randomness" is a broken CRYPTOGRAPHIC assumption, uncovered using
> the exact same tooling (parallel, precisely-timed requests) as a
> classic race condition attack.

---

### #06 — Partial construction race conditions

**URL:** https://portswigger.net/web-security/race-conditions/lab-race-conditions-partial-construction
**Vulnerability:** User registration requires email confirmation via a token — but there's a brief window between account creation and the confirmation requirement being fully enforced, during which an EMPTY token parameter (normally rejected) may briefly be accepted
**Aim:** Register an account using an email address you don't own by exploiting the partial-construction window, then log in and delete `carlos`

**Background:**
Registration only allows `@ginandjuice.shop` addresses, and you don't
control any real mailbox on that domain — so you can't complete the
normal "click the confirmation link" flow. Testing the confirmation
endpoint directly reveals THREE distinct behaviors: an arbitrary token
→ "Incorrect token" error; a MISSING token parameter →
"Missing parameter" error; an EMPTY token parameter → "Forbidden" (this
looks like a deliberately patched case). The "Forbidden" response
suggests the empty-token bypass USED to work and was patched — but the
patch may only apply AFTER a brief partial-construction window during
account creation completes.

**Analysis:**
```
POST /confirm?token=randomvalue    → "Incorrect token: randomvalue"
POST /confirm  (no token param)    → "Missing parameter: token"
POST /confirm?token=               → "Forbidden"   (patched — but maybe
                                                       only after full
                                                       construction?)

Race: submit registration (POST /register with a target email) AND the
      empty-token confirmation request (POST /confirm?token=) in the
      SAME parallel single-packet burst, repeated many times /
      experimented with different relative orderings

→ If the confirmation endpoint's "reject empty tokens" check is only
  enforced AFTER some other part of account construction finishes, a
  confirmation request landing DURING that partial-construction window
  (before the check is fully "live" for this specific new account) may
  succeed despite using an empty token
→ Registration completes for an email address you never verified
  ownership of
```

**Steps:**
1. Study `/confirm`'s behavior with an arbitrary token, no token, and
   an empty token parameter — note the three distinct responses
2. Attempt registration with a target email under `@ginandjuice.shop`
   you don't control (or one useful for privilege escalation)
3. In Burp Repeater, prepare the `POST /register` request AND a
   `POST /confirm?token=` (empty) request as a synchronised group
4. Send them in parallel using the single-packet attack — this needs
   EXPERIMENTATION, as the exact relative timing/ordering that lines up
   the partial-construction window may require several attempts and
   possibly the Turbo Intruder `gate` mechanism for finer control
5. If successful, the account is registered without genuine email
   verification — log in with it
6. Delete `carlos` (or otherwise use the account's granted access,
   depending on the specific lab variant)

> 📝 This is consistently rated the hardest lab in this module —
> PortSwigger's own lab description explicitly warns "you may need to
> experiment with different ways of lining up the race window." Partial
> construction races require you to think about a MULTI-STEP internal
> process (not visible from the outside) and find the exact moment a
> security check ISN'T YET fully active during that process — a genuinely
> harder target than a simple, stable check-then-act gap.

---

## REFERENCE — RACE CONDITIONS QUICK MAP

| Lab pattern | Root cause | Fix |
|---|---|---|
| Limit overrun | Check-then-act gap around a single-use resource | Make the check-and-apply operation atomic (e.g. a single database transaction with proper locking) |
| Rate limit bypass | Lockout counter incremented non-atomically across concurrent requests | Use atomic counter increments; consider queueing/serializing security-critical checks |
| Multi-endpoint collision | Two endpoints share underlying data with no synchronization between them | Identify all endpoints touching the same record; apply consistent locking across ALL of them, not just one |
| Single-endpoint parameter collision | Multiple session-state writes within one request aren't atomic relative to a parallel request's writes | Treat all state associated with one logical operation as a single atomic unit |
| Time-sensitive token weakness | Token derived from a predictable/low-entropy timestamp instead of secure randomness | Use a cryptographically secure random number generator for all security tokens |
| Partial construction | A security check isn't active during part of a multi-step creation process | Ensure ALL security checks are enforced consistently throughout every stage of object construction, with no "not yet checking" window |

---

## REFERENCE — DEFENCE PRINCIPLES

1. **Make check-then-act sequences atomic** — use database transactions,
   row-level locking, or equivalent mechanisms so that a "check" and its
   corresponding "act" cannot be interleaved by a concurrent request
2. **Avoid mixing data from different storage locations** for the same
   logical operation — split writes create windows for interleaving
3. **Ensure state changes are atomic using your datastore's own
   concurrency features** — most modern databases provide exactly this
   (transactions, optimistic/pessimistic locking) specifically to solve
   this class of problem
4. **Never derive security tokens from timestamps or other predictable
   sources** — always use a cryptographically secure random number
   generator
5. **Apply security checks consistently across an ENTIRE multi-step
   process** — not just at the final, externally-visible step; hidden
   sub-states need the same rigor as the obvious ones
6. **Consider rate-limiting and locking mechanisms as part of your
   THREAT MODEL, not just a convenience feature** — a rate limiter that
   isn't itself concurrency-safe provides a false sense of security
