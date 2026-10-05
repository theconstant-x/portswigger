# GraphQL API Vulnerabilities

PortSwigger Web Security Academy module: [GraphQL API vulnerabilities](https://portswigger.net/web-security/graphql)

## 📝 Core concepts

- **One endpoint, many operations.** Unlike REST, GraphQL typically exposes
  a SINGLE endpoint (`/graphql` or similar) that accepts a JSON body with a
  `query` (or `mutation`) field describing exactly what data to fetch/
  change — access-control and injection bugs hide in how that query string
  gets resolved server-side, not in the URL routing.
- **Introspection** lets a client ask the API to describe its own schema —
  every type, field, query, and mutation available — which is exactly what
  you want as an attacker doing recon. Production APIs are supposed to
  disable it, but partial/broken attempts to do so are common (see Lab 3).
- **Access control bugs** often come from a query/mutation that exists for
  internal/admin use but isn't actually restricted to admins — the schema
  reveals it exists even if the UI never calls it, so once you know the
  field name you can call it directly regardless of what buttons are shown.
- **Unsanitized arguments** — GraphQL resolvers still ultimately touch a
  database or filesystem; an argument passed straight into a query without
  validation is exploitable the same way a REST query parameter would be
  (SQLi, path traversal, etc. — GraphQL doesn't inherently prevent any of
  the vulnerability classes covered elsewhere in this repo).
- **Aliases defeat naive rate limiting.** GraphQL lets you name multiple
  instances of the same query/mutation differently (`attempt1: login(...)
  attempt2: login(...)`) and send them all in ONE HTTP request — if the
  rate limiter only counts HTTP requests (not operations within them), you
  can brute-force hundreds of guesses per "allowed" request.
- **CSRF over GraphQL** — if an endpoint accepts `application/x-www-form-
  urlencoded` or plain GET in addition to the expected `application/json`
  POST (often left enabled for debugging/compatibility), standard HTML-form
  or image-tag CSRF techniques apply directly to GraphQL mutations, since
  neither of those content types triggers a CORS preflight.

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [Accessing private GraphQL posts](https://portswigger.net/web-security/graphql/lab-graphql-sensitive-data) | Apprentice | ⬜ |
| 2 | [Accidental exposure of private GraphQL fields](https://portswigger.net/web-security/graphql/lab-graphql-field-exposure) | Practitioner | ⬜ |
| 3 | [Finding a hidden GraphQL endpoint](https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint) | Practitioner | ⬜ |
| 4 | [Bypassing GraphQL brute force protections](https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass) | Practitioner | ⬜ |
| 5 | [Performing CSRF exploits over GraphQL](https://portswigger.net/web-security/graphql/lab-graphql-csrf) | Practitioner | ⬜ |

## Per-lab notes

### Lab 1 — Accessing private GraphQL posts
📝 A hidden blog post with a password isn't listed on the page, but the
underlying GraphQL query that fetches posts can be modified (change the
`id` argument, or query the `Post` type directly) to retrieve it anyway.

### Lab 2 — Accidental exposure of private GraphQL fields
📝 Introspection reveals the full schema, including an `isAdmin`-style
field or a `password` field on a type that's returned by a query the UI
never actually displays that field from — request it explicitly instead.

### Lab 3 — Finding a hidden GraphQL endpoint
📝 No visible `/graphql` link anywhere in the app. Fuzz common suffixes
first; once found, this lab's introspection is actively blocked by a
filter — bypass it with a whitespace/formatting variant of the query that
still parses correctly but doesn't match the filter's literal pattern.

### Lab 4 — Bypassing GraphQL brute force protections
📝 The login mutation is rate-limited per HTTP request — but nothing stops
aliasing dozens of login attempts into ONE request, each trying a
different password from a list, turning the limiter's per-request budget
into dozens of free guesses.

### Lab 5 — CSRF over GraphQL
📝 The endpoint accepts the sensitive mutation via
`application/x-www-form-urlencoded` (not just JSON) — meaning a plain
auto-submitting HTML form (no preflight, no custom headers) can trigger it
cross-site, classic CSRF applied to a GraphQL mutation.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
