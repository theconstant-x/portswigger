# NoSQL Injection

PortSwigger Web Security Academy module: [NoSQL injection](https://portswigger.net/web-security/nosql-injection)

## 📝 Core concepts

- **No SQL syntax, but still injectable.** MongoDB (this module's target)
  takes queries as JSON-like documents/operators, not a string to parse —
  so classic `' OR 1=1--` doesn't apply. Instead, if the app builds its
  query by directly embedding a JSON VALUE you control, you can often
  swap a plain string for an **operator object** instead — e.g. sending
  `{"password": {"$ne": "invalid"}}` instead of `{"password": "invalid"}`
  asks MongoDB "does the password NOT EQUAL this string" instead of
  checking equality, which is true for basically any real password.
- **Detecting it:** try swapping a string param for a JSON operator object
  (`$ne`, `$gt`, `$regex`) via Content-Type: application/json, or try the
  equivalent operator SYNTAX in a form-urlencoded body
  (`password[$ne]=invalid`) if the app accepts that format instead — a
  CHANGE in behavior (different error message, different status) confirms
  the operator was parsed and acted on, not just treated as a literal string.
- **`$where` is the powerful/dangerous one** — it lets you embed a raw
  JAVASCRIPT expression evaluated server-side as part of the query. This
  is MongoDB's version of a classic blind-injection oracle: a `$where`
  clause that evaluates to `true`/`false` lets you extract data
  character-by-character the same way blind SQLi does, just using JS
  syntax (`this.username.match('^a')`) instead of SQL substring functions.
- **Timing-based blind injection** is also possible via `$where` using a
  deliberately slow JS expression (a busy-loop) — same methodology as
  time-based blind SQLi, useful when there's no visible true/false
  response difference to key off of.
- **Extracting UNKNOWN field names** — `$where` lets you run arbitrary JS,
  including `Object.keys(this)` to enumerate a document's field names you
  didn't already know existed (like a password-reset token field never
  shown in any form) — something SQL injection's fixed schema model has no
  real equivalent for.

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [Detecting NoSQL injection](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detecting) | Apprentice | ⬜ |
| 2 | [Exploiting NoSQL operator injection to bypass authentication](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication) | Apprentice | ⬜ |
| 3 | [Exploiting NoSQL injection to extract data](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-data) | Practitioner | ⬜ |
| 4 | [Exploiting NoSQL operator injection to extract unknown fields](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-unknown-fields) | Practitioner | ⬜ |

## Per-lab notes

### Lab 1 — Detecting NoSQL injection
📝 Pure detection: swap the password value for `{"$ne": "invalid"}` (or
try the bracket-syntax equivalent in a form body) and watch for a
DIFFERENT error message than a normal failed login — that difference
alone confirms the operator was interpreted, not just treated as text.

### Lab 2 — Bypass authentication
📝 Apply the same operator trick, but construct it so it actually
succeeds rather than just changing the error — `$ne` against a password
you know is wrong (not literally the string "invalid") lets you log in as
any user, including administrator, without knowing their real password.

### Lab 3 — Extract data
📝 Use a `$where` clause carrying a JS boolean expression
(`this.username == 'carlos'`-style field comparisons) to blind-extract
data character by character — here, the goal is typically the
administrator's password.

### Lab 4 — Extract unknown fields
📝 First use `$ne` to confirm the injection and lock yourself out of
direct login, then use `$where: Object.keys(this)[N]` to enumerate field
NAMES you don't already know exist (e.g. a password-reset token field),
extract that field's value character-by-character the same way as Lab 3,
then use it to actually reset and gain carlos's account.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
