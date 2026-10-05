# Prototype Pollution

PortSwigger Web Security Academy module: [Prototype pollution](https://portswigger.net/web-security/prototype-pollution)

## 📝 Core concepts

- **JavaScript's prototype chain:** every object inherits properties from
  its prototype. `Object.prototype` sits at the top of nearly every
  object's chain — so a property added to `Object.prototype` becomes
  readable on basically EVERY object in the program, even ones that never
  explicitly set it.
- **The flaw:** code that recursively MERGES or CLONES a user-controlled
  object (a URL's query string parsed into nested keys, a JSON request
  body) into an existing object, without special-casing the magic key
  `__proto__` (or `constructor.prototype`), ends up writing attacker data
  straight onto `Object.prototype` instead of the intended target object.
- **Why it's exploitable, not just a curiosity:** once a property exists on
  `Object.prototype`, any code elsewhere that does something like
  `if (!config.isAdmin) {...}` or `element.innerHTML = options.html` can
  be influenced — even in code that has NOTHING to do with where the
  pollution happened. This is what makes it so often chainable into XSS
  (client-side) or RCE (server-side, Node.js) — you're not injecting code
  directly, you're injecting a property value that SOME OTHER, unrelated
  piece of trusted code later reads and acts on unsafely (a "gadget").
- **Detection workflow (both sides):**
  1. Find a SOURCE — a place user input flows into an object-merge/clone
     operation (a query string parsed via `wur.js`-style libraries, jQuery
     `$.extend(true, ...)`, lodash `_.merge`, a JSON body passed to a
     naive recursive merge function).
  2. Confirm pollution actually lands on `Object.prototype` (not just the
     local object) — e.g. `__proto__[polluted]=xyz` then checking whether
     `Object.prototype.polluted` exists afterward.
  3. Find a GADGET — existing code elsewhere that reads a property with no
     "did I set this myself" guard, and does something dangerous with it.
- **Client-side (Labs 1-6):** the merge happens in the VICTIM's browser —
  deliverable is usually a crafted URL (query-string pollution) or an
  exploit-server page, same delivery model as Clickjacking/DOM-based
  modules. `utils.py`'s client-side helpers build probe URLs; actual
  confirmation needs the browser console or the Visualizer, not a Python
  request.
- **Server-side (Labs 7-10):** the merge happens in a Node.js backend
  processing a JSON request body — fully scriptable with `requests`, same
  shape as every server-side module in this repo. The dangerous gadgets
  here are usually either an auth-check object (`isAdmin`) or, for RCE, a
  property that gets passed into `child_process.exec`-adjacent code (e.g.
  a templating/logging library configuration option).

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [DOM XSS via client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss) | Apprentice | ⬜ |
| 2 | [DOM XSS via an alternative prototype pollution vector](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-alternative-vector) | Practitioner | ⬜ |
| 3 | [Client-side prototype pollution via browser APIs](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-browser-apis) | Practitioner | ⬜ |
| 4 | [Client-side prototype pollution via flawed sanitization](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-flawed-sanitization) | Practitioner | ⬜ |
| 5 | [Bypassing flawed input filters for client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-bypassing-flawed-input-filters) | Practitioner | ⬜ |
| 6 | [Detecting client-side prototype pollution without polluted property reflection](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-without-polluted-property-reflection) | Practitioner | ⬜ |
| 7 | [Privilege escalation via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution) | Practitioner | ⬜ |
| 8 | [Detecting server-side prototype pollution without polluted property reflection](https://portswigger.net/web-security/prototype-pollution/server-side/lab-detecting-server-side-prototype-pollution-without-polluted-property-reflection) | Practitioner | ⬜ |
| 9 | [Bypassing flawed input filters for server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-bypassing-flawed-input-filters-for-server-side-prototype-pollution) | Practitioner | ⬜ |
| 10 | [Remote code execution via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-remote-code-execution-via-server-side-prototype-pollution) | Expert | ⬜ |

## Per-lab notes

### Lab 1 — DOM XSS via client-side pollution
📝 A query-string parser merges params into an options object with no
`__proto__` guard. `?__proto__[transport_url]=...` or similar pollutes a
property an analytics/templating gadget later reads into `innerHTML`.

### Lab 2 — Alternative pollution vector
📝 Same idea, but the merge happens via a DIFFERENT mechanism than a plain
query-string parse (often a JSON blob embedded in the URL fragment or a
`postMessage`-delivered object) — the gadget is the same, the SOURCE
differs.

### Lab 3 — Pollution via browser APIs
📝 The pollution source is a browser API return value (e.g.
`new URLSearchParams(location.search)` iterated into an object) rather
than a hand-rolled parser — same underlying unsafe-merge pattern, just
triggered through a standard API most devs assume is "safe."

### Lab 4 — Flawed sanitization
📝 The app DOES attempt to strip `__proto__` from input — but the
filtering is incomplete (e.g. only checks the literal string once, missing
a differently-cased or array-wrapped variant).

### Lab 5 — Bypassing flawed input filters
📝 Harder filter-bypass variant of Lab 4 — try alternate key encodings:
`__pro__proto__to__` (filter strips `proto` once, leaving a valid
`__proto__` behind), `constructor[prototype]` as a substitute path, or
array/bracket notation tricks specific to the parsing library in use.

### Lab 6 — Detecting without reflection
📝 No visible effect from polluting a property directly — confirm via a
PortSwigger-documented universal side-channel instead (e.g. polluting
`Object.prototype` with a property that affects `JSON.stringify` output,
or using the "detect via a timing/behavior difference" approach the Burp
extension automates) rather than looking for a specific gadget first.

### Lab 7 — Privilege escalation (server-side)
📝 A JSON body merged server-side into the user's session/profile object.
Pollute `isAdmin` (or similar) via `__proto__` in the request body — every
subsequent object created without that field explicitly set inherits
`isAdmin: true`.

### Lab 8 — Detecting without reflection (server-side)
📝 Same "no visible gadget yet" problem as Lab 6, server side — the
PortSwigger Burp extension (Server-Side Prototype Pollution Scanner)
automates probing via JSON body/spacing variants; manually, look for
response TIMING differences or subtle header/behavior changes after
sending a pollution probe as the detection signal.

### Lab 9 — Bypassing flawed input filters (server-side)
📝 Same filter-evasion mindset as Lab 5, server side — the backend's JSON
parser or a pre-merge sanitizer blocks the literal `__proto__` key string;
try nested/bracket variants or a differently-structured JSON body that
still resolves to the same merge target.

### Lab 10 — RCE via server-side pollution (Expert)
📝 Chain pollution into an RCE gadget — this lab's documented chain
pollutes a property read by the app's templating/logging library (often
something like a Node `child_process` execution option, or an `ejs`/
similar templating engine's `escape`/`opts` configuration) such that
normal application behavior ends up executing attacker-controlled code.
This is genuinely specific to the exact library/version in the lab —
search "PortSwigger RCE server-side prototype pollution" for the current
documented gadget if the one referenced here needs updating.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
