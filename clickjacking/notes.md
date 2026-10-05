# Clickjacking (UI Redressing)

PortSwigger Web Security Academy module: [Clickjacking](https://portswigger.net/web-security/clickjacking)

## 📝 Core concepts

- **The trick:** render the real target page in a near-invisible `<iframe>`
  (opacity ~0), and draw your own decoy UI underneath at the exact pixel
  position of the real page's sensitive button. The victim thinks they're
  clicking your decoy — they're actually clicking the real button through
  the invisible iframe.
- **Defenses and how each lab defeats them:**
  - **CSRF tokens don't help** — the victim's own authenticated browser
    session is doing the real click, token and all. (Lab 1)
  - **Form fields can be pre-filled via URL/query params** on the framed
    page, turning a generic "click to confirm" into "click to do exactly
    what I chose." (Lab 2)
  - **JS frame-busters** (`if (top !== self) top.location = self.location`)
    can often be defeated with the iframe's `sandbox` attribute — sandboxing
    without `allow-top-navigation` blocks the busting script from
    navigating the top frame, while still rendering the page. (Lab 3)
  - **A single click can trigger more than a UI action** — if the framed
    page has a DOM XSS sink reachable via a crafted URL fragment/param, the
    "disguised click" delivery mechanism can be reused to fire that XSS
    instead of a simple state change. (Lab 4)
  - **Multi-step flows** need multiple stacked, carefully offset iframes
    (or iframes swapped between clicks) so a sequence of clicks walks the
    victim through several confirmation steps in one session. (Lab 5)
- **Modern primary defense:** `X-Frame-Options: DENY/SAMEORIGIN` or CSP
  `frame-ancestors` — if either is set correctly, framing is blocked before
  any JS runs, and none of the above tricks apply. Check these first with
  `utils.check_framing_defenses()`.

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [Basic clickjacking with CSRF token protection](https://portswigger.net/web-security/clickjacking/lab-csrf-token-protected) | Apprentice | ⬜ |
| 2 | [Clickjacking with form input data prefilled from a URL parameter](https://portswigger.net/web-security/clickjacking/lab-prefilled-form-input) | Apprentice | ⬜ |
| 3 | [Clickjacking with a frame buster script](https://portswigger.net/web-security/clickjacking/lab-frame-buster) | Apprentice | ⬜ |
| 4 | [Exploiting clickjacking vulnerability to trigger DOM-based XSS](https://portswigger.net/web-security/clickjacking/lab-dom-xss) | Practitioner | ⬜ |
| 5 | [Multistep clickjacking](https://portswigger.net/web-security/clickjacking/lab-multistep) | Practitioner | ⬜ |

## Per-lab notes

### Lab 1 — Basic clickjacking (CSRF token protected)
📝 Goal: trick the logged-in victim into clicking "Delete account" on the
blog's account page. CSRF token rides along for free since it's the victim's
real browser making the real request.

### Lab 2 — Prefilled form input from a URL parameter
📝 Goal: the "update email" form reads its initial value from a query
parameter. Set `?email=` in the iframe's `src` so one disguised click
changes the victim's email to an attacker-controlled address — setting up
account takeover via password reset.

### Lab 3 — Frame buster script
📝 Goal: same account-delete trick as Lab 1, but the page tries to bust out
of frames with JS. Add `sandbox="allow-forms allow-scripts"` (deliberately
WITHOUT `allow-top-navigation` / `allow-top-navigation-by-user-activation`)
to the iframe — the busting script still runs but can't navigate the parent.

### Lab 4 — Trigger DOM-based XSS via clickjacking
📝 Goal: the target page has a DOM XSS sink driven by a URL fragment, but it
only fires after a user interaction (e.g. clicking a "Click me" element on
the page). Frame the vulnerable URL (with the XSS payload already in the
fragment) and overlay a decoy on top of that exact in-page element.

### Lab 5 — Multistep clickjacking
📝 Goal: the "grant access" flow needs two separate confirmations. Stack two
iframes (or swap the iframe's `src`/position between two decoy divs using a
tiny bit of JS/CSS timing) so one visit walks the victim through both clicks
in sequence without them noticing the page changed underneath.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
