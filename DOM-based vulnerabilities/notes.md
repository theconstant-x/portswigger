# DOM-based Vulnerabilities

PortSwigger Web Security Academy module: [DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)

## 📝 Core concepts

- **Source → sink, entirely client-side.** A "source" is anything attacker-
  influenced the page can read (`location.hash`, `location.search`,
  `document.referrer`, a `postMessage` event, `document.cookie`). A "sink" is
  a place that data ends up used dangerously (`innerHTML`, `eval`,
  `document.write`, `location =`, jQuery's `$()`, `JSON.parse` feeding a
  template). Nothing here touches the server — view-source and a debugger
  are your main recon tools, not Burp's HTTP history.
- **`postMessage` without an origin check is the big one.** If a page's
  `window.addEventListener('message', handler)` doesn't verify
  `event.origin`, ANY page (ours, on the exploit server) can send it a
  message as if it came from the trusted partner page.
- **`JSON.parse` isn't automatically safe** — if the parsed object's fields
  get used in a sink afterward (e.g. inserted into `innerHTML`), the
  "it's just data" assumption breaks down the same as any other sink.
- **Open redirects** happen when a redirect target comes straight from a
  URL param with no allowlist — useful standalone (phishing) and as a
  building block for other attacks (see the OAuth module's redirect_uri
  labs).
- **DOM clobbering** exploits the browser quirk where an `id`/`name`
  attribute on an HTML element can create or overwrite a global JS variable
  of the same name — if page script does something like
  `var config = window.config || {{...defaults}}`, injecting
  `<a id=config><a id=config name=someProp>` BEFORE that script runs can
  clobber `config` (or one of its properties) with attacker-controlled DOM
  nodes, even in contexts where `<script>` tags themselves are stripped.
  This matters most where you're limited to HTML injection without JS
  execution (e.g. a sanitizer that strips `<script>` and event handlers).

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [DOM XSS using web messages](https://portswigger.net/web-security/dom-based/web-message-manipulation/lab-dom-xss-using-web-messages) | Practitioner | ⬜ |
| 2 | [DOM XSS using web messages and a JavaScript URL](https://portswigger.net/web-security/dom-based/web-message-manipulation/lab-dom-xss-using-web-messages-and-a-javascript-url) | Practitioner | ⬜ |
| 3 | [DOM XSS using web messages and JSON.parse](https://portswigger.net/web-security/dom-based/web-message-manipulation/lab-dom-xss-using-web-messages-and-json-parse) | Practitioner | ⬜ |
| 4 | [DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-based-open-redirection) | Practitioner | ⬜ |
| 5 | [DOM-based cookie manipulation](https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-based-cookie-manipulation) | Practitioner | ⬜ |
| 6 | [Exploiting DOM clobbering to enable XSS](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering) | Expert | ⬜ |
| 7 | [Clobbering DOM attributes to bypass HTML filters](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-clobbering-dom-attributes-to-bypass-html-filters) | Expert | ⬜ |

## Per-lab notes

### Lab 1 — DOM XSS using web messages
📝 The page's message handler writes `event.data` straight into `innerHTML`
with no origin check. One `postMessage(payload, '*')` from our iframe wrapper
executes arbitrary HTML/JS in the victim's session.

### Lab 2 — Web messages + a JavaScript URL
📝 The handler is slightly more careful (checks the message *shape*, e.g.
expects `{{type: 'someType', url: ...}}`) but then assigns that `url` field
to something like `location.href` or an anchor's `href` — a `javascript:`
URI as the value still executes.

### Lab 3 — Web messages + JSON.parse
📝 The handler does `JSON.parse(event.data)` first (so a raw HTML string
won't survive parsing) — but then uses a FIELD from the parsed object in a
dangerous sink. Send a valid JSON string whose field value is the payload.

### Lab 4 — DOM-based open redirection
📝 Client-side JS reads a redirect target from `location.search` (e.g.
`?returnPath=`) and assigns it to `window.location`/`location.href` with no
validation. `//evil-user.net` or a full `https://` URL as the value sends
the victim off-site.

### Lab 5 — DOM-based cookie manipulation
📝 Page JS trusts a `document.cookie` value (or sets one from a URL param)
and feeds it into a sink unsanitized — classic case is a tracking/analytics
script that writes a cookie value into the page to "personalize" content.

### Lab 6 — DOM clobbering to enable XSS
📝 Script does `var someGlobal = window.someGlobal || {{...}}` reading a
property used later in an `innerHTML`/`src`/`eval`-style sink. Our HTML
injection point is sanitized to strip `<script>`, so we clobber the global
with an `<a id="someGlobal" href="javascript:...">`-style anchor/form
element instead.

### Lab 7 — Clobbering DOM attributes to bypass HTML filters
📝 The filter/sanitizer itself reads its OWN configuration from a global
object on the page (e.g. an allowlist). Clobber that config object so the
sanitizer's own settings get overwritten to let something dangerous through
that it would normally strip.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
