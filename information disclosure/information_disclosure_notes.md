# Information Disclosure Notes — PortSwigger Web Security Academy

---

## WHAT IS INFORMATION DISCLOSURE?

Information disclosure (also called information leakage) is when an
application reveals sensitive data to a user who shouldn't have access to
it — data that was never meant to be exposed at all, to anyone outside the
development team.

```
Sensitive data that commonly leaks:
  - Source code
  - Framework/library version numbers
  - Internal file paths and directory structures
  - Database credentials, API keys, secret keys
  - Debugging information (stack traces, environment variables)
  - Internal IP addresses, hostnames
  - Usernames, session tokens
  - Version control history (old commits, deleted code)
```

> 📝 Information disclosure is almost never the FINAL goal of an attack —
> it's the RECON phase. A leaked framework version tells you which CVEs to
> try. A leaked database password lets you connect directly. A leaked
> internal header name unlocks an authentication bypass. This module is
> less about a single exploitation technique and more about learning where
> to LOOK — because almost every other vulnerability class in this
> curriculum becomes dramatically easier once you have inside information.

---

## WHY THIS MATTERS FOR BUG BOUNTY

Information disclosure findings individually often get triaged as "low" or
"informational" severity — but they're frequently the FIRST STEP in a
chain that leads to something critical. A responsible bug bounty hunter
treats every disclosure as a lead worth following, not just a standalone
report.

```
Example chain:
  1. Verbose error message reveals framework version (info disclosure)
  2. That version has a known, public CVE (RCE)
  3. Exploit the CVE using the disclosed version info
  → Low severity finding becomes the key that unlocks a critical one
```

---

## COMMON SOURCES OF INFORMATION DISCLOSURE

### 1. Error messages / stack traces
Verbose error output is a developer convenience left enabled in
production. Stack traces can reveal:
- Full internal file paths
- Framework and library names + exact version numbers
- Database query structure (useful for SQLi)
- Internal function/class names

**How to trigger them:** submit unexpected input types (a string where a
number is expected, a very long value, special characters) to see if
default error handling is verbose rather than generic.

### 2. Debug pages and development features left enabled
Debug/diagnostic pages (e.g. PHP's `phpinfo()`, framework debug consoles,
`/actuator` endpoints in Spring Boot apps) are meant for development only
but sometimes ship to production. These often dump the ENTIRE server
environment — environment variables, loaded modules, configuration,
sometimes even secret keys directly.

**Where to look:** view page source for links/comments referencing debug
tools; try common debug paths directly (`/phpinfo.php`, `/debug`,
`/_debug`, `/actuator/env`).

### 3. Backup and temporary files
Editors and deployment scripts sometimes leave backup copies of source
files sitting in the web root — `.bak`, `.old`, `.orig`, `~` (tilde)
suffixed files, or files still named after their original extension
before a rename (`.php.bak`, `.java.bak`). These are usually served as
plain text/download rather than being processed by the application, since
the web server doesn't recognise the non-standard extension as
executable — meaning you get the RAW SOURCE CODE, comments and all.

**Where to look:** `robots.txt` often lists directories developers wanted
hidden from search engines (which frequently means "sensitive," not just
"boring"). Try appending common backup extensions to known file paths.

### 4. Comments and files intended for developers only
`robots.txt`, `sitemap.xml`, HTML comments, and JS source comments
sometimes directly reveal internal paths, TODO notes with sensitive
context, or references to functionality that was never meant to be
publicly discoverable.

### 5. Insecure configuration — HTTP methods
Some web servers/frameworks leave non-standard or diagnostic HTTP methods
enabled by default. The `TRACE` method (originally meant for network
diagnostics) causes the server to echo the ENTIRE request straight back
in the response — including headers that might have been ADDED by an
intermediate proxy or load balancer BEFORE reaching the application. This
can reveal internal headers the application relies on for authorization
decisions, headers a normal client would never know to send.

### 6. Version control (`.git`) exposure
If a `.git` directory is accidentally deployed alongside the application
(instead of being excluded), its ENTIRE commit history is downloadable.
This includes files, credentials, or comments that were later REMOVED
from the current codebase but still exist permanently in old commits —
information the developers thought they'd deleted, but never actually did.

---

## INFORMATION DISCLOSURE TESTING SOP

### Step 1 — Passive recon first
- View page source on every significant page (Ctrl+U)
- Check `/robots.txt` and `/sitemap.xml`
- Look at every HTTP response header, not just the body

### Step 2 — Probe error handling
- Submit non-numeric values where numbers are expected
- Submit extremely long strings
- Submit malformed/unexpected content types
- Compare verbose vs. generic error responses

### Step 3 — Check for debug/diagnostic endpoints
- View source for links to debug tools
- Try common debug paths directly: `/debug`, `/phpinfo.php`,
  `/cgi-bin/phpinfo.php`, `/actuator`, `/actuator/env`, `/.well-known/`

### Step 4 — Look for backup/temp files
- Check `robots.txt` for disallowed directories — visit them anyway
- For any known file (e.g. `ProductTemplate.java`), try common backup
  suffixes: `.bak`, `.old`, `.orig`, `~`, `.swp`, `.tmp`

### Step 5 — Test unusual HTTP methods
- Send `OPTIONS` to any endpoint — check the `Allow:` header
- Send `TRACE` to sensitive endpoints (like a login page) — inspect
  whether the FULL request (including any headers added by
  intermediate infrastructure) gets echoed back verbatim

### Step 6 — Check for exposed version control
- Try `/.git/HEAD`, `/.git/config`, `/.svn/entries`
- If accessible, mirror the entire `.git` directory and inspect commit
  history for anything since removed from the live codebase

---

## QUICK BURP WORKFLOW

1. Browse the whole app with Burp running — build a full site map
2. Use **Engagement tools → Discover content** to brute-force common
   backup/debug/config paths automatically
3. In Repeater, systematically send malformed input to every parameter,
   watching for a shift from generic to verbose error responses
4. Right-click any request → **Change request method** → try `TRACE` and
   `OPTIONS` against key endpoints, especially authentication-related ones
5. For `.git` exposure: confirm `/.git/HEAD` returns `200`, then mirror
   the repository with `wget -r -np -nH --cut-dirs=1 <url>/.git/` and
   inspect with standard `git log` / `git diff` tooling locally

> 📝 **Content Discovery** in Burp (Engagement tools → Discover content)
> is purpose-built for this entire module — it systematically requests a
> huge wordlist of common paths (backup files, debug endpoints, config
> files, admin panels) against the target and reports what actually
> exists, turning hours of manual guessing into a few minutes of automated
> scanning.

---
---

## PORTSWIGGER LABS

---

### #01 — Information disclosure in error messages

**URL:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages
**Vulnerability:** Verbose error messages reveal the exact version of a third-party framework in use
**Aim:** Obtain the version number of the vulnerable framework

**Background:**
The product page takes a `productId` parameter as an integer. Supplying a
non-existent (but still numeric) ID triggers a clean, generic 404. But
supplying a NON-NUMERIC value entirely breaks the app's error handling,
falling through to the framework's own default verbose error page —
which happily discloses its exact name and version.

**Analysis:**
```
GET /product?productId=999999
→ 404 (generic, safely handled — no leak)

GET /product?productId=null
→ 500, verbose stack trace revealing:
   "Apache Struts 2 2.3.31"
```

**Payload used:** `productId=null` (any non-numeric value works similarly)

> 📝 The lesson here isn't really about Struts specifically — it's that
> input validation and ERROR HANDLING are two separate concerns.
> Developers often validate the "normal invalid" case (ID doesn't exist)
> carefully, while completely forgetting to catch the "wrong TYPE
> entirely" case, letting it fall through to a framework's raw default
> error page.

---

### #02 — Information disclosure on debug page

**URL:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page
**Vulnerability:** A PHP debug page (`phpinfo()`) is accessible and discloses the full server environment, including a `SECRET_KEY` variable
**Aim:** Obtain the `SECRET_KEY` environment variable

**Background:**
The home page's source code contains a link/reference to a debug page.
`phpinfo()` is a standard PHP function that dumps the ENTIRE PHP
configuration and environment — meant purely for local development
debugging, never for a production deployment.

**Analysis:**
```
View page source of the home page:
  → reveals a link to /cgi-bin/phpinfo.php

GET /cgi-bin/phpinfo.php
→ 200 OK — full phpinfo() dump, including:
   Environment variable: SECRET_KEY = <the value we need>
```

**Payload used:** none — just navigating to the disclosed debug page
directly and reading its output.

> 📝 `phpinfo()` pages are a classic, extremely common real-world finding
> in bug bounty — developers enable them for local debugging and simply
> forget to remove them before deploying. They ALWAYS disclose far more
> than intended: full file paths, loaded module versions, and (as here)
> any environment variables set on the server, which very often includes
> secrets never meant to be client-visible.

---

### #03 — Source code disclosure via backup files

**URL:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files
**Vulnerability:** A `.bak` backup copy of a source code file is accessible in a hidden-but-not-actually-protected directory
**Aim:** Identify and submit the hard-coded database password from the leaked source code

**Background:**
`robots.txt` explicitly disallows crawling of a `/backup` directory — a
strong hint that something sensitive lives there. Visiting it directly
(ignoring the crawler-only "disallow" instruction, which has zero actual
access-control effect) reveals a `.java.bak` file — a backup copy of
application source code that the web server serves as plain text rather
than executing.

**Analysis:**
```
GET /robots.txt
→ Disallow: /backup

GET /backup
→ 200 OK, directory listing showing: ProductTemplate.java.bak

GET /backup/ProductTemplate.java.bak
→ 200 OK, raw Java source code, including:
   String password = "<hardcoded PostgreSQL password>";
```

**Payload used:** none — direct navigation to the disclosed backup file.

> 📝 `robots.txt` is meant to tell search engine CRAWLERS not to index a
> path — it has absolutely no enforcement power over a human (or a
> script) simply requesting that URL directly. Every entry in
> `robots.txt` should be read by a pentester as "here's something the
> developers didn't want indexed" — which is a strong signal to check it
> personally, not to skip it.

---

### #04 — Authentication bypass via information disclosure

**URL:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass
**Vulnerability:** The `TRACE` HTTP method is enabled and echoes back a custom header — `X-Custom-IP-Authorization` — that's added by front-end infrastructure and used internally for IP-based access control, but was never meant to be visible to (or settable by) an end client directly
**Aim:** Discover the header name via `TRACE`, then use it to bypass `/admin` authentication and delete `carlos`

**Background:**
`/admin` returns `401 Unauthorized` when accessed normally. But sending a
`TRACE` request to the login page causes the server to echo the FULL
request it received back in the response body — including headers that
were injected by an intermediate proxy/load balancer sitting in front of
the application (not headers the client itself sent). This reveals an
internal-only header name the application trusts for authorization.

**Analysis:**
```
TRACE /login HTTP/1.1
Host: TARGET
(other normal headers...)

→ 200 OK
   Response body echoes the FULL request verbatim, INCLUDING a header
   we never sent ourselves:
     X-Custom-IP-Authorization: 194.xxx.xxx.xxx
   (this was added by the front-end infrastructure before reaching us)

GET /admin
→ 401 Unauthorized

GET /admin
X-Custom-IP-Authorization: 127.0.0.1
→ 200 OK — full admin panel access
   (the app trusts this header to mean "request originated internally")
```

**Payload used:** `TRACE /login` to discover the header name, then
`X-Custom-IP-Authorization: 127.0.0.1` added to requests against `/admin`.

> 📝 This lab elegantly demonstrates why the `TRACE` method is considered
> dangerous enough that most modern servers disable it by default. It
> exposes the gap between "what the CLIENT sent" and "what the
> APPLICATION actually received" — any header added by intermediate
> infrastructure (a reverse proxy, load balancer, WAF) becomes visible
> to anyone who can trigger a TRACE echo, even though that header was
> never meant to be client-controllable at all.

---

### #05 — Information disclosure in version control history

**URL:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history
**Vulnerability:** The application's `.git` directory is exposed and downloadable, exposing the ENTIRE commit history — including commits that later removed sensitive data from the live codebase, but never actually erased it from history
**Aim:** Recover the `administrator` password from an old commit, log in, and delete `carlos`

**Background:**
The `.git` metadata directory (normally used only locally by developers,
never meant to be deployed) is accessible over HTTP. This means the FULL
version history — every commit, every file at every point in time — can
be reconstructed and downloaded, even files/values later "removed" in
subsequent commits.

**Analysis:**
```
GET /.git/HEAD
→ 200 OK — confirms an exposed .git repository

Mirror the entire repository:
  wget -r -np -nH --cut-dirs=1 https://TARGET/.git/
  (rename the downloaded folder to exactly ".git")

Inside that directory:
  git log --oneline
  → shows commit history, including one titled something like:
     "Add skeleton admin panel"

  git diff <that-commit-hash>
  → reveals the diff for that commit, which includes a HARD-CODED
    admin password that was later removed from the current codebase —
    but remains permanently visible in this old commit's history
```

**Payload used:** none in the traditional sense — this is a download +
local Git tooling exercise rather than a crafted HTTP payload.

> 📝 "Deleting" a file or value in a NEW commit does NOT remove it from
> Git's history — it only stops the CURRENT version of the repository
> from containing it. Every prior version remains permanently
> retrievable via `git log`/`git diff`/`git show` as long as the `.git`
> directory itself is reachable. This is one of the most consistently
> valuable real-world bug bounty findings: developers often "fix" an
> accidentally-committed secret by simply deleting it in a later commit,
> without realising the original commit (and the secret inside it) is
> still fully present in history.

---

## REFERENCE — INFORMATION DISCLOSURE QUICK MAP

| Lab pattern | Root cause | Fix |
|---|---|---|
| Verbose error on bad input type | Error handling only covers "normal invalid" cases, not wrong-type input | Catch ALL error conditions generically; never let framework default error pages reach production |
| Exposed debug page | Development-only diagnostic tool left enabled in production | Strip all debug endpoints from production builds/deployments entirely |
| Backup file in web root | Editor/deployment artifact left in a publicly served directory | Exclude all non-application files from the web root; never store backups where the web server can serve them |
| TRACE method header leak | Non-standard HTTP method left enabled, echoing infrastructure-added headers | Disable TRACE (and other unneeded methods) at the web server level |
| Exposed `.git` directory | Version control metadata accidentally deployed alongside the application | Explicitly exclude `.git` (and all VCS metadata) from any production deployment; verify via automated checks in CI/CD |

---

## REFERENCE — DEFENCE PRINCIPLES

1. **Never let framework/library default error pages reach production** —
   always implement generic, custom error handling for every code path,
   including unexpected input types
2. **Strip ALL debugging and diagnostic tooling before deployment** —
   `phpinfo()`, framework debug consoles, verbose logging endpoints, and
   similar tools should never exist outside a local development
   environment
3. **Treat the web root as public** — nothing should be placed there
   that isn't explicitly meant to be served, including editor backups,
   temp files, and version control metadata
4. **Disable unused/dangerous HTTP methods** — most applications only
   need `GET`, `POST`, and occasionally `PUT`/`DELETE`; `TRACE` in
   particular should be disabled unless there's a specific, understood
   reason to keep it
5. **Exclude version control directories from every deployment** — add
   automated CI/CD checks that fail a build if `.git`, `.svn`, or
   similar metadata would end up in the deployed artifact
6. **Remember that `robots.txt` and similar "hint" files provide zero
   actual access control** — anything listed there should be treated as
   a red flag pointing TOWARD something worth investigating, not a
   working security boundary
