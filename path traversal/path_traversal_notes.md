# Path Traversal Notes — PortSwigger Web Security Academy

---

## WHAT IS PATH TRAVERSAL?

Path traversal (also called directory traversal) is a vulnerability that lets
an attacker read — and sometimes write — files OUTSIDE the directory the
application intended to expose, by manipulating a file path parameter the
application uses internally.

```
Intended behaviour:
  GET /image?filename=1.jpg
  → server reads: /var/www/images/1.jpg

Attacker manipulates the filename:
  GET /image?filename=../../../etc/passwd
  → server reads: /var/www/images/../../../etc/passwd
                 → normalises to: /etc/passwd
```

> 📝 `../` means "go up one directory" in a file path — this is standard
> filesystem navigation syntax, not a hack in itself. The vulnerability is
> that the SERVER blindly concatenates user input into a file path without
> validating that the result still stays inside the intended directory.

---

## WHY THIS MATTERS

Path traversal typically targets a feature that legitimately reads files
from disk based on user input — most commonly:
- Serving product/profile images by filename
- Downloading user-uploaded documents
- Loading templates or includes by name
- Log file viewers
- Any "download this file" functionality

**Impact depends on what's readable (or writable):**
- Configuration files (often containing credentials, API keys, DB connection strings)
- Application source code
- `/etc/passwd` (classic PoC target — confirms the vulnerability, low sensitivity itself)
- SSH keys, TLS private keys
- In write-scenarios: overwriting application files, planting a webshell

---

## THE CORE PAYLOAD

```
../          → go up one directory (Unix/Linux, also works on Windows)
..\          → go up one directory (Windows-style)
../../../    → go up three directories (stack as many as needed)
```

You typically don't know the exact directory depth of the target file at
the START of the traversal — so it's common practice to use MORE `../`
sequences than strictly necessary. Extra `../` sequences beyond the
filesystem root are simply ignored by the OS (you can't go up past `/`),
so over-traversing is harmless and saves you from guessing the exact depth.

```
../../../../../../../etc/passwd
```
Six levels up is almost always enough regardless of the actual starting depth.

---

## DEFENCES AND THEIR BYPASSES

Real applications rarely accept `../../../etc/passwd` completely unfiltered
— this module is fundamentally about learning the SPECIFIC ways developers
try (and fail) to block traversal, and the exact bypass for each one.

### Defence 1 — No defence at all
The simplest case. The filename is concatenated directly into the file path
with zero validation.
```
Bypass: just use ../../../etc/passwd directly.
```

### Defence 2 — Block traversal sequences, but trust an absolute path
The app strips/blocks `../` sequences — but doesn't stop you from supplying
a completely absolute path instead. If the underlying file-read function
accepts absolute paths, you can skip relative traversal entirely.
```
Bypass: supply the absolute path directly.
  filename=/etc/passwd
```

### Defence 3 — Strip traversal sequences NON-RECURSIVELY
The app removes `../` from the input — but only does ONE PASS. It doesn't
re-check the result after stripping. If you nest sequences cleverly, the
inner `../` left behind after the FIRST strip becomes a valid `../` once
the OUTER characters are removed.
```
Input:    ....//....//....//etc/passwd
Strip "../" (one pass, removes the substring "../" wherever found):
   "....//" contains "../" ? Let's trace it: "....//"
   → the sequence "../" appears starting at position 2: "..|../|/"... 
   Actually the classic bypass pattern is:
   Input:  ....//
   Strip "../" once → "..//" remains? No —

   The RELIABLE bypass pattern, confirmed working:
   Input:    ....//....//....//etc/passwd
   → after a single non-recursive removal of "../" substrings,
     what's left reassembles into: ../../../etc/passwd
```
> 📝 The exact character arithmetic here trips people up — the safest way to
> think about it: whatever traversal string you want to SURVIVE stripping,
> wrap it with the same blocked substring on the outside so the stripping
> operation "eats" the wrapper and leaves the real payload behind. This
> pattern generalises: if the filter removes `X`, and you send `XYX` where
> removing `X` from `XYX` leaves `Y`, and `Y` itself is a valid payload —
> you win. Always verify empirically in Burp Repeater rather than trying to
> compute it purely on paper; server-side string implementations vary.

### Defence 4 — Block traversal sequences, then URL-decode AFTER filtering
The app checks the RAW input for traversal sequences, rejects it if found —
THEN URL-decodes the input before actually using it. Since the filter ran
BEFORE decoding, an encoded traversal sequence sails through the filter
(it doesn't look like `../` yet) and only becomes `../` after the filter
has already approved it.
```
Normal URL-encoding:  ../  →  %2e%2e%2f     (this alone gets decoded by the
                                              server BEFORE your filter even
                                              runs, since one layer of URL
                                              decoding always happens on
                                              receipt of an HTTP request)

Double URL-encoding:  ../  →  %2e%2e%2f  →  %25%32%65%25%32%65%25%32%66
                               (encode again: % → %25, 2 → %32, e → %65, etc.)

The FIRST decode (automatic, by the web server) turns %25... back into
%2e%2e%2f — which still doesn't LOOK like ../ to the filter.
The filter passes it.
The APPLICATION then does its OWN additional decode — turning %2e%2e%2f
into ../ — AFTER the filter already ran.
```

### Defence 5 — Validate that the path STARTS WITH the expected folder
The app checks the resulting path begins with the intended directory
(e.g. `/var/www/images`) — but does the check BEFORE resolving `../`
sequences within it. As long as your supplied string starts with the
expected prefix, you can append traversal sequences afterward.
```
Input:  /var/www/images/../../../etc/passwd

Starts-with check: does this begin with "/var/www/images"? YES → passes.
Path resolution (happens AFTER the check): the OS resolves ../../../
against /var/www/images, walking back up to root, landing on /etc/passwd.
```

### Defence 6 — Validate the file EXTENSION, bypass with a null byte
The app checks that the filename ENDS with an expected extension (e.g.
`.jpg` or `.png`) before reading it. Many underlying file-handling functions
(in older/legacy stacks, particularly those built on C string handling)
treat a null byte (`\0`) as a string terminator — so appending `%00.jpg`
AFTER your real target satisfies the extension check, but the actual file
read stops at the null byte, ignoring everything after it.
```
Input:  ../../../etc/passwd%00.jpg

Extension check: does the string END with ".jpg"? YES → passes.
File read: the underlying OS/library call sees the null byte and treats
it as the end of the string → actually opens /etc/passwd, completely
ignoring the trailing ".jpg" that was only there to satisfy the check.
```
> 📝 Null byte injection is largely a LEGACY vulnerability — modern language
> runtimes (Java, current Python, current PHP, .NET) generally handle
> strings with explicit length tracking rather than null-termination, so
> this specific bypass doesn't work against most modern stacks. It's
> included in the Academy because it's still found in older/legacy code
> and is an important historical technique to recognise.

---

## PATH TRAVERSAL TESTING SOP

### Step 1 — Find file-handling functionality
- Any feature that displays/downloads a file based on user input
- Look for parameters with filename-like values: `filename=`, `file=`,
  `path=`, `document=`, `template=`, `page=`, `image=`

### Step 2 — Confirm the base case
- Try `../../../etc/passwd` (Linux) or `..\..\..\windows\win.ini` (Windows)
- If it works immediately: no defence, done

### Step 3 — If blocked, identify WHICH defence is in play
Test each systematically, in this order (cheapest tests first):
1. Absolute path: `/etc/passwd`
2. Non-recursive strip bypass: `....//....//....//etc/passwd`
3. Double URL-encoding: `..%252f..%252f..%252fetc/passwd`
4. Prefix + traversal: `{expected-prefix}/../../../etc/passwd`
5. Null byte + expected extension: `../../../etc/passwd%00.jpg`

### Step 4 — Read the error/response carefully
- Different error messages for "extension invalid" vs "path invalid" vs
  "file not found" tell you WHICH check is failing, narrowing down which
  bypass to try next
- A 200 with different content length than expected can indicate PARTIAL
  success (e.g. path accepted, but file doesn't exist at that exact path)

### Step 5 — Confirm impact
- `/etc/passwd` is the standard PoC (low sensitivity but universally
  present on Linux, easy to visually confirm)
- Once confirmed, pivot to sensitive application-specific files
  (config files, source code, credentials)

---

## QUICK BURP WORKFLOW

1. Browse the app, identify any file-serving endpoint → send to **Repeater**
2. Try the base payload (`../../../etc/passwd`) first
3. If blocked, work through the bypass list above one at a time, observing
   how the response/error changes with each attempt
4. Use **Burp Decoder** to build double-URL-encoded payloads quickly
   (encode once, then encode the result again)
5. For null-byte testing, Burp Repeater's "raw" request editor lets you
   insert `%00` directly without any client-side interference

> 📝 A useful habit: when a filter blocks something, don't just try to guess
> the bypass — send a FEW variations and closely diff the exact response
> text/length/status for each. The specific way an app responds to "blocked"
> vs "not found" vs "success" is often the fastest route to figuring out
> exactly which check you're up against.

---
---

## PORTSWIGGER LABS

---

### #01 — File path traversal, simple case

**URL:** https://portswigger.net/web-security/file-path-traversal/lab-simple
**Vulnerability:** Product image display has zero validation on the `filename` parameter
**Aim:** Retrieve the contents of `/etc/passwd`

**Background:**
Product images are loaded via `GET /image?filename=1.jpg`. There is no
filtering whatsoever — the filename is concatenated directly into a
server-side file path.

**Analysis:**
```
GET /image?filename=1.jpg
→ 200 OK (normal product image)

GET /image?filename=../../../etc/passwd
→ 200 OK — contents of /etc/passwd returned directly
```

**Payload used:** `../../../etc/passwd`

> 📝 This is the baseline. Every other lab in this module is a variation on
> defeating one specific validation mechanism layered on top of this exact
> same underlying vulnerability.

---

### #02 — File path traversal, traversal sequences blocked with absolute path bypass

**URL:** https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass
**Vulnerability:** `../` sequences are blocked, but the file-read function still accepts an absolute path
**Aim:** Retrieve the contents of `/etc/passwd`

**Background:**
Sending any traversal sequence (`../`) gets rejected. But the application
never validates that the supplied filename must be RELATIVE — supplying a
full absolute path bypasses the relative-traversal check entirely, since
there's no `../` in it at all.

**Analysis:**
```
GET /image?filename=../../../etc/passwd
→ blocked (traversal sequence detected)

GET /image?filename=/etc/passwd
→ 200 OK — contents of /etc/passwd returned directly (absolute path, no
  traversal sequence present, so the filter never triggers)
```

**Payload used:** `/etc/passwd`

> 📝 This defence only checked for the SYMPTOM (`../` substrings) rather
> than the actual security property it needed (the resolved path must stay
> inside the intended directory). An absolute path achieves the same
> attacker goal through a completely different mechanism the filter never
> considered.

---

### #03 — File path traversal, traversal sequences stripped non-recursively

**URL:** https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively
**Vulnerability:** The app strips `../` from the input, but only in a single, non-recursive pass
**Aim:** Retrieve the contents of `/etc/passwd`

**Background:**
`../../../etc/passwd` gets your traversal sequences removed, leaving
`etc/passwd` — a relative path with no traversal, which just 404s. Because
the stripping only happens ONCE (not repeatedly until no more matches
exist), nesting the blocked substring around your real payload causes the
single removal pass to leave behind exactly the sequence you wanted.

**Analysis:**
```
GET /image?filename=../../../etc/passwd
→ traversal stripped → becomes "etc/passwd" → 404 (no traversal, wrong path)

GET /image?filename=....//....//....//etc/passwd
→ single-pass strip of "../" substrings leaves behind: ../../../etc/passwd
→ 200 OK — contents of /etc/passwd returned
```

**Payload used:** `....//....//....//etc/passwd`

> 📝 This bypass pattern is worth internalising generally, not just for this
> lab: whenever a filter removes a fixed substring exactly ONCE per
> occurrence rather than looping until no matches remain, wrapping your
> real payload with an extra copy of the blocked substring will often
> "feed" the filter something to remove while leaving your actual payload
> intact underneath.

---

### #04 — File path traversal, traversal sequences stripped with superfluous URL-decode

**URL:** https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode
**Vulnerability:** The app blocks raw traversal sequences, THEN performs an extra URL-decode on the (already-filtered) input before use
**Aim:** Retrieve the contents of `/etc/passwd`

**Background:**
A single layer of URL-encoding (`../` → `%2e%2e%2f`) doesn't help — the web
server automatically URL-decodes incoming requests once before your
filter even sees them, so `%2e%2e%2f` arrives at the filter already looking
like `../` and gets blocked just the same. The bypass requires encoding
TWICE: the first (automatic) decode only partially unwraps the payload,
still hiding it from the filter; the application's OWN additional decode
(happening after the filter has already approved the input) finishes the
job.

**Analysis:**
```
../          → single encode →  %2e%2e%2f
%2e%2e%2f    → encode AGAIN  →  %25%32%65%25%32%65%25%32%66
                                 (% becomes %25, 2 becomes %32, e becomes %65,
                                  the trailing f becomes %66, etc.)

GET /image?filename=%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66etc/passwd

→ Server's automatic single decode: %25... → %2e%2e%2f%2e%2e%2f%2e%2e%2f...
  (still doesn't look like ../ — filter passes it)
→ Application's OWN extra decode: %2e%2e%2f → ../
  (NOW it becomes actual traversal — but this happens AFTER the filter ran)
→ 200 OK — contents of /etc/passwd returned
```

**Payload used (double URL-encoded):**
`%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66etc/passwd`

> 📝 This is a great example of a security check and the actual data
> processing happening at DIFFERENT layers with different encoding
> assumptions. The fix is straightforward in principle — validate AFTER
> all decoding is complete, not before — but the bug is subtle enough that
> it shows up in real applications fairly often, especially where
> validation and business logic are implemented by different layers/teams.

---

### #05 — File path traversal, validation of start of path

**URL:** https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path
**Vulnerability:** The app validates that the supplied path STARTS WITH the expected directory, but resolves `../` sequences AFTER that check
**Aim:** Retrieve the contents of `/etc/passwd`

**Background:**
The full file path (not just a filename) is passed via the request
parameter. The server checks: "does this string begin with
`/var/www/images`?" — and if so, considers it safe. But the check happens
BEFORE the operating system resolves any `../` sequences within the
string, so appending traversal AFTER the required prefix satisfies the
check while still escaping the directory once resolved.

**Analysis:**
```
GET /image?filename=/etc/passwd
→ blocked — doesn't start with /var/www/images

GET /image?filename=/var/www/images/../../../etc/passwd
→ starts-with check: begins with "/var/www/images"? YES → passes
→ OS resolves the full path AFTER the check:
     /var/www/images/../../../etc/passwd  →  /etc/passwd
→ 200 OK — contents of /etc/passwd returned
```

**Payload used:** `/var/www/images/../../../etc/passwd`

> 📝 This is the same class of bug as the Access Control module's "URL-based
> access control circumvented" lab — validating a STRING PATTERN rather
> than the actual RESOLVED RESOURCE. Any time validation happens before a
> normalisation/resolution step, appending something AFTER the validated
> portion is worth testing.

---

### #06 — File path traversal, validation of file extension with null byte bypass

**URL:** https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass
**Vulnerability:** The app validates that the filename ENDS WITH an expected image extension, using a legacy file-handling layer that treats a null byte as a string terminator
**Aim:** Retrieve the contents of `/etc/passwd`

**Background:**
The application only serves files whose name ends in `.jpg` (or similar).
`/etc/passwd` fails this check outright. But appending a null byte
(`%00`) followed by a fake extension satisfies the STRING-LEVEL check
(the string DOES end in `.jpg`), while the underlying file-open call
(built on a legacy/C-style string handling layer) stops reading the
filename at the null byte — silently discarding everything after it,
including the fake extension.

**Analysis:**
```
GET /image?filename=../../../etc/passwd
→ blocked — doesn't end in an allowed extension

GET /image?filename=../../../etc/passwd%00.jpg
→ extension check: does the string end in ".jpg"? YES → passes
→ underlying file-open call: null byte terminates the string early
   → actually opens: ../../../etc/passwd  (the %00.jpg is ignored)
→ 200 OK — contents of /etc/passwd returned
```

**Payload used:** `../../../etc/passwd%00.jpg`

> 📝 Null byte injection is largely a LEGACY technique — most modern
> language runtimes track string length explicitly rather than relying on
> a null terminator, so this specific bypass won't work against most
> current stacks. It remains important to know because older systems,
> some C-based components, and certain file-handling libraries still
> exhibit this behaviour — and it's a great illustration of validation
> happening at one layer (string content) while the actual operation
> happens at a DIFFERENT layer with different rules (null-terminated
> C strings).

---

## REFERENCE — PATH TRAVERSAL QUICK MAP

| Lab pattern | What's broken | Fix |
|---|---|---|
| No validation | Filename concatenated directly into a file path | Never trust user input for file paths; use an allow-list of known-safe filenames |
| Traversal blocked, absolute path allowed | Filter only checks for `../`, not for absolute paths | Reject any path that isn't a bare filename with no separators at all |
| Non-recursive stripping | Filter removes `../` once instead of looping until none remain | Strip repeatedly until no more matches exist, or reject rather than sanitise |
| Filter-then-decode ordering | Validation runs BEFORE the final decode step | Always validate AFTER all decoding is complete — validate the fully-resolved value |
| Prefix-only validation | Checks the path STARTS WITH an expected directory, before resolving `../` | Resolve the path fully first (canonicalise), THEN check it's still inside the intended directory |
| Extension-only validation + null byte | Checks the filename ENDS WITH an allowed extension; underlying call stops at null byte | Validate using safe, modern string-handling APIs; canonicalise and check the resolved path, not just the filename string |

---

## REFERENCE — DEFENCE PRINCIPLES

1. **Best practice: avoid passing user input to filesystem APIs at all** —
   use an indirect reference (e.g. a database ID mapped server-side to a
   real, fixed filename) instead of accepting a filename or path directly
2. **If you must accept a filename, use a strict allow-list** — validate
   against a known set of permitted values, don't try to "sanitise" a
   free-form path
3. **If you must accept a path, canonicalise BEFORE validating** — resolve
   all `../`, `.`, symlinks, and encoding FIRST, then check the fully
   resolved absolute path starts with (and stays within) the intended
   directory
4. **Validate after ALL decoding, not before** — a filter that runs before
   a subsequent decode step can always be bypassed by hiding the payload
   from that filter's view
5. **Don't rely on string-level checks (prefix/suffix) as your only
   defence** — a string can satisfy a prefix/suffix check while still
   resolving to a completely different, dangerous location once processed
6. **Use modern, well-tested filesystem/path libraries** — many languages
   provide a canonicalisation function (e.g. `realpath()`, `Path.resolve()`)
   specifically to eliminate this entire class of bug when used correctly
