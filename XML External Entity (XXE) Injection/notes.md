# XML External Entity (XXE) Injection

PortSwigger Web Security Academy module: [XXE injection](https://portswigger.net/web-security/xxe)

## 📝 Core concepts

- **The core primitive:** a `<!DOCTYPE ... [ <!ENTITY xxe SYSTEM "..."> ]>`
  declaration lets XML define custom entities resolved from a URI —
  `file://`, `http://`, even `expect://` on some setups. Reference `&xxe;`
  anywhere in the body and the parser substitutes the resolved content
  before the app ever sees the "real" data.
- **In-band vs blind:**
  - **In-band** — the resolved value gets reflected back in the response
    (e.g. inside a "product not found: &xxe;" style error or a normal
    field echo). Read it straight off the HTTP response.
  - **Blind** — nothing comes back directly. Confirm exploitation via an
    out-of-band (OOB) interaction: point the entity at a Burp Collaborator
    (or any listener you control) and watch for the inbound DNS/HTTP hit.
- **General entities vs parameter entities:** `&name;` (general) can only be
  used in the document body. `%name;` (parameter) can ONLY be used inside
  the DTD itself — needed when the app's XML parser rejects entities
  referenced in the data but still processes the DTD. Parameter entities are
  also how the two-stage "malicious external DTD" and "local DTD
  repurposing" tricks work: they let you build up a payload entity-by-entity
  before referencing the final one.
- **File reads often can't cross newlines/be used directly as a URL** — this
  is why the error-based and malicious-DTD techniques exist: they smuggle
  file content into a URL (as part of a deliberately-broken SYSTEM
  identifier) so it either errors out WITH the content in the message, or
  gets appended to an outbound request to your OOB listener.
- **XInclude** is a fallback when you don't control the DOCTYPE at all — only
  a single data value. If the app's parser has XInclude support enabled,
  `<xi:include href="file://...">` still gets you file reads from inside
  just that one field.
- **File-upload XXE** — don't just look for raw XML endpoints; file formats
  like SVG, DOCX, XLSX are ZIP/XML under the hood, so an uploaded "image"
  can smuggle a DOCTYPE in its metadata.

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [Exploiting XXE using external entities to retrieve files](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files) | Apprentice | ⬜ |
| 2 | [Exploiting XXE to perform SSRF attacks](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf) | Apprentice | ⬜ |
| 3 | [Blind XXE with out-of-band interaction](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction) | Practitioner | ⬜ |
| 4 | [Blind XXE with out-of-band interaction via XML parameter entities](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities) | Practitioner | ⬜ |
| 5 | [Exploiting blind XXE to exfiltrate data using a malicious external DTD](https://portswigger.net/web-security/xxe/blind/lab-xxe-exfiltrate-data-using-malicious-external-dtd) | Practitioner | ⬜ |
| 6 | [Exploiting blind XXE to retrieve data via error messages](https://portswigger.net/web-security/xxe/blind/lab-xxe-triggering-error-message-containing-sensitive-data) | Practitioner | ⬜ |
| 7 | [Exploiting XInclude to retrieve files](https://portswigger.net/web-security/xxe/lab-xxe-exploiting-xinclude-to-retrieve-files) | Practitioner | ⬜ |
| 8 | [Exploiting XXE via image file upload](https://portswigger.net/web-security/xxe/lab-xxe-exploiting-xxe-via-image-file-upload) | Practitioner | ⬜ |
| 9 | [Exploiting XXE to retrieve data by repurposing a local DTD](https://portswigger.net/web-security/xxe/blind/lab-xxe-repurposing-local-dtd) | Expert | ⬜ |

## Per-lab notes

### Lab 1 — Retrieve files via external entities
📝 Textbook case: no defenses at all. Define `&xxe;` as `file:///etc/passwd`,
reference it in the request body, read the file straight off the response.

### Lab 2 — SSRF via XXE
📝 Same primitive, `http://` target instead of `file://` — point it at the
internal admin endpoint the lab wants you to reach (check `/product/stock`
style internal URL hints in the app first).

### Lab 3 — Blind XXE, OOB interaction
📝 No reflection at all. Confirm the vulnerability purely by seeing the
Collaborator interaction land after sending the payload.

### Lab 4 — Blind XXE, OOB via parameter entities
📝 Direct `&xxe;` in the body gets rejected/stripped by this app's parser —
switch to `%xxe;` defined and referenced entirely within the DTD itself.

### Lab 5 — Exfiltrate via malicious external DTD
📝 Two-stage: host a `.dtd` file (own exploit server) that reads a local
file and smuggles it into a request to your Collaborator URL as a query
param, then trigger the target to fetch and process that DTD.

### Lab 6 — Error-based blind XXE
📝 Same two-stage shape as Lab 5, but instead of an OOB request, the hosted
DTD deliberately causes a parse error whose message CONTAINS the file
content — no Collaborator needed, read it straight from the HTTP error.

### Lab 7 — XInclude to retrieve files
📝 Used when you can only control a single XML VALUE, not the DOCTYPE
(e.g. a comment/field that gets embedded into a larger XML document
server-side). `<xi:include>` sidesteps the lack of DOCTYPE control.

### Lab 8 — XXE via image file upload
📝 Upload a file (SVG works well — it's just XML) containing a DOCTYPE/XXE
payload in its metadata/content. The "image processing" step parses it as
XML even though the upload UI treats it as a picture.

### Lab 9 — Repurposing a local DTD
📝 No outbound network access at all (fully blind, no OOB possible) — but a
predictable local `.dtd` file exists on the server filesystem (bundled with
a library). Redefine one of ITS entities via a parameter-entity override to
carry the file-read + error-based exfil payload instead, all without ever
leaving the box.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
