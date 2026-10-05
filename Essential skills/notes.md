# Essential Skills

PortSwigger Web Security Academy category: Essential Skills

## ⚠️ Confidence flag — read this first

Unlike every other module in this repo, I could not confirm the exact lab
titles/URLs for this category despite a real search effort. What's solid:
cross-referencing several independent BSCP-prep trackers (people logging
their own progress through all Academy labs) consistently shows **2
Practitioner-level labs** under an "Essential Skills" grouping, separate
from the ~30 vulnerability-class topics. What I could NOT confirm: their
actual names, URLs, or what each one specifically asks you to do.

What's reasonably inferable from context: PortSwigger's own "Getting
Started" page and Burp Suite tutorial series center on **Proxy/Repeater
interception and resending requests**, and the Academy separately promotes
**Burp Decoder** and **Burp Intruder** as core tools you're expected to be
fluent in before tackling the harder topics. It's a reasonable guess that
this category's 2 labs test exactly that kind of raw tool fluency (not a
specific vulnerability class) — but treat the two scripts below as a
**scaffold to correct against the real lab text**, not a confirmed
solution, in a way that's not true of any other module here.

If you open the actual labs and they turn out to test something different,
the fix is simple: update this notes.md with the real title/goal, rename
the lab scripts to match, and rewrite their logic — the proxies.py/
utils.py pattern underneath will still apply fine either way, since both
likely labs (whatever their real form) are just HTTP requests through Burp.

## 📝 Core skills this category most likely covers

- **Intercepting and modifying requests in Burp Proxy** — the foundational
  workflow every other module in this repo assumes you already have.
- **Burp Repeater** — resending a captured request with manual tweaks,
  comparing responses, iterating quickly without re-triggering the whole
  page flow each time.
- **Burp Decoder** — recognizing and converting between encodings
  (base64, URL-encoding, hex) you'll hit constantly in cookies, tokens,
  and serialized data across other modules.
- **Burp Intruder** (Community Edition's single-threaded version, or Pro) —
  automating a sweep of many payload values against one injection point
  (the manual-tool equivalent of the brute-force scripts used elsewhere in
  this repo).

## Labs (placeholder — titles unconfirmed)

| # | Lab (best guess) | Difficulty | Status |
|---|-----|------------|--------|
| 1 | Using Burp Repeater to modify and resend a request | Practitioner | ⬜ |
| 2 | Using Burp Decoder / Intruder on an encoded or brute-forceable value | Practitioner | ⬜ |

## Status key
⬜ not started · 🟨 in progress · ✅ solved · ❓ placeholder, needs correction against real lab
