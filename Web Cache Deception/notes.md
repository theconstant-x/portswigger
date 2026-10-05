# Web Cache Deception

PortSwigger Web Security Academy module: [Web cache deception](https://portswigger.net/web-security/web-cache-deception)

## 📝 Core concepts

- **Deception vs. poisoning** (easy to mix up): poisoning injects
  malicious content that the cache then serves to OTHER users. Deception
  tricks the cache into storing a DYNAMIC, PRIVATE page (someone's own
  account page, containing their own API key) under a URL an ATTACKER can
  also request — the attacker steals the victim's own data by reading it
  back out of the cache themselves. No payload injection needed — this is
  purely about URL path confusion.
- **Cache rules** are usually based on simple path patterns:
  - **Static extension rules** — cache anything ending in `.css`, `.js`,
    `.png`, etc., regardless of what directory it's in.
  - **Static directory rules** — cache anything under a known-static
    prefix like `/resources/` or `/static/`.
  - **Exact-match / file name rules** — cache a SPECIFIC known file like
    `/robots.txt` by name.
- **The exploit shape, every lab:** find a way to make the ORIGIN server
  still resolve a crafted URL to the SAME sensitive dynamic page (ignoring
  some extra junk you appended), while the CACHE'S path parser instead
  sees that junk as matching one of its cache rules and stores the result.
  The two parsers disagreeing is the entire vulnerability.
- **Delimiters are the main discovery tool** — a character like `;`, `#`,
  `?`, or a URL-encoded null/newline might be treated as "end of
  meaningful path" by ONE parser but passed through literally by the
  other. `utils.probe_delimiters()` automates testing PortSwigger's
  published candidate list against the origin server.
- **Normalization discrepancies** — one parser might decode `%2e%2e%2f`
  (`../`) and resolve dot-segments before matching cache rules; the other
  might not, or might do so differently (single-pass vs. recursive, before
  vs. after rule-matching) — letting a path like
  `/resources/..%2fmy-account` be read as `/my-account` by the origin but
  matched against the `/resources/` static-directory rule by the cache.
- **Always use a cache buster** (an extra, harmless query param) while
  PROBING, so each test request gets its own fresh cache key and you don't
  accidentally serve yourself a stale/previous result while investigating
  — then drop the buster for the final delivered exploit URL, since the
  victim's real request won't have it either.

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [Exploiting path mapping for web cache deception](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-path-mapping) | Apprentice | ⬜ |
| 2 | [Exploiting path delimiters for web cache deception](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-path-delimiters) | Practitioner | ⬜ |
| 3 | [Exploiting cache server normalization for web cache deception](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-cache-server-normalization) | Practitioner | ⬜ |
| 4 | [Exploiting origin server normalization for web cache deception](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-origin-server-normalization) | Practitioner | ⬜ |
| 5 | [Exploiting exact-match cache rules for web cache deception](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-exact-match-cache-rules) | Expert | ⬜ |

## Per-lab notes

### Lab 1 — Path mapping
📝 The simplest case: the origin's routing maps ANY path starting with
`/my-account/` back to the account page (ignoring the extra segment
entirely), and the cache has a static-extension rule for `.js`. Request
`/my-account/wcd.js` — origin serves the real account page, cache stores
it under that `.js`-suffixed URL because of the extension rule.

### Lab 2 — Path delimiters
📝 The origin treats `;` as a path-segment delimiter (stripping everything
from it onward when resolving `/my-account;anything` → `/my-account`), but
the cache does NOT recognize `;` as a delimiter and happens to still apply
its `.js` extension rule to the full literal string. `/my-account;wcd.js`
threads both needles at once.

### Lab 3 — Cache server normalization
📝 The CACHE decodes `%2f%2e%2e%2f` (`/../`) and resolves it against its
static-directory rule for `/resources/` — even though that dot-segment
sequence, once resolved, actually points back at `/my-account`. A fragment
delimiter (`#`) hides the real path from the origin's own routing while
the cache still walks through and normalizes it for rule-matching.

### Lab 4 — Origin server normalization
📝 The mirror case: here it's specifically confirmed that the CACHE does
NOT decode/resolve dot-segments (so `/resources/..%2fmy-account` still
matches its `/resources/` prefix rule verbatim), while the ORIGIN DOES
resolve it, serving the real `/my-account` page underneath.

### Lab 5 — Exact-match cache rules (Expert)
📝 No static-extension or static-directory rule exists at all — instead
the cache has a rule for the EXACT file name `/robots.txt`. Chain a
delimiter the origin ignores (`;`) with a normalization discrepancy the
cache resolves (`%2f%2e%2e%2f`) so the full crafted path still matches
`/robots.txt` exactly as far as the cache's rule-matcher is concerned,
while the origin serves the real sensitive page underneath. The target
here is CSRF-related (changing the administrator's email) rather than a
simple API-key read, combining this module with CSRF concepts.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
