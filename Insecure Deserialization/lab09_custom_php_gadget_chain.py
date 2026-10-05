"""
Lab 9: Developing a custom gadget chain for PHP deserialization
https://portswigger.net/web-security/deserialization/exploiting/lab-developing-custom-gadget-chain-for-php-deserialization
Difficulty: Expert

📝 Same spirit as Lab 8, PHP side — PHPGGC has no matching chain because
the chain needs to be built from THIS app's own class definitions, which
the lab deliberately exposes somewhere (commonly a source-disclosure bug
in another part of the site, per the lab's own hints).
"""

from utils import get_session, log, note, php_serialize_object

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def run():
    note("Step 1: find the app's own PHP source — this lab typically leaks")
    note("it via a separate, deliberately-present vulnerability elsewhere")
    note("on the site (check the lab's hint text for which one specifically;")
    note("commonly a path traversal or similar disclosure bug).")

    note("Step 2: read through the disclosed classes for __destruct(),")
    note("__wakeup(), __toString(), or __call() methods that do something")
    note("exploitable with attacker-controlled property values — the same")
    note("magic-method hunting as Lab 4, just with a longer chain needed")
    note("(one object's destructor calling a method on another injected")
    note("object, rather than a single-class direct effect).")

    note("Step 3: once you've identified the chain, build it with")
    note("php_serialize_object() for each link — nest them by making one")
    note("object's property value literally BE another serialized object.")

    note("Example skeleton (fill in real class/property names from Step 1):")
    example = php_serialize_object("FirstGadget", {
        "next": php_serialize_object("SecondGadget", {"cmd": "id"})
    })
    print(example)

    log("No automated payload generation for this lab — see steps above.", ok=False)


if __name__ == "__main__":
    run()
