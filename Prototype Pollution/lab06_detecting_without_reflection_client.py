"""
Lab 6: Detecting client-side prototype pollution without polluted property reflection
https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-without-polluted-property-reflection
Difficulty: Practitioner

📝 No visible effect from polluting a property directly this time — the
page doesn't reflect the polluted value anywhere obvious. Detection needs
a SIDE-CHANNEL rather than looking for a specific gadget first: polluting
a property that affects a BUILT-IN JS behavior (not app-specific code) is
the standard technique — e.g. polluting `hasOwnProperty` itself, or a
property that changes how JSON.stringify/for-in iteration behaves, which
you can observe generically rather than needing app-specific knowledge.
"""

from utils import get_session, log, note, fetch_page_source

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def run():
    s = get_session()
    source = fetch_page_source(s, f"{TARGET}/")

    note("Universal detection trick: pollute Object.prototype with a NEW")
    note("enumerable property, then check whether a COMPLETELY UNRELATED")
    note("object (one the polluting code never touched) picks it up via a")
    note("for...in loop — this proves pollution reached the prototype even")
    note("with zero app-specific gadget knowledge.")

    print(f"""
  Step 1 — visit: {TARGET}/?__proto__[sentinelProp]=yes

  Step 2 — in the browser console, run:
    for (let key in {{}}) console.log(key);
  If 'sentinelProp' appears in a for...in over a BRAND NEW empty object,
  pollution is confirmed — Object.prototype now carries it globally.
""")

    note("Once confirmed this way, proceed exactly as in Labs 1-5: hunt the")
    note("page's JS for an actual exploitable gadget (a property read with")
    note("no prior explicit assignment) to escalate from 'confirmed")
    note("pollution' to actual XSS — the detection step and the")
    note("exploitation step are deliberately separated in this lab.")


if __name__ == "__main__":
    run()
