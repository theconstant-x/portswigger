# business_logic_utils.py — shared utilities for Business Logic Vulnerabilities
# lab automation scripts
#
# Mirrors all prior utils files in structure and naming conventions.
# Import in each lab script with:
#   from business_logic_utils import banner, section, make_session, ...

import re
import base64
import requests


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║   PortSwigger — Business Logic Vulnerabilities Lab Suite     ║
║   Client Trust, Workflow, Overflow & Encryption Oracle       ║
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


def get_csrf_from_response(html):
    """
    Extract a CSRF token from an HTML page's hidden form input.
    Returns the token string or None if not found.
    """
    m = (re.search(r'<input[^>]+name=["\']csrf["\'][^>]+value=["\']([^"\']+)["\']', html) or
         re.search(r'name=["\']csrf["\'][^>]+value=["\']([^"\']+)["\']', html))
    return m.group(1) if m else None


def login(session, base_url, username="wiener", password="peter"):
    """
    Log in to the PortSwigger lab with the provided credentials.
    Returns True on success, False on failure.
    """
    login_page = session.get(f"{base_url}/login")
    csrf = get_csrf_from_response(login_page.text)

    data = {"username": username, "password": password}
    if csrf:
        data["csrf"] = csrf

    r = session.post(f"{base_url}/login", data=data, allow_redirects=True)

    if "Log out" in r.text or "My account" in r.text:
        print(f"  ✔  Logged in as {username}")
        return True

    print(f"  ✘  Login failed for {username} (status {r.status_code})")
    return False


def find_product_id(session, base_url, name_fragment="l33t"):
    """
    Scan the home page for a product link whose text or URL contains the
    given fragment (default: the 'l33t' leather jacket used across most
    Business Logic labs). Returns the productId as a string, falling back
    to '1' if not found.
    """
    r = session.get(base_url)
    idx = r.text.lower().find(name_fragment.lower())
    if idx != -1:
        window = r.text[max(0, idx - 300):idx + 50]
        pid_match = re.search(r'productId=(\d+)', window)
        if pid_match:
            print(f"  ✔  Found product ID via page scan: {pid_match.group(1)}")
            return pid_match.group(1)

    print("  ?  Could not auto-detect product ID — falling back to '1'")
    return "1"


def add_to_cart(session, base_url, product_id, quantity=1, extra_data=None):
    """
    Add a product to the cart. extra_data lets callers inject additional
    (potentially malicious) form fields, e.g. a manipulated price.
    """
    data = {"productId": product_id, "redir": "PRODUCT", "quantity": str(quantity)}
    if extra_data:
        data.update(extra_data)
    return session.post(f"{base_url}/cart", data=data)


def get_cart_total(session, base_url):
    """Fetch the cart page and try to extract the displayed total."""
    r = session.get(f"{base_url}/cart")
    m = re.search(r'Total:\s*\$?(-?[\d,]+\.\d{2})', r.text)
    return m.group(1) if m else None


def check_status(response, expected, label="Request"):
    """
    Compare response.status_code against an expected value (int or list of
    ints) and print a pass/fail line.
    """
    expected_list = expected if isinstance(expected, (list, tuple)) else [expected]
    if response.status_code in expected_list:
        print(f"  ✔  {label} → status {response.status_code} (as expected)")
        return True
    print(f"  ✘  {label} → status {response.status_code} (expected {expected_list})")
    return False


def strip_bytes_from_ciphertext(url_encoded_cookie_value, num_bytes):
    """
    Given a URL-encoded, base64-encoded ciphertext (as found in a cookie
    value), strip the first `num_bytes` raw bytes and return a new
    URL-encoded, base64-encoded string.

    This mirrors the Burp Decoder workflow used in the encryption oracle
    lab: URL-decode -> base64-decode -> slice off N bytes -> base64-encode
    -> URL-encode.
    """
    import urllib.parse

    url_decoded = urllib.parse.unquote(url_encoded_cookie_value)
    raw_bytes = base64.b64decode(url_decoded)
    stripped = raw_bytes[num_bytes:]
    re_encoded = base64.b64encode(stripped).decode()
    return urllib.parse.quote(re_encoded, safe="")


def utf7_encode_segment(text):
    """
    Minimal UTF-7 'modified base64' encoder for a segment of text, used to
    build the &...- style escape sequences seen in UTF-7 email encoding.
    This encodes the given text using UTF-7's modified base64 alphabet
    (same as standard base64 but with '/' replaced by ',' and no padding).
    """
    utf16_bytes = text.encode("utf-16-be")
    b64 = base64.b64encode(utf16_bytes).decode()
    b64 = b64.rstrip("=").replace("/", ",")
    return f"&{b64}-"


def print_step(msg):
    """Print a single instructional step."""
    print(f"  ➜  {msg}")


def print_box(title, content):
    """
    Print a clearly bordered block — used for showing leaked data, cart
    totals, forged cookies, or exploit payloads.
    """
    bar = "─" * 60
    print(f"\n  ┌─── {title} {bar[:max(0, 52 - len(title))]}┐")
    for line in str(content).strip().split("\n"):
        print(f"  │  {line}")
    print(f"  └{bar}┘\n")
