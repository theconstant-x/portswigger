# cors_utils.py — shared utilities for CORS lab automation scripts
#
# Mirrors sqli_utils.py, xss_utils.py, csrf_utils.py, access_control_utils.py,
# and api_testing_utils.py in structure.
# Import in each lab script with:
#   from cors_utils import banner, section, make_session, login, ...

import re
import requests


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║           PortSwigger — CORS Lab Automation Suite            ║
║           Cross-Origin Resource Sharing Misconfigurations     ║
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

    📝 Reminder: `requests` is not a browser — it never enforces or even
    looks at CORS response headers. Sending an Origin header with `requests`
    and reading the response is something a real attacker's JS could NOT
    do unless the server's CORS policy actually permits it. We use `requests`
    here purely to PROBE what the server's policy allows; the actual
    exploitation always happens in a real victim browser.
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


def probe_origin(session, url, origin_value, label=None):
    """
    Send a GET request to `url` with a custom Origin header and report
    whether the server reflects it back in Access-Control-Allow-Origin,
    and whether Access-Control-Allow-Credentials is also set.

    Returns a dict: {"reflected": bool, "credentials": bool, "response": Response}
    """
    label = label or origin_value
    r = session.get(url, headers={"Origin": origin_value})

    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")

    reflected = (acao == origin_value)
    credentials = (acac.lower() == "true")

    status = "✔" if reflected else "✘"
    cred_status = "✔" if credentials else "✘"

    print(f"  {status}  Origin: {label:50s} → ACAO: {acao or '(none)'}")
    print(f"      {cred_status}  Access-Control-Allow-Credentials: {acac or '(none)'}")

    return {"reflected": reflected, "credentials": credentials, "response": r}


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


def print_step(msg):
    """Print a single instructional step."""
    print(f"  ➜  {msg}")


def print_box(title, content):
    """
    Print a clearly bordered block — used for showing raw HTTP responses,
    exploit HTML/JS, or leaked data.
    """
    bar = "─" * 60
    print(f"\n  ┌─── {title} {bar[:max(0, 52 - len(title))]}┐")
    for line in str(content).strip().split("\n"):
        print(f"  │  {line}")
    print(f"  └{bar}┘\n")
