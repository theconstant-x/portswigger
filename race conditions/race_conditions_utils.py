# race_conditions_utils.py — shared utilities for Race Conditions lab
# automation scripts
#
# Mirrors all prior utils files in structure and naming conventions.
# Import in each lab script with:
#   from race_conditions_utils import banner, section, make_session, ...
#
# 📝 IMPORTANT CONTEXT: Burp Suite's "Send group in parallel (single-packet
# attack)" exploits HTTP/2 multiplexing to place multiple requests in ONE
# TCP packet, eliminating network jitter entirely. Python's `requests`
# library cannot do this — it has no HTTP/2 multiplexing support and each
# request opens its own connection/stream. The functions below use
# threading with a Barrier to synchronise request DISPATCH as tightly as
# pure Python allows, which is a reasonable approximation for generous
# race windows but will NOT reliably win millisecond-scale races the way
# Burp's single-packet attack can. Where a lab's race window is known to
# be narrow, the scripts say so explicitly and point back to Burp/Turbo
# Intruder as the more reliable tool.

import re
import threading
import requests


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║        PortSwigger — Race Conditions Lab Automation Suite    ║
║        Limit Overrun, Multi-Endpoint & Timing Attacks        ║
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


def send_parallel(request_funcs, timeout=15):
    """
    Fire a list of zero-argument callables ("request functions") from
    separate threads, synchronised with a Barrier so they all begin
    executing their HTTP call at essentially the same instant.

    Each request_func should perform exactly ONE request and return its
    response object (or None on failure).

    Returns a list of results in the SAME order as request_funcs.

    📝 This is the pure-Python approximation of Burp's "Send group in
    parallel (single-packet attack)". A threading.Barrier ensures every
    thread reaches the actual session.get/post call within microseconds
    of each other — but each still opens its own TCP connection, so real
    network jitter (unlike Burp's single-packet HTTP/2 technique) is NOT
    eliminated. Good enough for race windows of tens of milliseconds or
    more; not reliable for sub-millisecond windows.
    """
    n = len(request_funcs)
    barrier = threading.Barrier(n)
    results = [None] * n

    def worker(index, func):
        barrier.wait()
        try:
            results[index] = func()
        except Exception as e:
            results[index] = e

    threads = [
        threading.Thread(target=worker, args=(i, f))
        for i, f in enumerate(request_funcs)
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout)

    return results


def warm_connection(session, url):
    """
    Send a single throwaway GET request to warm up the TCP/TLS connection
    before firing the real parallel race attempt. Reduces first-request
    latency outliers on a fresh connection, mirroring the "connection
    warming" technique described in the module notes.
    """
    try:
        session.get(url, timeout=10)
    except requests.RequestException:
        pass


def check_status(response, expected, label="Request"):
    """
    Compare response.status_code against an expected value (int or list of
    ints) and print a pass/fail line. Handles None/exception results
    gracefully (from send_parallel).
    """
    if response is None or isinstance(response, Exception):
        print(f"  ✘  {label} → no response ({response})")
        return False

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
    Print a clearly bordered block — used for showing race attempt
    results, leaked data, or exploit details.
    """
    bar = "─" * 60
    print(f"\n  ┌─── {title} {bar[:max(0, 52 - len(title))]}┐")
    for line in str(content).strip().split("\n"):
        print(f"  │  {line}")
    print(f"  └{bar}┘\n")
