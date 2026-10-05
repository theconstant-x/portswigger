"""
Lab 2 (UNCONFIRMED TITLE): Using Burp Decoder / Intruder on an encoded or
brute-forceable value
⚠️ See notes.md — this module's actual lab titles/content could not be
confirmed. This script is a best-effort SCAFFOLD, not a verified solution.

📝 Best guess at intent: either (a) a captured value turns out to be
encoded and needs identifying/decoding before it's useful (Decoder's job),
or (b) a parameter needs sweeping through many candidate values to find
the one that works (Intruder's job). This script scaffolds both, since
either is a reasonable guess for what a "core tools" lab would test.

TODO once you've opened the real lab: replace CAPTURED_VALUE and the
sweep target/payloads below with the real ones, and rename this file.
"""

from utils import get_session, try_all_decodings, sweep_payloads, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"

# --- Decoder-style scenario ---
CAPTURED_VALUE = "d2llbmVyOnBldGVy"  # TODO: real captured cookie/param value


def run_decoder_scenario():
    note("Decoder-style step: try every common encoding against a captured")
    note("value and see which one produces readable output.")
    try_all_decodings(CAPTURED_VALUE)


# --- Intruder-style scenario ---
SWEEP_URL = f"{TARGET}/some-endpoint"  # TODO: real endpoint
SWEEP_PARAM = "id"                      # TODO: real parameter name
SWEEP_PAYLOADS = [str(i) for i in range(1, 21)]  # TODO: real candidate list
SUCCESS_MARKER = 200                    # TODO: real success signal (status or text)


def run_intruder_scenario():
    s = get_session()
    note(f"Intruder-style sweep: trying {len(SWEEP_PAYLOADS)} candidate")
    note(f"values against '{SWEEP_PARAM}'.")
    hit_payload, hit_response = sweep_payloads(
        s, SWEEP_URL, SWEEP_PARAM, SWEEP_PAYLOADS, success_marker=SUCCESS_MARKER
    )
    if hit_payload:
        log(f"Match found: {hit_payload!r}")
    else:
        log("No match in the placeholder range — adjust SWEEP_PAYLOADS.", ok=False)


def run():
    run_decoder_scenario()
    print()
    run_intruder_scenario()


if __name__ == "__main__":
    run()
