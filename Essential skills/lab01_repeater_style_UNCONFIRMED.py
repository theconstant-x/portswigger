"""
Lab 1 (UNCONFIRMED TITLE): Using Burp Repeater to modify and resend a request
⚠️ See notes.md — this module's actual lab titles/content could not be
confirmed. This script is a best-effort SCAFFOLD, not a verified solution.

📝 Best guess at intent: the real Repeater workflow is "capture a request,
tweak one field by hand, resend, compare the response" — repeated as many
times as needed while reasoning about what changed. This script mirrors
that loop in code: fetch a baseline, apply a single modification, resend,
diff the two responses.

TODO once you've opened the real lab: replace TARGET_PATH, BASELINE_DATA,
and MODIFIED_FIELD below with whatever the actual lab's request/field is,
and rename this file to match the real lab title.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
TARGET_PATH = "/"  # TODO: real vulnerable/interesting endpoint
BASELINE_DATA = {}  # TODO: real baseline form fields, if any
MODIFIED_FIELD = {"example_param": "modified_value"}  # TODO: real field to tweak


def run():
    s = get_session()

    note("Baseline request — equivalent to the first capture in Repeater.")
    r1 = s.get(f"{TARGET}{TARGET_PATH}", params=BASELINE_DATA)
    log(f"Baseline status: {r1.status_code}, length: {len(r1.text)}")

    note("Modified request — equivalent to tweaking one field and hitting")
    note("'Send' again in Repeater.")
    modified_params = {**BASELINE_DATA, **MODIFIED_FIELD}
    r2 = s.get(f"{TARGET}{TARGET_PATH}", params=modified_params)
    log(f"Modified status: {r2.status_code}, length: {len(r2.text)}")

    note(f"Status changed: {r1.status_code != r2.status_code}")
    note(f"Body length changed: {len(r1.text) != len(r2.text)}")
    note("Compare the two response bodies manually for anything the simple")
    note("status/length diff above wouldn't catch (reflected values,")
    note("different error messages, etc.) — this is exactly the kind of")
    note("close reading Repeater is built to make fast and iterative.")


if __name__ == "__main__":
    run()
