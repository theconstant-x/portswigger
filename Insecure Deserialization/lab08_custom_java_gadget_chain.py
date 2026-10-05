"""
Lab 8: Developing a custom gadget chain for Java deserialization
https://portswigger.net/web-security/deserialization/exploiting/lab-developing-custom-gadget-chain-for-java-deserialization
Difficulty: Expert

📝 ysoserial has no pre-built chain for this app's specific dependency
set — this is genuinely manual, capstone-level work: find classes in the
app's own disclosed source/dependencies with exploitable magic methods
(readObject, finalize, etc.) and chain them yourself. No shortcut exists
here by design; this script scaffolds the RESEARCH workflow rather than
pretending to hand you a working chain.
"""

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def run():
    note("Step 1: find the app's disclosed source/dependency list — this")
    note("lab typically exposes it via a downloadable JAR or visible stack")
    note("trace on a deliberately-triggered error. Decompile with a tool")
    note("like CFR or Fernflower if only a .jar is available:")
    note("  java -jar cfr.jar app.jar --outputdir decompiled/")

    note("Step 2: search the decompiled classes for one with a readObject()")
    note("or similar method doing something dangerous with a field value")
    note("(file write, reflection call, process exec) — ysoserial's own")
    note("source (https://github.com/frohoff/ysoserial/tree/master/src/main/java/ysoserial/payloads)")
    note("is the best reference for what a working gadget LOOKS like,")
    note("even when you have to build a new one from different classes.")

    note("Step 3: once you have a candidate chain, serialize it using")
    note("Java's own ObjectOutputStream (a small custom .java harness,")
    note("compiled and run locally) rather than ysoserial's CLI, since")
    note("ysoserial only knows its OWN pre-built chains.")

    note("Step 4: deliver via the same cookie mechanism as Lab 5 once you")
    note("have working serialized bytes — reuse that script's base64 +")
    note("cookie-set logic directly.")

    log("No automated payload generation for this lab — see steps above.", ok=False)


if __name__ == "__main__":
    run()
