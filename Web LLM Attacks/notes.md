# Web LLM Attacks

PortSwigger Web Security Academy module: [Web LLM attacks](https://portswigger.net/web-security/llm-attacks)

## 📝 Core concepts

- **Treat it like SSRF with a brain.** An LLM wired up to internal APIs is
  structurally similar to a server making requests on your behalf — except
  instead of crafting a URL, you craft a SENTENCE that convinces the model
  to make the request for you. "What APIs can you access?" is your recon
  step, same spirit as fuzzing endpoints.
- **Prompt injection, direct vs. indirect:**
  - **Direct** — you type the malicious prompt straight into the chat.
  - **Indirect** — the malicious prompt is hidden in content the LLM reads
    as DATA (a blog comment, a product review, a scanned web page), not
    something you said to it directly. This is the more dangerous class
    because it attacks OTHER users (or autonomous agents) who never saw
    your prompt at all — the LLM encounters it while doing its normal job
    and can't always tell "instruction from the real user" apart from
    "instruction smuggled inside content it's supposed to just read."
- **Excessive agency** = the LLM has more API/tool access than its actual
  job requires, and nothing stops it from being talked into using that
  access destructively. The fix is always permissions/scoping on the API
  side — never trust the model to "know better" on its own.
- **Bypassing an LLM's own guardrails** (a system prompt telling it "don't
  do X") — fake delimiters/markup claiming to be a system message, or fake
  "user response" turns embedded in your injected text, can convince the
  model the conversation state is different than it really is. These are
  genuinely just text tricks — no code involved.
- **Non-determinism is the defining quirk of this whole module.** Every
  official lab description includes a line to the effect of "this uses a
  live LLM and may need rephrasing." Scripts here encode the BEST KNOWN
  shape of a working prompt, but expect to iterate live in the chat UI
  more than with any other module in this repo.
- **The AI-powered-scanner sub-topic (labs 5-8)** flips the attacker's
  role: instead of being the one chatting with the LLM, you're planting
  the injection somewhere an AUTONOMOUS SCANNER (itself LLM-driven, with
  its own elevated credentials/permissions) will read it later while
  auditing the site — a comment on a blog post is the standard delivery
  vector, triggered by clicking "Scan site."

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [Exploiting LLM APIs with excessive agency](https://portswigger.net/web-security/llm-attacks/lab-exploiting-llm-apis-with-excessive-agency) | Apprentice | ⬜ |
| 2 | [Exploiting vulnerabilities in LLM APIs](https://portswigger.net/web-security/llm-attacks/lab-exploiting-vulnerabilities-in-llm-apis) | Practitioner | ⬜ |
| 3 | [Indirect prompt injection](https://portswigger.net/web-security/llm-attacks/lab-indirect-prompt-injection) | Practitioner | ⬜ |
| 4 | [Exploiting insecure output handling in LLMs](https://portswigger.net/web-security/llm-attacks/lab-exploiting-insecure-output-handling-in-llms) | Practitioner | ⬜ |
| 5 | [Exploiting AI agents to perform destructive actions](https://portswigger.net/web-security/llm-attacks/ai-powered-scanner-vulnerabilities/lab-indirect-prompt-injection-via-ai-powered-scan) | Practitioner | ⬜ |
| 6 | [Exploiting AI agents to exfiltrate sensitive information](https://portswigger.net/web-security/llm-attacks/ai-powered-scanner-vulnerabilities/lab-sensitive-information-exfiltration) | Practitioner | ⬜ |
| 7 | [Exploiting AI agents to trigger secondary vulnerabilities](https://portswigger.net/web-security/llm-attacks/ai-powered-scanner-vulnerabilities/lab-exploiting-target-website-vulnerabilities-to-bypass-restrictions) | Practitioner | ⬜ |
| 8 | [Bypassing AI scanner defenses to exfiltrate sensitive information](https://portswigger.net/web-security/llm-attacks/ai-powered-scanner-vulnerabilities/lab-bypassing-ai-scanner-defenses-to-exfiltrate-sensitive-information) | Expert | ⬜ |

## Per-lab notes

### Lab 1 — Excessive agency
📝 Ask the LLM what APIs/functions it supports, then ask it to call one
directly that goes beyond a normal customer-support scope (e.g. deleting
a user account) — the model has the access; nothing stops it using it.

### Lab 2 — Vulnerabilities in LLM APIs
📝 One of the LLM's legitimate functions (e.g. a newsletter subscribe
tool) passes your input through to a vulnerable backend unsanitized —
chain a classic web vuln (here, OS command injection via a crafted email
address) THROUGH the LLM's own API call.

### Lab 3 — Indirect prompt injection
📝 Plant an injected instruction inside a product review (content the
LLM reads when summarizing/answering about that product) rather than
typing it yourself — when a VICTIM asks the assistant about that product,
the hidden instruction executes in their session instead of yours.

### Lab 4 — Insecure output handling
📝 The LLM's raw output gets inserted into the page without sanitization.
Use indirect injection (a review) to make the LLM's response CONTAIN an
XSS payload — when the victim's session renders that response, the script
executes with their privileges.

### Lab 5 — AI agents: destructive actions
📝 Plant an injection in a blog comment that an AI-powered SCANNER (not a
chat user) reads during an automated audit — convince it to take a
destructive action (delete a user) as part of its "analysis."

### Lab 6 — AI agents: exfiltrate sensitive information
📝 Same delivery (a planted comment), but the scanner has access to
another user's sensitive data (an API key) during its audit — convince it
to leak that data back through its own output/report.

### Lab 7 — AI agents: trigger secondary vulnerabilities
📝 The scanner itself can be manipulated into performing a ROUTING-BASED
SSRF (manipulating the Host header on requests IT makes) — chain prompt
injection into a classic infrastructure-level vuln, scanner as the pivot.

### Lab 8 — Bypassing AI scanner defenses (Expert)
📝 The scanner has its OWN built-in defenses against prompt injection this
time. Needs a more carefully-framed injection that survives those
defenses — expect several iterations in the live chat/comment UI, since
by PortSwigger's own account this one doesn't land on the first try even
for experienced testers.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
