# Server-Side Template Injection (SSTI)

PortSwigger Web Security Academy module: [Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)

## 📝 Core concepts

- **The flaw:** user input gets concatenated directly into a template
  STRING before that template is rendered — rather than being passed in as
  DATA to be substituted into an existing template. The engine then parses
  our input as template syntax, not as a value.
- **General workflow, every lab:**
  1. **Detect** — a math-expression probe like `{{7*7}}` that evaluates to
     `49` in the response confirms injection (vs. an XSS-only reflection,
     where it'd come back as literal text).
  2. **Identify the engine** — different engines use different delimiter
     syntax (`{{ }}` Jinja2/Twig, `${ }` FreeMarker, `#{ }` some EL-based
     engines, `*{ }` Thymeleaf, `@( )` Razor). The polyglot probe or trying
     each syntax in turn narrows it down; error messages often just name
     the engine outright.
  3. **Find/craft an RCE payload** for that specific engine — usually by
     walking from the template context out to the underlying language's
     built-ins (Python's `__globals__`/`__builtins__` chain for Jinja2,
     Java reflection for FreeMarker/Velocity, etc.).
- **"Code context" vs "plain text context"** — sometimes the injection
  point is inside an attribute/expression the template was ALREADY going to
  evaluate (e.g. a Freemarker `${...}` block you're injecting INSIDE of),
  so you only need to close out of the current function call rather than
  open a brand new template expression from scratch.
- **Documentation is a legitimate recon tool** — once you know the engine
  name, its official docs often directly describe privileged/utility
  classes (like FreeMarker's `freemarker.template.utility.Execute`) that
  exist specifically for template authors and are exactly what you repurpose
  for RCE.
- **Sandboxed environments** restrict which classes/methods a template can
  reach — but sandbox escapes are a whole sub-genre of known CVEs/bypasses
  per engine; "sandboxed" doesn't mean "safe," just "needs a documented
  escape technique" layered on top of the basic SSTI.
- **User-supplied OBJECTS (not just strings)** can also drive SSTI — if the
  app lets you influence which object/class gets passed into the template
  context (not just a string value), simply introspecting what that object
  exposes (via Python's `__class__`/`__mro__` or similar) can leak internal
  application state even without achieving full RCE.

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [Basic server-side template injection](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic) | Practitioner | ⬜ |
| 2 | [Basic SSTI (code context)](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-code-context) | Practitioner | ⬜ |
| 3 | [SSTI using documentation](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation) | Practitioner | ⬜ |
| 4 | [SSTI in an unknown language with a documented exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-unknown-language-with-documented-exploit) | Practitioner | ⬜ |
| 5 | [SSTI with information disclosure via user-supplied objects](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-information-disclosure-via-user-supplied-objects) | Practitioner | ⬜ |
| 6 | [SSTI in a sandboxed environment](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-sandbox-environment) | Expert | ⬜ |
| 7 | [SSTI with a custom exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-custom-exploit) | Expert | ⬜ |

## Per-lab notes

### Lab 1 — Basic SSTI
📝 Plain-text context, Jinja2 under the hood. `{{7*7}}` confirms it, then
walk the `__globals__`/`__builtins__` chain to `os.popen`.

### Lab 2 — Basic SSTI (code context)
📝 Injection point is already INSIDE a template expression (e.g. a search
box that gets wrapped as `{{search(request.input)}}`) — payload needs to
close out of/escape the existing call rather than open `{{ }}` fresh.

### Lab 3 — Using documentation
📝 Freemarker. Identify via error message or probe syntax, then the
exploit literally comes straight from Freemarker's own docs for the
`Execute` utility class.

### Lab 4 — Unknown language with a documented exploit
📝 Deliberately doesn't tell you the engine. Fingerprint via error text/
probe syntax (this one's commonly Handlebars), then search for a known
public RCE writeup for that specific engine — the lab is testing the
research step, not just payload execution.

### Lab 5 — Info disclosure via user-supplied objects
📝 Django templates. The vulnerable point passes an OBJECT (not a raw
string) into the template context — introspect it via Django template
syntax (`{{ obj.__class__ ... }}`-style attribute traversal) to leak
internal config/secret values without needing full RCE.

### Lab 6 — Sandboxed environment
📝 FreeMarker with a sandbox blocking the obvious `Execute` utility.
Needs a documented SANDBOX ESCAPE technique specific to FreeMarker's
sandbox implementation — search for known bypasses rather than the basic
exploit from Lab 3.

### Lab 7 — Custom exploit
📝 No publicly documented exploit exists for this specific
engine/configuration — have to build the RCE chain yourself from
first principles (identify engine → explore what classes/objects are
reachable from the template context → manually find a path to code
execution), the capstone of the module.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
