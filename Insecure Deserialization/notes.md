# Insecure Deserialization

PortSwigger Web Security Academy module: [Insecure deserialization](https://portswigger.net/web-security/deserialization)

## 📝 Core concepts

- **Serialization** converts an in-memory object into a byte stream (to
  store in a cookie, cache, or send over the wire); **deserialization**
  reverses it. The vulnerability: if a website deserializes data it
  received from the USER without validating it first, the user effectively
  controls what object gets reconstructed — including its field values,
  and in the worst case, which CLASS gets instantiated at all.
- **"Object injection"** — the simplest form: just editing field values
  inside an otherwise-legitimate serialized blob (e.g. flipping
  `"admin":false` to `"admin":true` inside a serialized session cookie).
  No gadget chain needed, just understanding the format.
- **Gadget chains** — the advanced form. Many languages' deserialization
  process doesn't just rebuild data — it can trigger method calls as a
  side effect (constructors, `__wakeup`/`__destruct` in PHP,
  `readObject`/`finalize` in Java, custom `marshal_load` in Ruby). A
  "gadget chain" is a sequence of otherwise-harmless classes ALREADY
  present in the app (or its libraries) whose methods, called back-to-back
  during deserialization, add up to something dangerous — classically,
  remote code execution. You're not writing new code to run; you're
  finding a path through code that's already there.
- **Why established tools matter here:** finding/building a gadget chain
  by hand means deep knowledge of a specific library version's internals.
  **ysoserial** (Java) and **PHPGGC** (PHP) are the standard community
  tools that already encode dozens of known chains for common libraries
  (Apache Commons Collections, Spring, Symfony, Laravel, etc.) — using them
  is the normal professional workflow, not a shortcut.
- **PHAR deserialization** (PHP-specific) — PHP will deserialize metadata
  embedded in a `.phar` archive file whenever that file is touched by
  certain filesystem functions (`file_exists`, `is_dir`, etc.) even WITHOUT
  an explicit `unserialize()` call — so an upload feature that merely
  checks "does this file exist" on a user-uploaded file can trigger
  deserialization of attacker-controlled PHAR metadata.

## Labs

| # | Lab | Difficulty | Status |
|---|-----|------------|--------|
| 1 | [Modifying serialized objects](https://portswigger.net/web-security/deserialization/exploiting/lab-modifying-serialized-objects) | Apprentice | ⬜ |
| 2 | [Modifying serialized data types](https://portswigger.net/web-security/deserialization/exploiting/lab-modifying-serialized-data-types) | Apprentice | ⬜ |
| 3 | [Using application functionality to exploit insecure deserialization](https://portswigger.net/web-security/deserialization/exploiting/lab-using-application-functionality-to-exploit-insecure-deserialization) | Practitioner | ⬜ |
| 4 | [Arbitrary object injection in PHP](https://portswigger.net/web-security/deserialization/exploiting/lab-arbitrary-object-injection-in-php) | Practitioner | ⬜ |
| 5 | [Exploiting Java deserialization with Apache Commons](https://portswigger.net/web-security/deserialization/exploiting/lab-exploiting-java-deserialization-with-apache-commons) | Practitioner | ⬜ |
| 6 | [Exploiting PHP deserialization with a pre-built gadget chain](https://portswigger.net/web-security/deserialization/exploiting/lab-exploiting-php-deserialization-with-a-pre-built-gadget-chain) | Practitioner | ⬜ |
| 7 | [Exploiting Ruby deserialization using a documented gadget chain](https://portswigger.net/web-security/deserialization/exploiting/lab-exploiting-ruby-deserialization) | Practitioner | ⬜ |
| 8 | [Developing a custom gadget chain for Java deserialization](https://portswigger.net/web-security/deserialization/exploiting/lab-developing-custom-gadget-chain-for-java-deserialization) | Expert | ⬜ |
| 9 | [Developing a custom gadget chain for PHP deserialization](https://portswigger.net/web-security/deserialization/exploiting/lab-developing-custom-gadget-chain-for-php-deserialization) | Expert | ⬜ |
| 10 | [Using PHAR deserialization to deploy a custom gadget chain](https://portswigger.net/web-security/deserialization/exploiting/lab-using-phar-deserialization-to-deploy-a-custom-gadget-chain) | Expert | ⬜ |

## Per-lab notes

### Lab 1 — Modifying serialized objects
📝 The session cookie is a base64-encoded PHP serialized object with an
`isAdmin`/`accessToken`-style field. Decode it, flip the field, re-encode.

### Lab 2 — Modifying serialized data types
📝 PHP's loose typing bites here: a field expected to be a string can
instead be serialized as something else (e.g. a boolean) that a comparison
elsewhere in the app treats as always-true — a type-confusion variant of
Lab 1's field-editing approach.

### Lab 3 — Using application functionality
📝 No direct serialized-cookie editing — instead, find a legitimate app
FEATURE (e.g. "update email", "delete account") whose side effects, when
chained via the existing object structure, achieve the lab's goal (often
deleting another user) without needing a gadget chain at all.

### Lab 4 — Arbitrary object injection in PHP
📝 The app deserializes a field expecting one specific class, but doesn't
validate WHICH class actually gets instantiated. Swap in a DIFFERENT class
already defined in the app's own code whose magic methods
(`__wakeup`/`__destruct`) have a side effect you can abuse (e.g. deleting a
file via a logging class).

### Lab 5 — Apache Commons (Java)
📝 Textbook ysoserial usage: generate a `CommonsCollections` chain, base64
it into the session cookie, deliver.

### Lab 6 — Pre-built PHP gadget chain
📝 Same shape as Lab 5, PHPGGC instead of ysoserial — the app uses a
known framework/library PHPGGC already has a chain for.

### Lab 7 — Ruby, documented gadget chain
📝 No single universal tool like ysoserial/PHPGGC for Ruby — instead,
identify the Ruby framework/version in use and search for its specific
PUBLICLY DOCUMENTED gadget chain writeup (Rails' `Marshal`-based chains
are the classic example), then reproduce it.

### Lab 8 — Custom Java gadget chain
📝 ysoserial doesn't have a pre-built chain for THIS app's specific
dependency set. Use its gadget-authoring framework as a starting point, but
the actual chain has to be built against classes unique to this lab —
genuinely manual, capstone-level work.

### Lab 9 — Custom PHP gadget chain
📝 Same idea as Lab 8, PHP side — PHPGGC has no matching chain, so the
chain gets built from the app's OWN class definitions (visible via a
source-disclosure bug elsewhere in the lab, as hinted).

### Lab 10 — PHAR deserialization
📝 Upload a crafted `.phar` file (disguised with a harmless extension/
content-type, e.g. renamed to `.jpg`), trigger ANY filesystem-check
function on it server-side (an avatar "preview" feature checking the file
exists is typical) to invoke deserialization of its embedded metadata
WITHOUT the app ever calling `unserialize()` directly — then pair it with
a known gadget chain (PHPGGC) for the actual payload.

## Status key
⬜ not started · 🟨 in progress · ✅ solved
